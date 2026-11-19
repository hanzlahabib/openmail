//! Digest email end to end: real SMTP submission to GreenMail (TLS via an in-process proxy),
//! delivery verified over IMAP. A digest only ever reaches the account owner, is sent once per
//! brief across "processes", and is rate limited.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/greenmail.rs"]
mod harness;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use harness::*;
use openmail_briefs::delivery::{
    BriefItem, BriefSection, DeliverableBrief, DeliveryOutcome, EmailDigestAdapter, Provenance,
};
use openmail_briefs::digest::{DIGEST_SUBJECT_PREFIX, MAX_DIGESTS_PER_DAY, SmtpDigestSender};
use openmail_briefs::store::BriefStore;
use openmail_core::ErrorCode;
use openmail_core::backend::MailBackend;
use openmail_core::config::{AccountConfig, Limits, ServerEndpoint, TlsMode};
use openmail_core::ids::AccountId;
use openmail_core::model::PageRequest;
use openmail_imap::ImapBackend;
use openmail_smtp::{SmtpClient, SmtpOptions, SqliteOutbox};

const PW: &str = "secret";

fn pem(der: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

fn brief(id: &str) -> DeliverableBrief {
    DeliverableBrief {
        id: id.into(),
        title: format!("Morning brief {id}"),
        sections: vec![BriefSection {
            title: "Needs your attention".into(),
            items: vec![BriefItem {
                text: "looks like payment_related - \"Invoice 1\"".into(),
                provenance: Provenance::Inferred,
                source_ref: Some("ref1".into()),
            }],
        }],
    }
}

struct Env {
    _gm: Greenmail,
    _imap: TlsProxy,
    _smtp: TlsProxy,
    _dir: tempfile::TempDir,
    store: Arc<Mutex<BriefStore>>,
    imap: ImapBackend,
    account: AccountConfig,
    cert_pem: Vec<u8>,
    outbox: std::path::PathBuf,
}

async fn env() -> Option<Env> {
    let gm = Greenmail::start(&[("alice", PW), ("bob", PW)])?;
    let imap_proxy = TlsProxy::spawn(gm.port, Mode::Implicit, false).await;
    let smtp_proxy = TlsProxy::spawn(gm.smtp_port, Mode::Implicit, false).await;
    let mut account = account("alice", "alice", "PW", imap_proxy.port, TlsMode::Implicit);
    account.read_only = false;
    account.permissions.send = true;
    account.smtp = Some(ServerEndpoint {
        host: "localhost".into(),
        port: smtp_proxy.port,
        tls: TlsMode::Implicit,
    });
    let imap = ImapBackend::with_extra_roots(
        vec![
            account.clone(),
            harness::account("bob", "bob", "PW", imap_proxy.port, TlsMode::Implicit),
        ],
        Limits::default(),
        secrets(&[("PW", PW)]),
        std::slice::from_ref(&imap_proxy.cert),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Mutex::new(
        BriefStore::open(&dir.path().join("briefs.db")).unwrap(),
    ));
    Some(Env {
        cert_pem: pem(smtp_proxy.cert.as_ref()),
        outbox: dir.path().join("outbox.db"),
        _gm: gm,
        _imap: imap_proxy,
        _smtp: smtp_proxy,
        _dir: dir,
        store,
        imap,
        account,
    })
}

impl Env {
    /// A fresh sender, as a new process would build it (own adapter audit, shared SQLite).
    fn adapter(&self) -> EmailDigestAdapter<SmtpDigestSender<Secrets>> {
        let client = SmtpClient::new(
            SqliteOutbox::open(&self.outbox).unwrap(),
            Secrets(std::collections::HashMap::from([(
                "PW".to_owned(),
                PW.to_owned(),
            )])),
            SmtpOptions {
                extra_root_certs_pem: vec![self.cert_pem.clone()],
                ..SmtpOptions::default()
            },
        );
        let sender =
            SmtpDigestSender::new(client, self.account.clone(), Arc::clone(&self.store)).unwrap();
        EmailDigestAdapter::new(sender)
    }

    async fn inbox_subjects(&self, who: &str) -> Vec<String> {
        let page = self
            .imap
            .list_messages(
                &AccountId::new(who).unwrap(),
                "INBOX",
                PageRequest {
                    cursor: None,
                    limit: 50,
                },
            )
            .await
            .unwrap();
        page.items.into_iter().map(|m| m.subject.0).collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn digest_reaches_only_the_owner_once_per_brief() {
    let Some(env) = env().await else { return };
    let outcome = env
        .adapter()
        .deliver(&brief("b1"), "alice@localhost")
        .await
        .unwrap();
    assert_eq!(outcome, DeliveryOutcome::Sent);

    let alice = env.inbox_subjects("alice").await;
    assert_eq!(alice.len(), 1, "{alice:?}");
    assert!(alice[0].starts_with(DIGEST_SUBJECT_PREFIX), "{}", alice[0]);
    assert!(env.inbox_subjects("bob").await.is_empty());

    // Same brief again from a "second process" (fresh adapter, shared database): no new mail.
    let again = env
        .adapter()
        .deliver(&brief("b1"), "alice@localhost")
        .await
        .unwrap();
    assert_eq!(
        again,
        DeliveryOutcome::Sent,
        "adapter has no memory; the store decides"
    );
    assert_eq!(
        env.inbox_subjects("alice").await.len(),
        1,
        "duplicate digest sent"
    );
    // And the audit has exactly one row for it.
    let hist = env
        .store
        .lock()
        .unwrap()
        .digest_history(&AccountId::new("alice").unwrap(), 10)
        .unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].0, "alice@localhost");
    assert_eq!(hist[0].1, "sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_digest_cannot_be_aimed_at_anyone_else() {
    let Some(env) = env().await else { return };
    for target in [
        "bob@localhost",
        "alice@localhost\r\nBcc: bob@localhost",
        "bob@localhost,alice@localhost",
    ] {
        let e = env
            .adapter()
            .deliver(&brief("b2"), target)
            .await
            .unwrap_err();
        assert!(
            matches!(e.code(), ErrorCode::AccessDenied | ErrorCode::InvalidInput),
            "{target}: {e}"
        );
    }
    assert!(env.inbox_subjects("bob").await.is_empty());
    assert!(env.inbox_subjects("alice").await.is_empty());
    assert!(
        env.store
            .lock()
            .unwrap()
            .digest_history(&AccountId::new("alice").unwrap(), 10)
            .unwrap()
            .is_empty(),
        "refused attempts must not even be claimed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn digests_are_rate_limited_per_account() {
    let Some(env) = env().await else { return };
    for i in 0..MAX_DIGESTS_PER_DAY {
        env.adapter()
            .deliver(&brief(&format!("r{i}")), "alice@localhost")
            .await
            .unwrap();
    }
    let e = env
        .adapter()
        .deliver(&brief("one-too-many"), "alice@localhost")
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::RateLimited);
    assert_eq!(
        env.inbox_subjects("alice").await.len(),
        usize::try_from(MAX_DIGESTS_PER_DAY).unwrap()
    );
}
