#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]
//! SMTP metrics on real flows against the scripted server: attempts, auth failures and
//! uncertain deliveries are counted per account id, and no address or key becomes a label.
#[path = "support/fake_server.rs"]
mod fake_server;

use std::path::Path;
use std::sync::Arc;

use fake_server::{AfterData, Script, Server, TlsKind, start};
use openmail_core::backend::SecretSource;
use openmail_core::config::{AccountConfig, Config, CredentialRef};
use openmail_core::model::Address;
use openmail_core::{ErrorCode, Result};
use openmail_observe::metrics::{Counter, Labels, Metrics};
use openmail_observe::observer::Observer;
use openmail_smtp::{
    ApprovalConsumer, ApprovalProof, SendRequest, SendRequestDescriptor, SmtpClient, SmtpOptions,
    SqliteOutbox,
};
use secrecy::SecretString;

struct FixedSecret(&'static str);
impl SecretSource for FixedSecret {
    fn resolve(&self, _: &CredentialRef) -> Result<SecretString> {
        Ok(SecretString::from(self.0))
    }
}

fn account(port: u16, tls: &str, timeout_secs: u64) -> AccountConfig {
    let toml = format!(
        r#"version = 1
[[account]]
id = "work"
display_name = "Work"
email = "me@example.com"
auth = "password"
read_only = false
timeout_secs = {timeout_secs}
credential = {{ kind = "env", var = "X" }}
imap = {{ host = "localhost", port = 993, tls = "implicit" }}
smtp = {{ host = "localhost", port = {port}, tls = "{tls}" }}
permissions = {{ send = true }}
"#
    );
    Config::from_toml(&toml).unwrap().accounts.remove(0)
}

fn request(key: &str) -> SendRequest {
    SendRequest {
        idempotency_key: key.into(),
        from: Address {
            name: Some("Me".into()),
            email: "me@example.com".into(),
        },
        to: vec![Address {
            name: None,
            email: "you@example.org".into(),
        }],
        cc: vec![],
        bcc: vec![Address {
            name: None,
            email: "hidden@example.net".into(),
        }],
        subject: "Hello".into(),
        text: Some("body text".into()),
        html: None,
        attachments: vec![],
        in_reply_to: None,
        references: vec![],
    }
}

/// Stand-in for the security layer: approves whatever descriptor it is asked about.
struct AllowAll;

impl ApprovalConsumer for AllowAll {
    fn consume(
        &self,
        _principal: &str,
        _descriptor: &SendRequestDescriptor,
        _token: Option<&str>,
    ) -> openmail_core::Result<()> {
        Ok(())
    }
}

fn proof_for(acct: &AccountConfig, r: &SendRequest) -> ApprovalProof {
    ApprovalProof::obtain(&AllowAll, "test", &acct.id, r, Some("approval-1")).unwrap()
}

type Client = SmtpClient<SqliteOutbox, FixedSecret>;

fn client(db: &Path, server: &Server, password: &'static str, m: &Arc<Metrics>) -> Client {
    let options = SmtpOptions {
        extra_root_certs_pem: vec![server.root_pem.clone()],
        ..SmtpOptions::default()
    };
    SmtpClient::new(
        SqliteOutbox::open(db).unwrap(),
        FixedSecret(password),
        options,
    )
    .with_observer(Observer::recording(Arc::clone(m)))
}

fn work() -> Labels {
    Labels::none().account("work")
}

#[tokio::test]
async fn successful_send_counts_one_attempt_and_nothing_else() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(Metrics::new());
    let c = client(&dir.path().join("o.sqlite"), &srv, "s3cret", &m);
    let acct = account(srv.port, "implicit", 10);
    let r = request("k-ok");
    c.send(&acct, r.clone(), proof_for(&acct, &r))
        .await
        .unwrap();
    assert_eq!(m.counter_with(Counter::SmtpAttempts, &work()), 1);
    assert_eq!(m.counter(Counter::SmtpUncertain), 0);
    assert_eq!(m.counter(Counter::AuthFailures), 0);
    // An idempotent replay of an accepted send is not another attempt.
    c.send(&acct, r.clone(), proof_for(&acct, &r))
        .await
        .unwrap();
    assert_eq!(m.counter_with(Counter::SmtpAttempts, &work()), 1);
    let text = m.render_prometheus();
    assert!(
        !text.contains("example.org") && !text.contains("k-ok"),
        "{text}"
    );
}

#[tokio::test]
async fn auth_failure_moves_auth_failures() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(Metrics::new());
    let c = client(&dir.path().join("o.sqlite"), &srv, "wrong-password", &m);
    let acct = account(srv.port, "implicit", 10);
    let r = request("k-auth");
    let err = c
        .send(&acct, r.clone(), proof_for(&acct, &r))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthFailed);
    assert_eq!(m.counter_with(Counter::AuthFailures, &work()), 1);
    assert_eq!(m.counter_with(Counter::SmtpAttempts, &work()), 1);
    assert_eq!(m.counter(Counter::SmtpUncertain), 0);
}

#[tokio::test]
async fn timeout_after_data_moves_smtp_uncertain() {
    let mut script = Script::new(TlsKind::Implicit);
    script.after_data = AfterData::Hang;
    let srv = start(script).await;
    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(Metrics::new());
    let c = client(&dir.path().join("o.sqlite"), &srv, "s3cret", &m);
    // 1 s was too tight for the TLS handshake on slow Windows runners, which then timed out BEFORE data.
    let acct = account(srv.port, "implicit", 5);
    let r = request("k-hang");
    let err = c
        .send(&acct, r.clone(), proof_for(&acct, &r))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeliveryUncertain);
    assert_eq!(m.counter_with(Counter::SmtpUncertain, &work()), 1);
    // The refused replay is not a new attempt and not a new uncertainty.
    let _ = c.send(&acct, r.clone(), proof_for(&acct, &r)).await;
    assert_eq!(m.counter_with(Counter::SmtpAttempts, &work()), 1);
    assert_eq!(m.counter_with(Counter::SmtpUncertain, &work()), 1);
}
