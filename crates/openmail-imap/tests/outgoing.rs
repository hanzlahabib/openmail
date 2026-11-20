//! Drafts, attachment download and Sent copy against a real IMAP server (GreenMail).
//! Skips loudly without docker; fails instead with OPENMAIL_REQUIRE_DOCKER=1.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

#[path = "greenmail/harness.rs"]
mod harness;

use base64::Engine;
use harness::*;
use openmail_core::ErrorCode;
use openmail_core::backend::{AttachmentSource, MailBackend, MailDrafts, SentFolder};
use openmail_core::config::{AccountConfig, Limits, TlsMode};
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{Address, DraftInput, PageRequest};
use openmail_imap::ImapBackend;

const PW: &str = "secret";

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn page() -> PageRequest {
    PageRequest {
        cursor: None,
        limit: 50,
    }
}

fn addr(email: &str) -> Address {
    Address {
        name: None,
        email: email.into(),
    }
}

struct Env {
    gm: Greenmail,
    proxy: TlsProxy,
}

async fn env() -> Option<Env> {
    let gm = Greenmail::start(&[("alice", PW)])?;
    let proxy = TlsProxy::spawn(gm.port, Mode::Implicit, false).await;
    Some(Env { gm, proxy })
}

fn cfg(env: &Env, tweak: impl FnOnce(&mut AccountConfig)) -> ImapBackend {
    let mut c = account("alice", "alice", "PW", env.proxy.port, TlsMode::Implicit);
    c.read_only = false;
    tweak(&mut c);
    ImapBackend::with_extra_roots(
        vec![c],
        Limits::default(),
        secrets(&[("PW", PW)]),
        std::slice::from_ref(&env.proxy.cert),
    )
    .unwrap()
}

fn drafts_cfg(c: &mut AccountConfig) {
    c.permissions.drafts = true;
    c.folders.drafts = Some("Drafts".into());
}

async fn count(env: &Env, folder: &str) -> u32 {
    env.gm
        .admin("alice", PW)
        .await
        .select(folder)
        .await
        .unwrap()
        .exists
}

fn input(subject: &str) -> DraftInput {
    DraftInput {
        to: vec![addr("bob@example.org")],
        subject: subject.into(),
        text: Some("draft body".into()),
        ..DraftInput::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn draft_create_update_delete_touch_only_the_draft() {
    let Some(env) = env().await else { return };
    let mut admin = env.gm.admin("alice", PW).await;
    admin.create("Drafts").await.unwrap();
    // Bystanders in Drafts: one flagged \Deleted by someone else, one non-draft mail.
    admin
        .append(
            "Drafts",
            Some("(\\Deleted)"),
            None,
            eml("Bystander", "x@example.com", "by1@example.com", "", "b"),
        )
        .await
        .unwrap();
    admin
        .append(
            "Drafts",
            None,
            None,
            eml("Plain mail", "x@example.com", "by2@example.com", "", "b"),
        )
        .await
        .unwrap();
    admin
        .append(
            "INBOX",
            None,
            None,
            eml(
                "Question",
                "bob@example.org",
                "q1@example.org",
                "References: <root@example.org>\r\n",
                "hi",
            ),
        )
        .await
        .unwrap();

    let b = cfg(&env, drafts_cfg);
    let a = id("alice");
    let inbox = b.list_messages(&a, "INBOX", page()).await.unwrap();
    let parent = inbox.items[0].reference.clone();

    // Create as a reply: threading headers come from the replied-to message.
    let mut d = input("Re: Question");
    d.in_reply_to = Some(parent);
    d.bcc = vec![addr("hidden@example.org")];
    let r1 = b.create_draft(&a, d).await.unwrap();
    assert_eq!(r1.folder, "Drafts");
    assert_eq!(count(&env, "Drafts").await, 3);
    let m = b.get_message(&r1, 10_000).await.unwrap();
    assert!(m.summary.flags.draft, "stored with \\Draft");
    assert_eq!(m.summary.subject.0, "Re: Question");
    assert_eq!(m.in_reply_to.as_deref(), Some("q1@example.org"));
    assert_eq!(m.references, vec!["root@example.org", "q1@example.org"]);
    assert_eq!(m.body.text.unwrap().0.trim(), "draft body");

    // Update replaces the draft; the old UID disappears, bystanders (incl. \Deleted) stay.
    let r2 = b.update_draft(&r1, input("Re: Question v2")).await.unwrap();
    assert_ne!(r2.uid, r1.uid);
    assert_eq!(
        b.get_message(&r1, 1000).await.unwrap_err().code(),
        ErrorCode::MessageNotFound
    );
    assert_eq!(
        b.get_message(&r2, 1000).await.unwrap().summary.subject.0,
        "Re: Question v2"
    );
    assert_eq!(
        count(&env, "Drafts").await,
        3,
        "bystander flagged \\Deleted must survive (UID EXPUNGE only)"
    );

    // Non-drafts and other folders are refused, not deleted.
    let plain = MessageRef {
        uid: 2,
        ..r2.clone()
    };
    assert_eq!(
        b.delete_draft(&plain).await.unwrap_err().code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(
        b.update_draft(&plain, input("x")).await.unwrap_err().code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(
        b.delete_draft(&inbox.items[0].reference)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(count(&env, "INBOX").await, 1);

    b.delete_draft(&r2).await.unwrap();
    assert_eq!(count(&env, "Drafts").await, 2);
    assert_eq!(
        b.delete_draft(&r2).await.unwrap_err().code(),
        ErrorCode::MessageNotFound
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn draft_permissions_and_missing_folder() {
    let Some(env) = env().await else { return };
    let a = id("alice");
    let ro = cfg(&env, |c| c.folders.drafts = Some("Drafts".into()));
    assert_eq!(
        ro.create_draft(&a, input("x")).await.unwrap_err().code(),
        ErrorCode::ReadOnlyAccount
    );
    // Permitted but no configured folder and the server advertises no \Drafts role.
    let b = cfg(&env, |c| c.permissions.drafts = true);
    assert_eq!(
        b.create_draft(&a, input("x")).await.unwrap_err().code(),
        ErrorCode::FolderNotFound
    );
    // Configured folder that does not exist.
    let b = cfg(&env, drafts_cfg);
    assert!(b.create_draft(&a, input("x")).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn crlf_in_subject_or_recipients_cannot_inject_headers() {
    let Some(env) = env().await else { return };
    env.gm
        .admin("alice", PW)
        .await
        .create("Drafts")
        .await
        .unwrap();
    let b = cfg(&env, drafts_cfg);
    let a = id("alice");
    let mut bad_subject = input("hello\r\nBcc: evil@example.net");
    bad_subject.subject = "hello\r\nBcc: evil@example.net".into();
    let mut bad_to = input("ok");
    bad_to.to = vec![addr("bob@example.org\r\nBcc: evil@example.net")];
    let mut bad_name = input("ok");
    bad_name.to = vec![Address {
        name: Some("Bob\r\nBcc: evil@example.net".into()),
        email: "bob@example.org".into(),
    }];
    let mut bad_cc = input("ok");
    bad_cc.cc = vec![addr("c@example.org\nX-Injected: 1")];
    for d in [bad_subject, bad_to, bad_name, bad_cc] {
        assert_eq!(
            b.create_draft(&a, d).await.unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }
    assert_eq!(count(&env, "Drafts").await, 0, "nothing may be stored");
}

fn b64_wrapped(bytes: &[u8]) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(bytes);
    enc.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn attachment_bytes_equal_seeded_bytes_and_cap_is_enforced() {
    let Some(env) = env().await else { return };
    let binary: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    let png: Vec<u8> = (0..=255u8).rev().cycle().take(700).collect();
    let mail = format!(
        "From: bob@example.org\r\nTo: alice@localhost\r\nSubject: Many parts\r\nDate: Tue, 02 Jan 2024 09:00:00 +0000\r\nMessage-ID: <many@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"mx\"\r\n\r\n\
--mx\r\nContent-Type: multipart/related; boundary=\"rel\"\r\n\r\n\
--rel\r\nContent-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n\
--alt\r\nContent-Type: text/plain\r\n\r\nplain body\r\n\
--alt\r\nContent-Type: text/html\r\n\r\n<p>html <img src=\"cid:logo\"></p>\r\n\
--alt--\r\n\
--rel\r\nContent-Type: image/png; name=\"logo.png\"\r\nContent-Disposition: inline; filename=\"logo.png\"\r\nContent-ID: <logo>\r\nContent-Transfer-Encoding: base64\r\n\r\n{png}\r\n\
--rel--\r\n\
--mx\r\nContent-Type: application/octet-stream; name=\"data.bin\"\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{bin}\r\n\
--mx\r\nContent-Type: text/csv; name=\"t.csv\"\r\nContent-Disposition: attachment; filename=\"t.csv\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db,c\r\n\
--mx--\r\n",
        png = b64_wrapped(&png),
        bin = b64_wrapped(&binary),
    );
    env.gm
        .admin("alice", PW)
        .await
        .append("INBOX", None, None, mail)
        .await
        .unwrap();
    let b = cfg(&env, |_| {});
    let a = id("alice");
    let r = b.list_messages(&a, "INBOX", page()).await.unwrap().items[0]
        .reference
        .clone();

    // The part-level fetch must agree with the full-message attachment numbering.
    let meta = b.get_message(&r, 100_000).await.unwrap().attachments;
    assert!(meta.len() >= 3, "{meta:?}");
    let mut seen_bin = false;
    let mut seen_csv = false;
    for m in &meta {
        let got = b.get_attachment(&r, m.index, 100_000).await.unwrap();
        assert_eq!(got.meta.filename, m.filename, "index {}", m.index);
        assert_eq!(got.meta.content_type, m.content_type);
        assert_eq!(got.meta.inline, m.inline);
        assert_eq!(got.bytes.len(), m.size as usize);
        match m.filename.as_deref() {
            Some("data.bin") => {
                assert_eq!(got.bytes, binary, "binary bytes must round-trip exactly");
                seen_bin = true;
            }
            Some("t.csv") => {
                assert_eq!(got.bytes, b"a=b,c");
                seen_csv = true;
            }
            Some("logo.png") => assert_eq!(got.bytes, png),
            other => panic!("unexpected attachment {other:?}"),
        }
    }
    assert!(seen_bin && seen_csv);

    let bin_index = meta
        .iter()
        .find(|m| m.filename.as_deref() == Some("data.bin"))
        .unwrap()
        .index;
    assert_eq!(
        b.get_attachment(&r, bin_index, 4999)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded
    );
    assert_eq!(
        b.get_attachment(&r, 99, 100_000).await.unwrap_err().code(),
        ErrorCode::MessageNotFound
    );
    let stale = MessageRef {
        uid_validity: r.uid_validity + 1,
        ..r.clone()
    };
    assert_eq!(
        b.get_attachment(&stale, 0, 10).await.unwrap_err().code(),
        ErrorCode::StaleReference
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_part_is_refused_without_downloading_it() {
    let Some(env) = env().await else { return };
    let big = vec![b'z'; 300_000];
    let mail = format!(
        "From: bob@example.org\r\nTo: alice@localhost\r\nSubject: Big\r\nMessage-ID: <big@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"mx\"\r\n\r\n--mx\r\nContent-Type: text/plain\r\n\r\nhi\r\n--mx\r\nContent-Type: application/octet-stream; name=\"big.bin\"\r\nContent-Disposition: attachment; filename=\"big.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--mx--\r\n",
        b64_wrapped(&big)
    );
    env.gm
        .admin("alice", PW)
        .await
        .append("INBOX", None, None, mail)
        .await
        .unwrap();
    let b = cfg(&env, |_| {});
    let r = b
        .list_messages(&id("alice"), "INBOX", page())
        .await
        .unwrap()
        .items[0]
        .reference
        .clone();
    assert_eq!(
        b.get_attachment(&r, 0, 1000).await.unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
    assert_eq!(
        b.get_attachment(&r, 0, 300_000).await.unwrap().bytes,
        big,
        "the same part succeeds when the cap allows it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sent_copy_appears_seen_and_requires_send_permission() {
    let Some(env) = env().await else { return };
    env.gm
        .admin("alice", PW)
        .await
        .create("Sent")
        .await
        .unwrap();
    let a = id("alice");
    let raw = eml(
        "Delivered",
        "alice@localhost",
        "sent1@localhost",
        "",
        "body",
    )
    .into_bytes();

    let denied = cfg(&env, |c| c.folders.sent = Some("Sent".into()));
    assert_eq!(
        denied
            .append_sent(&a, raw.clone())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::ReadOnlyAccount
    );
    assert_eq!(count(&env, "Sent").await, 0);

    let b = cfg(&env, |c| {
        c.permissions.send = true;
        c.folders.sent = Some("Sent".into());
    });
    b.append_sent(&a, raw).await.unwrap();
    let sent = b.list_messages(&a, "Sent", page()).await.unwrap();
    assert_eq!(sent.items.len(), 1);
    assert_eq!(sent.items[0].subject.0, "Delivered");
    assert!(sent.items[0].flags.seen, "Sent copy is stored \\Seen");

    // No configured folder and (on GreenMail) no advertised special-use: the conventional
    // name "Sent" is found, so a stock Dovecot without RFC 6154 still gets its copy.
    let unconfigured = cfg(&env, |c| c.permissions.send = true);
    unconfigured.append_sent(&a, b"x".to_vec()).await.unwrap();
    assert_eq!(count(&env, "Sent").await, 2);
}
