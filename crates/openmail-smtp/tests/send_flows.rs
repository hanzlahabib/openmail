#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end SMTP flows against an in-process scripted server (see support/fake_server.rs).
//! Nothing here talks to a real host.
#[path = "support/fake_server.rs"]
mod fake_server;

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use fake_server::{AfterData, Script, Server, TlsKind, start};
use openmail_core::backend::SecretSource;
use openmail_core::config::{AccountConfig, Config, CredentialRef};
use openmail_core::model::Address;
use openmail_core::{ErrorCode, Result};
use openmail_smtp::outbox::OutboxState;
use openmail_smtp::{
    ApprovalProof, OutboxStore, Outcome, SendOutcome, SendRequest, SmtpClient, SmtpOptions,
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

fn proof(r: &SendRequest) -> ApprovalProof {
    ApprovalProof::new(r.content_hash(), "approval-1")
}

type Client = SmtpClient<SqliteOutbox, FixedSecret>;

fn client(db: &Path, server: &Server, password: &'static str) -> Client {
    let options = SmtpOptions {
        extra_root_certs_pem: vec![server.root_pem.clone()],
        ..SmtpOptions::default()
    };
    SmtpClient::new(
        SqliteOutbox::open(db).unwrap(),
        FixedSecret(password),
        options,
    )
}

async fn send(c: &Client, acct: &AccountConfig, r: SendRequest) -> Result<SendOutcome> {
    let p = proof(&r);
    c.send(acct, r, &p).await
}

fn db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outbox.sqlite");
    (dir, path)
}

#[tokio::test]
async fn success_over_implicit_tls_delivers_and_records_acceptance() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    let acct = account(srv.port, "implicit", 10);
    let out = send(&c, &acct, request("k-ok")).await.unwrap();
    let SendOutcome::Sent { message_id } = out else {
        panic!("expected Sent")
    };
    assert!(message_id.ends_with("@example.com>"));

    let msgs = srv.state.messages.lock().unwrap().clone();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].from, "me@example.com");
    assert_eq!(msgs[0].rcpts, ["you@example.org", "hidden@example.net"]);
    assert!(msgs[0].data.contains(&format!("Message-ID: {message_id}")));
    assert!(
        !msgs[0].data.contains("hidden@example.net"),
        "bcc leaked into headers"
    );

    let rec = c.outbox().get(&acct.id, "k-ok").await.unwrap().unwrap();
    assert_eq!(rec.state, OutboxState::Accepted);
    let audit = c.outbox().audit_entries(&acct.id, 10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(
        (
            audit[0].outcome.as_str(),
            audit[0].recipients,
            audit[0].message_id.as_str()
        ),
        ("accepted", 2, message_id.as_str())
    );
}

#[tokio::test]
async fn success_over_starttls_never_authenticates_in_plaintext() {
    let srv = start(Script::new(TlsKind::StartTls)).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    send(&c, &account(srv.port, "start_tls", 10), request("k-st"))
        .await
        .unwrap();
    assert_eq!(srv.state.message_count(), 1);
    assert!(!srv.state.auth_over_plaintext.load(Ordering::SeqCst));
}

#[tokio::test]
async fn starttls_is_required_not_downgraded() {
    let srv = start(Script::new(TlsKind::Plain)).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    let acct = account(srv.port, "start_tls", 10);
    let err = send(&c, &acct, request("k-down")).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConnectionFailed);
    assert_eq!(
        srv.state.auth_attempts.load(Ordering::SeqCst),
        0,
        "credentials must not be offered without TLS"
    );
    assert_eq!(srv.state.message_count(), 0);
    assert_eq!(
        c.outbox()
            .get(&acct.id, "k-down")
            .await
            .unwrap()
            .unwrap()
            .state,
        OutboxState::Rejected
    );
}

#[tokio::test]
async fn implicit_tls_against_plaintext_server_fails_closed() {
    let srv = start(Script::new(TlsKind::Plain)).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    let err = send(&c, &account(srv.port, "implicit", 3), request("k-plain"))
        .await
        .unwrap_err();
    assert!(
        matches!(err.code(), ErrorCode::ConnectionFailed | ErrorCode::Timeout),
        "{err}"
    );
    assert_eq!(srv.state.auth_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(srv.state.message_count(), 0);
}

#[tokio::test]
async fn untrusted_certificate_is_rejected() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    // Deliberately do NOT trust the server's self-signed root.
    let c = SmtpClient::new(
        SqliteOutbox::open(&path).unwrap(),
        FixedSecret("s3cret"),
        SmtpOptions::default(),
    );
    let err = send(&c, &account(srv.port, "implicit", 10), request("k-cert"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConnectionFailed);
    assert_eq!(srv.state.auth_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(srv.state.message_count(), 0);
}

#[tokio::test]
async fn auth_failure_is_reported_and_nothing_is_sent() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "wrong-password");
    let acct = account(srv.port, "implicit", 10);
    let err = send(&c, &acct, request("k-auth")).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthFailed);
    assert!(!err.to_string().contains("wrong-password"));
    assert_eq!(srv.state.message_count(), 0);
    assert_eq!(
        c.outbox()
            .get(&acct.id, "k-auth")
            .await
            .unwrap()
            .unwrap()
            .state,
        OutboxState::Rejected
    );
}

#[tokio::test]
async fn recipient_rejection_fails_whole_send() {
    let mut script = Script::new(TlsKind::Implicit);
    script.reject_rcpt = true;
    let srv = start(script).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    let acct = account(srv.port, "implicit", 10);
    let err = send(&c, &acct, request("k-rcpt")).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidInput);
    assert_eq!(srv.state.message_count(), 0);
    assert_eq!(
        c.outbox()
            .get(&acct.id, "k-rcpt")
            .await
            .unwrap()
            .unwrap()
            .state,
        OutboxState::Rejected
    );
}

#[tokio::test]
async fn final_server_rejection_is_rejected_not_uncertain() {
    let mut script = Script::new(TlsKind::Implicit);
    script.after_data = AfterData::Reject;
    let srv = start(script).await;
    let (_d, path) = db();
    let c = client(&path, &srv, "s3cret");
    let acct = account(srv.port, "implicit", 10);
    let err = send(&c, &acct, request("k-554")).await.unwrap_err();
    assert_ne!(err.code(), ErrorCode::DeliveryUncertain);
    assert_eq!(
        c.outbox()
            .get(&acct.id, "k-554")
            .await
            .unwrap()
            .unwrap()
            .state,
        OutboxState::Rejected
    );
}

#[tokio::test]
async fn timeout_after_data_is_uncertain_and_never_resent_even_after_restart() {
    let mut script = Script::new(TlsKind::Implicit);
    script.after_data = AfterData::Hang;
    let srv = start(script).await;
    let (_d, path) = db();
    let acct = account(srv.port, "implicit", 1);
    {
        let c = client(&path, &srv, "s3cret");
        let err = send(&c, &acct, request("k-hang")).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::DeliveryUncertain);
        assert_eq!(
            c.outbox()
                .get(&acct.id, "k-hang")
                .await
                .unwrap()
                .unwrap()
                .state,
            OutboxState::Uncertain
        );
        // Same process, same key: no new connection, still uncertain.
        let before = srv.state.connections.load(Ordering::SeqCst);
        let again = send(&c, &acct, request("k-hang")).await.unwrap_err();
        assert_eq!(again.code(), ErrorCode::DeliveryUncertain);
        assert_eq!(srv.state.connections.load(Ordering::SeqCst), before);
    }
    // "Restart": drop everything, reopen the same SQLite file.
    let c2 = client(&path, &srv, "s3cret");
    let again = send(&c2, &acct, request("k-hang")).await.unwrap_err();
    assert_eq!(again.code(), ErrorCode::DeliveryUncertain);
    assert_eq!(
        srv.state.message_count(),
        1,
        "message must have been transmitted exactly once"
    );

    // Operator says it was not delivered -> the same key may be sent again.
    let rec = c2
        .resolve_uncertain(
            &acct.id,
            "k-hang",
            Outcome::NotDelivered,
            "checked Sent folder",
        )
        .await
        .unwrap();
    assert_eq!(rec.state, OutboxState::Rejected);
    let _ = send(&c2, &acct, request("k-hang")).await; // hangs again -> uncertain again; proves re-send is possible
    assert_eq!(srv.state.message_count(), 2);
    let audit = c2.outbox().audit_entries(&acct.id, 10).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.outcome == "operator_resolved_not_delivered")
    );
    assert!(audit.iter().all(|a| a.recipients == 2));
}

#[tokio::test]
async fn crash_during_data_recovers_as_uncertain_on_reopen() {
    let mut script = Script::new(TlsKind::Implicit);
    script.after_data = AfterData::Hang;
    let srv = start(script).await;
    let (_d, path) = db();
    let acct = account(srv.port, "implicit", 60);
    let c = client(&path, &srv, "s3cret");
    let task = tokio::spawn({
        let acct = acct.clone();
        async move {
            let _ = send(&c, &acct, request("k-crash")).await;
        }
    });
    for _ in 0..200 {
        if srv.state.message_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(srv.state.message_count(), 1, "server never saw the message");
    task.abort(); // simulated process death: no finish() is ever written
    let _ = task.await;

    let reopened = client(&path, &srv, "s3cret");
    let rec = reopened
        .outbox()
        .get(&acct.id, "k-crash")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.state, OutboxState::Uncertain);
    let err = send(&reopened, &acct, request("k-crash"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeliveryUncertain);
    assert_eq!(srv.state.message_count(), 1);
}

#[tokio::test]
async fn duplicate_key_after_acceptance_does_not_resend() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    let acct = account(srv.port, "implicit", 10);
    let c = client(&path, &srv, "s3cret");
    let first = send(&c, &acct, request("k-dup")).await.unwrap();
    let c2 = client(&path, &srv, "s3cret"); // also across restart
    let second = send(&c2, &acct, request("k-dup")).await.unwrap();
    let (SendOutcome::Sent { message_id: a }, SendOutcome::AlreadyAccepted { message_id: b }) =
        (first, second)
    else {
        panic!("unexpected outcomes")
    };
    assert_eq!(a, b);
    assert_eq!(srv.state.message_count(), 1);
    assert_eq!(srv.state.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn key_reuse_with_different_content_is_refused() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    let acct = account(srv.port, "implicit", 10);
    let c = client(&path, &srv, "s3cret");
    send(&c, &acct, request("k-same")).await.unwrap();
    let mut other = request("k-same");
    other.subject = "Different".into();
    let err = send(&c, &acct, other).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidInput);
    assert_eq!(srv.state.message_count(), 1);
}

#[tokio::test]
async fn approval_must_match_content_and_sender_must_be_own_identity() {
    let srv = start(Script::new(TlsKind::Implicit)).await;
    let (_d, path) = db();
    let acct = account(srv.port, "implicit", 10);
    let c = client(&path, &srv, "s3cret");

    let approved = request("k-appr");
    let stale = ApprovalProof::new(approved.content_hash(), "t");
    let mut tampered = request("k-appr");
    tampered.bcc.push(Address {
        name: None,
        email: "extra@example.net".into(),
    });
    let err = c.send(&acct, tampered, &stale).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ApprovalInvalid);

    let mut spoof = request("k-spoof");
    spoof.from.email = "ceo@example.com".into();
    let err = send(&c, &acct, spoof.clone()).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AccessDenied);

    let options = SmtpOptions {
        aliases: vec!["ceo@example.com".into()],
        extra_root_certs_pem: vec![srv.root_pem.clone()],
        ..SmtpOptions::default()
    };
    let aliased = SmtpClient::new(
        SqliteOutbox::open(&path).unwrap(),
        FixedSecret("s3cret"),
        options,
    );
    send(&aliased, &acct, spoof).await.unwrap();
    assert_eq!(srv.state.message_count(), 1);
    assert_eq!(
        srv.state.messages.lock().unwrap()[0].from,
        "ceo@example.com"
    );
}
