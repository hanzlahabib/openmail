#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end checks that an approval minted for one exact message is the only way
//! to obtain an `ApprovalProof`, and that it is single-use, bound and persistent.
use std::sync::Arc;
use std::time::Duration;

use openmail_core::ErrorCode;
use openmail_core::ids::AccountId;
use openmail_core::model::Address;
use openmail_security::{
    ApprovalGrantor, ApprovalIssuer, ApprovalVerifier, Clock, GrantDecision, SendIntent,
    SqliteApprovalStore,
};
use openmail_smtp::{ApprovalProof, Attachment, SendRequest, SendRequestDescriptor};

#[derive(Debug, Clone)]
struct TestClock(Arc<std::sync::atomic::AtomicU64>);
impl Clock for TestClock {
    fn unix_secs(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn monotonic_ms(&self) -> u64 {
        self.unix_secs() * 1000
    }
}

struct Human;
impl ApprovalGrantor for Human {
    fn review(&self, _: &SendIntent) -> openmail_core::Result<GrantDecision> {
        Ok(GrantDecision::Approve)
    }
}

fn addr(e: &str) -> Address {
    Address {
        name: None,
        email: e.into(),
    }
}

fn request() -> SendRequest {
    SendRequest {
        idempotency_key: "k".into(),
        from: addr("me@example.com"),
        to: vec![addr("you@example.org")],
        cc: vec![addr("cc@example.org")],
        bcc: vec![addr("hidden@example.net")],
        subject: "Hello".into(),
        text: Some("body".into()),
        html: None,
        attachments: vec![Attachment {
            filename: "a.txt".into(),
            content_type: "text/plain".into(),
            data: b"attached".to_vec(),
        }],
        in_reply_to: None,
        references: vec![],
    }
}

fn account() -> AccountId {
    AccountId::new("work").unwrap()
}

struct Env {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    now: Arc<std::sync::atomic::AtomicU64>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.sqlite");
        Self {
            _dir: dir,
            path,
            now: Arc::new(10_000.into()),
        }
    }
    fn open(
        &self,
    ) -> (
        ApprovalIssuer<SqliteApprovalStore, TestClock>,
        ApprovalVerifier<SqliteApprovalStore, TestClock>,
    ) {
        let store = Arc::new(SqliteApprovalStore::open(&self.path).unwrap());
        let clk = TestClock(self.now.clone());
        (
            ApprovalIssuer::new(store.clone(), clk.clone()),
            ApprovalVerifier::new(store, clk),
        )
    }
    fn advance(&self, s: u64) {
        self.now.fetch_add(s, std::sync::atomic::Ordering::SeqCst);
    }
}

fn mint(
    iss: &ApprovalIssuer<SqliteApprovalStore, TestClock>,
    principal: &str,
    req: &SendRequest,
    ttl: u64,
) -> String {
    let d = descriptor(req);
    let intent = SendIntent::from_descriptor(principal, &d).unwrap();
    iss.issue(&Human, &intent, Duration::from_secs(ttl))
        .unwrap()
        .as_str()
        .to_owned()
}

/// The descriptor is derived by smtp; obtaining it via a recording consumer is the only public route.
fn descriptor(req: &SendRequest) -> SendRequestDescriptor {
    struct Capture(std::sync::Mutex<Option<SendRequestDescriptor>>);
    impl openmail_smtp::ApprovalConsumer for Capture {
        fn consume(
            &self,
            _: &str,
            d: &SendRequestDescriptor,
            _: Option<&str>,
        ) -> openmail_core::Result<()> {
            *self.0.lock().unwrap() = Some(d.clone());
            Ok(())
        }
    }
    let c = Capture(std::sync::Mutex::new(None));
    ApprovalProof::obtain(&c, "p", &account(), req, None).unwrap();
    c.0.lock().unwrap().take().unwrap()
}

fn obtain(
    ver: &ApprovalVerifier<SqliteApprovalStore, TestClock>,
    principal: &str,
    req: &SendRequest,
    token: Option<&str>,
) -> openmail_core::Result<ApprovalProof> {
    ApprovalProof::obtain(ver, principal, &account(), req, token)
}

#[test]
fn approved_request_yields_a_proof_once() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let token = mint(&iss, "client", &request(), 60);
    assert!(obtain(&ver, "client", &request(), Some(&token)).is_ok());
    assert_eq!(
        obtain(&ver, "client", &request(), Some(&token))
            .unwrap_err()
            .code(),
        ErrorCode::ApprovalInvalid
    );
}

#[test]
fn no_token_is_not_approved() {
    let env = Env::new();
    let (_iss, ver) = env.open();
    assert_eq!(
        obtain(&ver, "client", &request(), None).unwrap_err().code(),
        ErrorCode::SendNotApproved
    );
}

#[test]
fn any_changed_field_is_rejected_and_does_not_burn_the_approval() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let token = mint(&iss, "client", &request(), 60);

    let mut variants: Vec<SendRequest> = Vec::new();
    let mut r = request();
    r.to.push(addr("evil@example.org"));
    variants.push(r);
    let mut r = request();
    r.bcc.clear(); // dropping a bcc changes the binding too
    variants.push(r);
    let mut r = request();
    // moving a recipient between to/cc must not reuse the approval (content hash binds roles)
    let moved = r.cc.remove(0);
    r.to.push(moved);
    variants.push(r);
    let mut r = request();
    r.subject = "Hello!".into();
    variants.push(r);
    let mut r = request();
    r.text = Some("other body".into());
    variants.push(r);
    let mut r = request();
    r.html = Some("<b>x</b>".into());
    variants.push(r);
    let mut r = request();
    r.attachments[0].data = b"swapped".to_vec();
    variants.push(r);
    let mut r = request();
    r.attachments.clear();
    variants.push(r);
    let mut r = request();
    r.references = vec!["<a@b.c>".into()];
    variants.push(r);

    for (i, v) in variants.iter().enumerate() {
        assert_eq!(
            obtain(&ver, "client", v, Some(&token)).unwrap_err().code(),
            ErrorCode::ApprovalInvalid,
            "variant {i}"
        );
    }
    // A failed mismatch must not burn the approval for the genuine message.
    assert!(obtain(&ver, "client", &request(), Some(&token)).is_ok());
}

#[test]
fn approval_for_request_a_cannot_authorize_request_b() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let mut b = request();
    b.subject = "Different".into();
    let token_a = mint(&iss, "client", &request(), 60);
    assert!(obtain(&ver, "client", &b, Some(&token_a)).is_err());
}

#[test]
fn wrong_principal_is_rejected() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let token = mint(&iss, "alice", &request(), 60);
    assert_eq!(
        obtain(&ver, "mallory", &request(), Some(&token))
            .unwrap_err()
            .code(),
        ErrorCode::ApprovalInvalid
    );
    assert!(obtain(&ver, "alice", &request(), Some(&token)).is_ok());
}

#[test]
fn wrong_account_is_rejected() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let token = mint(&iss, "client", &request(), 60);
    let other = AccountId::new("personal").unwrap();
    assert!(ApprovalProof::obtain(&ver, "client", &other, &request(), Some(&token)).is_err());
}

#[test]
fn expired_approval_is_rejected() {
    let env = Env::new();
    let (iss, ver) = env.open();
    let token = mint(&iss, "client", &request(), 60);
    env.advance(60);
    assert_eq!(
        obtain(&ver, "client", &request(), Some(&token))
            .unwrap_err()
            .code(),
        ErrorCode::ApprovalInvalid
    );
}

#[test]
fn replay_is_rejected_after_reopening_the_store() {
    let env = Env::new();
    let token = {
        let (iss, ver) = env.open();
        let t = mint(&iss, "client", &request(), 60);
        assert!(obtain(&ver, "client", &request(), Some(&t)).is_ok());
        t
    };
    let (_iss, ver) = env.open();
    assert_eq!(
        obtain(&ver, "client", &request(), Some(&token))
            .unwrap_err()
            .code(),
        ErrorCode::ApprovalInvalid,
        "consumption must persist across reopen"
    );
}
