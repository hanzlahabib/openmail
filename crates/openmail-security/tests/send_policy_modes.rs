//! The owner's approval mode decides whether a send without a human token may proceed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use openmail_core::ids::AccountId;
use openmail_core::model::Address;
use openmail_core::{Error, ErrorCode, Result};
use openmail_security::{ApprovalMode, PolicyConsumer, SendPolicyStore, SystemClock};
use openmail_smtp::{ApprovalConsumer, ApprovalProof, SendRequest, SendRequestDescriptor};

/// Stands in for the human-approval verifier: refuses unless a token is given.
struct Human(AtomicUsize);
impl ApprovalConsumer for Human {
    fn consume(&self, _: &str, _: &SendRequestDescriptor, token: Option<&str>) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        match token {
            Some("good") => Ok(()),
            Some(_) => Err(Error::new(ErrorCode::ApprovalInvalid, "bad")),
            None => Err(Error::new(ErrorCode::SendNotApproved, "needs a human")),
        }
    }
}

fn request(to: &str) -> SendRequest {
    let a = |e: &str| Address {
        name: None,
        email: e.to_owned(),
    };
    SendRequest {
        idempotency_key: format!("k-{to}"),
        from: a("me@work.example"),
        to: vec![a(to)],
        cc: vec![],
        bcc: vec![],
        subject: "Hello".into(),
        text: Some("body".into()),
        html: None,
        attachments: vec![],
        in_reply_to: None,
        references: vec![],
    }
}

fn acc() -> AccountId {
    AccountId::new("work").unwrap()
}

fn attempt(c: &impl ApprovalConsumer, to: &str, token: Option<&str>) -> Result<()> {
    ApprovalProof::obtain(c, "chatgpt", &acc(), &request(to), token).map(|_| ())
}

fn consumer(
    mode: ApprovalMode,
    store: &Arc<SendPolicyStore>,
    limit: u32,
) -> PolicyConsumer<Human, SystemClock> {
    PolicyConsumer::new(
        mode,
        Arc::clone(store),
        Human(AtomicUsize::new(0)),
        SystemClock::new(),
        limit,
    )
}

#[test]
fn owner_only_delegates_nothing_even_when_rules_exist() {
    let store = Arc::new(SendPolicyStore::open_in_memory().unwrap());
    store
        .add_rule(&acc(), "@example.com", 10, 7, "", 0)
        .unwrap();
    let c = consumer(ApprovalMode::OwnerOnly, &store, 100);
    assert_eq!(
        attempt(&c, "a@example.com", None).unwrap_err().code(),
        ErrorCode::SendNotApproved
    );
    assert!(
        attempt(&c, "a@example.com", Some("good")).is_ok(),
        "a human token still works"
    );
    assert_eq!(
        attempt(&c, "a@example.com", Some("forged"))
            .unwrap_err()
            .code(),
        ErrorCode::ApprovalInvalid
    );
}

#[test]
fn rules_mode_allows_only_matching_recipients_within_quota() {
    let store = Arc::new(SendPolicyStore::open_in_memory().unwrap());
    let now = SystemClock::new();
    let t = openmail_security::Clock::unix_secs(&now);
    store
        .add_rule(&acc(), "@example.com", 2, 7, "outreach", t)
        .unwrap();
    let c = consumer(ApprovalMode::Rules, &store, 100);
    assert!(attempt(&c, "a@example.com", None).is_ok());
    assert!(attempt(&c, "b@example.com", None).is_ok());
    // Quota of 2 per day is used up: falls back to needing a human.
    assert_eq!(
        attempt(&c, "c@example.com", None).unwrap_err().code(),
        ErrorCode::SendNotApproved
    );
    // A recipient outside the rule always needs a human.
    let store2 = Arc::new(SendPolicyStore::open_in_memory().unwrap());
    store2
        .add_rule(&acc(), "@example.com", 5, 7, "", t)
        .unwrap();
    let c2 = consumer(ApprovalMode::Rules, &store2, 100);
    assert_eq!(
        attempt(&c2, "x@other.com", None).unwrap_err().code(),
        ErrorCode::SendNotApproved
    );
    // Revoking stops it immediately.
    let id = store2.list(t).unwrap()[0].id;
    store2.revoke(id).unwrap();
    assert_eq!(
        attempt(&c2, "a@example.com", None).unwrap_err().code(),
        ErrorCode::SendNotApproved
    );
}

#[test]
fn delegated_mode_trusts_the_client_but_enforces_the_daily_cap() {
    let store = Arc::new(SendPolicyStore::open_in_memory().unwrap());
    let c = consumer(ApprovalMode::Delegated, &store, 3);
    for i in 0..3 {
        assert!(
            attempt(&c, &format!("u{i}@example.com"), None).is_ok(),
            "send {i}"
        );
    }
    assert_eq!(
        attempt(&c, "u9@example.com", None).unwrap_err().code(),
        ErrorCode::LimitExceeded
    );
}
