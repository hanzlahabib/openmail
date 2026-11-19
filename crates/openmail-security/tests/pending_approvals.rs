#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Pending-approval queue: request → human grant → single-use token, end to end
//! against a real SQLite file shared by an "issuer" and a "verifier" handle.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openmail_core::ErrorCode;
use openmail_core::ids::AccountId;
use openmail_core::model::Address;
use openmail_security::{
    ApprovalVerifier, Clock, HumanConfirmation, PendingApprovals, PendingId, PendingStatus,
    SqliteApprovalStore,
};
use openmail_smtp::{ApprovalConsumer, ApprovalProof, SendRequest, SendRequestDescriptor};

#[derive(Debug, Clone)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn unix_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn monotonic_ms(&self) -> u64 {
        self.unix_secs() * 1000
    }
}

fn addr(e: &str) -> Address {
    Address {
        name: None,
        email: e.into(),
    }
}

fn request(subject: &str, to: &str) -> SendRequest {
    SendRequest {
        idempotency_key: "k".into(),
        from: addr("me@example.com"),
        to: vec![addr(to)],
        cc: vec![],
        bcc: vec![addr("hidden@example.net")],
        subject: subject.into(),
        text: Some("body".into()),
        html: None,
        attachments: vec![],
        in_reply_to: None,
        references: vec![],
    }
}

fn account() -> AccountId {
    AccountId::new("work").unwrap()
}

fn descriptor(req: &SendRequest) -> SendRequestDescriptor {
    struct Capture(std::sync::Mutex<Option<SendRequestDescriptor>>);
    impl ApprovalConsumer for Capture {
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

struct Env {
    _dir: tempfile::TempDir,
    path: PathBuf,
    now: Arc<AtomicU64>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.db");
        Self {
            _dir: dir,
            path,
            now: Arc::new(10_000.into()),
        }
    }
    fn clock(&self) -> TestClock {
        TestClock(self.now.clone())
    }
    fn pending(&self) -> PendingApprovals<TestClock> {
        PendingApprovals::open(&self.path, self.clock()).unwrap()
    }
    fn verifier(&self) -> ApprovalVerifier<SqliteApprovalStore, TestClock> {
        ApprovalVerifier::new(
            Arc::new(SqliteApprovalStore::open(&self.path).unwrap()),
            self.clock(),
        )
    }
    fn advance(&self, s: u64) {
        self.now.fetch_add(s, Ordering::SeqCst);
    }
}

fn confirm(id: &PendingId) -> HumanConfirmation {
    HumanConfirmation::typed_id(id, id.as_str()).unwrap()
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
fn grant_consumes_once_and_replay_is_rejected() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let token = pending.grant(&id, &confirm(&id)).unwrap();
    let ver = env.verifier();
    obtain(&ver, "agent", &req, Some(token.as_str())).unwrap();
    let e = obtain(&ver, "agent", &req, Some(token.as_str())).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
}

#[test]
fn nothing_is_approved_before_a_human_grants() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let e = obtain(&env.verifier(), "agent", &req, None).unwrap_err();
    assert_eq!(e.code(), ErrorCode::SendNotApproved);
}

#[test]
fn request_is_idempotent_and_listed_with_full_descriptor() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Quarterly numbers", "You@Example.ORG");
    let d = descriptor(&req);
    let a = pending.request("agent", &account(), &d).unwrap();
    let b = pending.request("agent", &account(), &d).unwrap();
    assert_eq!(a, b);
    let other = pending.request("other-agent", &account(), &d).unwrap();
    assert_ne!(a, other, "a different principal is a different request");

    let list = pending.list_pending().unwrap();
    assert_eq!(list.len(), 2);
    let item = pending.get(&a).unwrap().unwrap();
    assert_eq!(item.subject, "Quarterly numbers");
    assert_eq!(
        item.recipients,
        vec!["You@example.org", "hidden@example.net"]
    );
    assert_eq!(item.content_hash, d.content_hash().to_hex());
    assert_eq!(item.principal, "agent");
    assert_eq!(item.status, PendingStatus::Pending);
    assert_eq!(item.expires_at, 10_000 + 3_600);
}

#[test]
fn granted_and_denied_requests_leave_the_pending_list() {
    let env = Env::new();
    let pending = env.pending();
    let r1 = request("one", "a@example.org");
    let r2 = request("two", "b@example.org");
    let i1 = pending.request("p", &account(), &descriptor(&r1)).unwrap();
    let i2 = pending.request("p", &account(), &descriptor(&r2)).unwrap();
    pending.grant(&i1, &confirm(&i1)).unwrap();
    assert!(pending.deny(&i2).unwrap());
    assert!(!pending.deny(&i2).unwrap(), "already decided");
    assert!(pending.list_pending().unwrap().is_empty());
    assert_eq!(
        pending.get(&i2).unwrap().unwrap().status,
        PendingStatus::Denied
    );
    // Denied or already granted requests can never mint a token.
    for id in [&i1, &i2] {
        let e = pending.grant(id, &confirm(id)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
    }
}

#[test]
fn denied_request_yields_no_usable_token() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    pending.deny(&id).unwrap();
    let guess = "AAAAAAAAAAAAAAAAAAAAAA";
    let e = obtain(&env.verifier(), "agent", &req, Some(guess)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
}

#[test]
fn token_expires() {
    let env = Env::new();
    let pending = env.pending().with_token_ttl(Duration::from_secs(60));
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let token = pending.grant(&id, &confirm(&id)).unwrap();
    env.advance(61);
    let e = obtain(&env.verifier(), "agent", &req, Some(token.as_str())).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
}

#[test]
fn token_ttl_is_capped_at_the_maximum() {
    let env = Env::new();
    let pending = env.pending().with_token_ttl(Duration::from_secs(86_400));
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let token = pending.grant(&id, &confirm(&id)).unwrap();
    env.advance(901);
    assert!(obtain(&env.verifier(), "agent", &req, Some(token.as_str())).is_err());
}

#[test]
fn unanswered_request_expires_and_cannot_be_granted() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    env.advance(3_601);
    assert!(pending.list_pending().unwrap().is_empty());
    assert_eq!(
        pending.grant(&id, &confirm(&id)).unwrap_err().code(),
        ErrorCode::ApprovalInvalid
    );
    // The agent may ask again and gets a fresh, grantable request.
    let again = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    pending.grant(&again, &confirm(&again)).unwrap();
}

#[test]
fn token_is_bound_to_principal_and_exact_message() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let token = pending.grant(&id, &confirm(&id)).unwrap();
    let ver = env.verifier();

    let wrong_principal = obtain(&ver, "intruder", &req, Some(token.as_str())).unwrap_err();
    assert_eq!(wrong_principal.code(), ErrorCode::ApprovalInvalid);
    let tampered = request("Hello", "attacker@example.org");
    let e = obtain(&ver, "agent", &tampered, Some(token.as_str())).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
    let e = obtain(
        &ver,
        "agent",
        &request("Hello!", "you@example.org"),
        Some(token.as_str()),
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
    // None of the failed attempts burned the token.
    obtain(&ver, "agent", &req, Some(token.as_str())).unwrap();
}

#[test]
fn tampered_database_row_cannot_widen_a_grant() {
    let env = Env::new();
    let pending = env.pending();
    let req = request("Hello", "you@example.org");
    let id = pending
        .request("agent", &account(), &descriptor(&req))
        .unwrap();
    let raw = rusqlite::Connection::open(&env.path).unwrap();
    raw.execute(
        "UPDATE pending_approvals SET recipients = recipients || char(10) || 'evil@example.net'",
        [],
    )
    .unwrap();
    let e = pending.grant(&id, &confirm(&id)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalInvalid);
}

#[test]
fn confirmation_must_name_the_same_request() {
    let env = Env::new();
    let pending = env.pending();
    let a = pending
        .request("p", &account(), &descriptor(&request("a", "a@example.org")))
        .unwrap();
    let b = pending
        .request("p", &account(), &descriptor(&request("b", "b@example.org")))
        .unwrap();
    assert!(HumanConfirmation::typed_id(&a, "deadbeef").is_err());
    let for_a = confirm(&a);
    assert_eq!(
        pending.grant(&b, &for_a).unwrap_err().code(),
        ErrorCode::InvalidInput
    );
}

#[test]
fn account_mismatch_between_argument_and_descriptor_is_refused() {
    let env = Env::new();
    let pending = env.pending();
    let d = descriptor(&request("Hello", "you@example.org"));
    let other = AccountId::new("personal").unwrap();
    assert!(pending.request("agent", &other, &d).is_err());
}

#[cfg(unix)]
#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let _ = env.pending();
    assert_eq!(
        std::fs::metadata(&env.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// The MCP side must have no route to minting. Everything that can mint
/// (`ApprovalIssuer`, `ApprovalGrantor`, `HumanConfirmation`, a `.grant(` call) is
/// allowed only in openmail-security and the CLI. `PendingApprovals` itself is NOT
/// forbidden: the server holds it to `request()` a human review, which mints nothing.
/// Comment lines are ignored so documentation can name these types.
#[test]
fn no_other_crate_mints_approvals() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let forbidden = [
        "ApprovalIssuer",
        "ApprovalGrantor",
        "HumanConfirmation",
        ".grant(",
    ];
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if matches!(name.as_str(), "openmail-security" | "openmail-cli") || !dir.is_dir() {
            continue;
        }
        scan(&dir.join("src"), &forbidden, &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "minting API used outside CLI: {offenders:?}"
    );
}

fn scan(dir: &Path, forbidden: &[&str], out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            scan(&p, forbidden, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let text = std::fs::read_to_string(&p).unwrap();
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for f in forbidden {
                if code.contains(f) {
                    out.push(format!("{}: {f}", p.display()));
                }
            }
        }
    }
}
