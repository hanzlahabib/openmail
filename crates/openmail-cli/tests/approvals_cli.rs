#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `openmail-mcp approvals ...` against a real SQLite file in a temp state dir,
//! with a verifier handle standing in for the server.
use std::path::Path;
use std::sync::Arc;

use assert_cmd::Command;
use openmail_core::ErrorCode;
use openmail_core::ids::AccountId;
use openmail_core::model::Address;
use openmail_security::{
    ApprovalVerifier, PendingApprovals, PendingId, SqliteApprovalStore, SystemClock,
};
use openmail_smtp::{ApprovalConsumer, ApprovalProof, SendRequest, SendRequestDescriptor};

fn addr(e: &str) -> Address {
    Address {
        name: None,
        email: e.into(),
    }
}

fn send_request(subject: &str) -> SendRequest {
    SendRequest {
        idempotency_key: "k".into(),
        from: addr("me@example.com"),
        to: vec![addr("you@example.org")],
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

fn seed(state: &Path, req: &SendRequest) -> PendingId {
    let pending = PendingApprovals::open(&state.join("approvals.db"), SystemClock::new()).unwrap();
    pending
        .request("agent", &account(), &descriptor(req))
        .unwrap()
}

fn cli(state: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmail-mcp"));
    cmd.arg("--config")
        .arg(state.join("config.toml"))
        .arg("approvals")
        .arg("--state-dir")
        .arg(state)
        .args(args);
    cmd
}

fn stdout(a: assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&a.get_output().stdout).into_owned()
}

fn token_from(out: &str) -> String {
    out.lines().last().unwrap().trim().to_owned()
}

fn verifier(state: &Path) -> ApprovalVerifier<SqliteApprovalStore, SystemClock> {
    ApprovalVerifier::new(
        Arc::new(SqliteApprovalStore::open(&state.join("approvals.db")).unwrap()),
        SystemClock::new(),
    )
}

#[test]
fn list_show_grant_flow_yields_a_single_use_token() {
    let dir = tempfile::tempdir().unwrap();
    let req = send_request("Quarterly numbers");
    let id = seed(dir.path(), &req);

    let listed = stdout(cli(dir.path(), &["list"]).assert().success());
    assert!(
        listed.contains(id.as_str()) && listed.contains("Quarterly numbers"),
        "{listed}"
    );

    let shown = stdout(cli(dir.path(), &["show", id.as_str()]).assert().success());
    for needle in [
        "you@example.org",
        "hidden@example.net",
        "Quarterly numbers",
        "Content hash:",
    ] {
        assert!(shown.contains(needle), "show missing {needle}: {shown}");
    }

    let granted = stdout(
        cli(dir.path(), &["grant", id.as_str()])
            .write_stdin(format!("{}\n", id.as_str()))
            .assert()
            .success(),
    );
    assert!(
        granted.contains("you@example.org"),
        "grant must show the recipients"
    );
    let token = token_from(&granted);

    let ver = verifier(dir.path());
    ApprovalProof::obtain(&ver, "agent", &account(), &req, Some(&token)).unwrap();
    let replay = ApprovalProof::obtain(&ver, "agent", &account(), &req, Some(&token)).unwrap_err();
    assert_eq!(replay.code(), ErrorCode::ApprovalInvalid);

    let after = stdout(cli(dir.path(), &["list"]).assert().success());
    assert!(after.contains("No pending"), "{after}");
}

#[test]
fn wrong_typed_id_grants_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let req = send_request("Hello");
    let id = seed(dir.path(), &req);
    let failed = cli(dir.path(), &["grant", id.as_str()])
        .write_stdin("deadbeef\n")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&failed.get_output().stderr).into_owned();
    assert!(stderr.contains("nothing was approved"), "{stderr}");
    // Still pending, and a closed stdin (EOF) is not consent either.
    cli(dir.path(), &["grant", id.as_str()])
        .write_stdin("")
        .assert()
        .failure();
    let listed = stdout(cli(dir.path(), &["list"]).assert().success());
    assert!(listed.contains(id.as_str()));
}

#[test]
fn yes_flag_skips_the_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let req = send_request("Hello");
    let id = seed(dir.path(), &req);
    let out = stdout(
        cli(dir.path(), &["grant", id.as_str(), "--yes"])
            .assert()
            .success(),
    );
    ApprovalProof::obtain(
        &verifier(dir.path()),
        "agent",
        &account(),
        &req,
        Some(&token_from(&out)),
    )
    .unwrap();
}

#[test]
fn deny_removes_the_request_and_blocks_grant() {
    let dir = tempfile::tempdir().unwrap();
    let id = seed(dir.path(), &send_request("Hello"));
    cli(dir.path(), &["deny", id.as_str()]).assert().success();
    cli(dir.path(), &["grant", id.as_str(), "--yes"])
        .assert()
        .failure();
    cli(dir.path(), &["deny", id.as_str()]).assert().failure();
}

#[test]
fn unknown_or_malformed_id_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    cli(dir.path(), &["show", "zzzz"]).assert().failure();
    cli(dir.path(), &["show", "00000000"]).assert().failure();
}

#[cfg(unix)]
#[test]
fn state_dir_and_database_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("state");
    cli(&nested, &["list"]).assert().success();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&nested), 0o700);
    assert_eq!(mode(&nested.join("approvals.db")), 0o600);
}
