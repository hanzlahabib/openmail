//! Integration tests against a real disposable IMAP server (GreenMail in docker).
//! They skip loudly when docker is unavailable (fail instead with OPENMAIL_REQUIRE_DOCKER=1).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "greenmail/harness.rs"]
mod harness;

use harness::*;
use openmail_core::ErrorCode;
use openmail_core::backend::{MailBackend, MailOrganizer};
use openmail_core::config::{Limits, TlsMode};
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{PageRequest, SearchQuery};
use openmail_imap::{ImapBackend, ThreadRelation};
use std::sync::atomic::Ordering;

const PW: &str = "secret";

fn page(limit: u32) -> PageRequest {
    PageRequest {
        cursor: None,
        limit,
    }
}

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

struct Env {
    gm: Greenmail,
    proxy: TlsProxy,
}

async fn env(mode: Mode, hide_move: bool) -> Option<Env> {
    let gm = Greenmail::start(&[("alice", PW), ("bob", PW), ("carol", PW)])?;
    let proxy = TlsProxy::spawn(gm.port, mode, hide_move).await;
    Some(Env { gm, proxy })
}

fn backend(
    env: &Env,
    accounts: Vec<openmail_core::config::AccountConfig>,
    limits: Limits,
) -> ImapBackend {
    ImapBackend::with_extra_roots(
        accounts,
        limits,
        secrets(&[("PW", PW), ("BAD", "wrong")]),
        std::slice::from_ref(&env.proxy.cert),
    )
    .unwrap()
}

fn alice(env: &Env, tls: TlsMode) -> openmail_core::config::AccountConfig {
    account("alice", "alice", "PW", env.proxy.port, tls)
}

#[tokio::test(flavor = "multi_thread")]
async fn login_capabilities_auth_failure_and_folders() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let mut admin = env.gm.admin("alice", PW).await;
    admin.create("Archive").await.unwrap();
    let mut cfg = alice(&env, TlsMode::Implicit);
    cfg.folders.archive = Some("Archive".into());
    let bad = account("badpw", "alice", "BAD", env.proxy.port, TlsMode::Implicit);
    let b = backend(&env, vec![cfg, bad], Limits::default());

    let report = b.test_connection(&id("alice")).await.unwrap();
    assert!(report.imap_ok, "{report:?}");
    assert!(
        report.capabilities.iter().any(|c| c == "UIDPLUS")
            && report.capabilities.iter().any(|c| c == "MOVE")
    );

    let folders = b.list_folders(&id("alice")).await.unwrap();
    let inbox = folders.iter().find(|f| f.name == "INBOX").unwrap();
    assert_eq!(inbox.role.as_deref(), Some("inbox"));
    assert!(inbox.selectable);
    let archive = folders
        .iter()
        .find(|f| f.name == "Archive")
        .expect("Archive listed");
    assert_eq!(
        archive.role.as_deref(),
        Some("archive"),
        "config FolderMap supplies the role"
    );

    let status = b.folder_status(&id("alice"), "INBOX").await.unwrap();
    assert_eq!((status.exists, status.name.as_str()), (0, "INBOX"));
    assert!(status.uid_validity > 0);
    assert_eq!(
        b.folder_status(&id("alice"), "Nope")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::FolderNotFound
    );

    // Wrong password: typed error for operations, diagnostic (not Err) for test_connection.
    assert_eq!(
        b.list_folders(&id("badpw")).await.unwrap_err().code(),
        ErrorCode::AuthFailed
    );
    let report = b.test_connection(&id("badpw")).await.unwrap();
    assert!(!report.imap_ok);
    assert!(
        report
            .detail
            .as_deref()
            .unwrap()
            .contains("authentication failed")
    );
    assert!(
        !report.detail.unwrap().contains("wrong"),
        "secret must not leak"
    );
    assert_eq!(
        b.list_folders(&id("ghost")).await.unwrap_err().code(),
        ErrorCode::AccountNotFound
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn starttls_works_and_unknown_ca_is_rejected() {
    let Some(env) = env(Mode::StartTls, false).await else {
        return;
    };
    let ok = backend(
        &env,
        vec![alice(&env, TlsMode::StartTls)],
        Limits::default(),
    );
    assert!(ok.test_connection(&id("alice")).await.unwrap().imap_ok);

    // Same server, but the proxy certificate is NOT trusted: verification must fail closed.
    let strict = ImapBackend::new(
        vec![alice(&env, TlsMode::StartTls)],
        Limits::default(),
        secrets(&[("PW", PW)]),
    )
    .unwrap();
    let report = strict.test_connection(&id("alice")).await.unwrap();
    assert!(
        !report.imap_ok,
        "untrusted certificate must not be accepted"
    );
    assert!(report.detail.unwrap().contains("TLS"));
    assert_eq!(
        strict.list_folders(&id("alice")).await.unwrap_err().code(),
        ErrorCode::ConnectionFailed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_search_and_pagination() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let mut admin = env.gm.admin("alice", PW).await;
    for i in 1..=7 {
        let from = if i % 2 == 0 {
            "even@example.com"
        } else {
            "odd@example.com"
        };
        let subject = if i == 3 {
            "Café menu".to_owned()
        } else {
            format!("Message number {i}")
        };
        let flags = if i == 5 {
            Some("(\\Flagged \\Seen)")
        } else {
            None
        };
        let m = eml(
            &subject,
            from,
            &format!("m{i}@example.com"),
            "",
            &format!("body {i}"),
        );
        admin.append("INBOX", flags, None, m).await.unwrap();
    }
    admin.append("INBOX", None, None, PDF_MAIL).await.unwrap();
    let b = backend(
        &env,
        vec![alice(&env, TlsMode::Implicit)],
        Limits::default(),
    );
    let a = id("alice");

    // Pagination walks newest -> oldest with no gaps or duplicates.
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let p = b
            .list_messages(
                &a,
                "INBOX",
                PageRequest {
                    cursor: cursor.clone(),
                    limit: 3,
                },
            )
            .await
            .unwrap();
        assert!(p.items.len() <= 3);
        seen.extend(p.items.iter().map(|m| m.reference.uid));
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen.len(), 8);
    assert!(
        seen.windows(2).all(|w| w[0] > w[1]),
        "strictly descending: {seen:?}"
    );

    let first = b.list_messages(&a, "INBOX", page(50)).await.unwrap();
    assert_eq!(first.items.len(), 8);
    assert!(first.next_cursor.is_none());
    let pdf = &first.items[0];
    assert_eq!(pdf.subject.0, "With attachment");
    assert!(pdf.has_attachments);
    assert_eq!(first.items.iter().filter(|m| m.has_attachments).count(), 1);
    let flagged = first
        .items
        .iter()
        .find(|m| m.subject.0 == "Message number 5")
        .unwrap()
        .clone();
    assert!(flagged.flags.flagged && flagged.flags.seen);
    assert!(
        !first
            .items
            .iter()
            .find(|m| m.subject.0 == "Message number 1")
            .unwrap()
            .flags
            .seen
    );
    assert_eq!(
        first
            .items
            .iter()
            .find(|m| m.subject.0 == "Message number 2")
            .unwrap()
            .from[0]
            .email,
        "even@example.com"
    );

    // Search translation against a real server.
    let q = |f: &dyn Fn(&mut SearchQuery)| {
        let mut q = SearchQuery::default();
        f(&mut q);
        q
    };
    let from_even = b
        .search(
            &a,
            &q(&|q| q.from = Some("even@example.com".into())),
            page(50),
        )
        .await
        .unwrap();
    assert_eq!(from_even.items.len(), 3);
    let subj = b
        .search(&a, &q(&|q| q.subject = Some("number 4".into())), page(50))
        .await
        .unwrap();
    assert_eq!(subj.items.len(), 1);
    let unread = b
        .search(&a, &q(&|q| q.unread = Some(true)), page(50))
        .await
        .unwrap();
    assert_eq!(unread.items.len(), 7);
    let flagged_hits = b
        .search(&a, &q(&|q| q.flagged = Some(true)), page(50))
        .await
        .unwrap();
    assert_eq!(flagged_hits.items.len(), 1);
    let text = b
        .search(&a, &q(&|q| q.text = Some("body 6".into())), page(50))
        .await
        .unwrap();
    assert_eq!(text.items.len(), 1);
    let since_future = b
        .search(
            &a,
            &q(&|q| q.since = Some("2030-01-01T00:00:00Z".into())),
            page(50),
        )
        .await
        .unwrap();
    assert!(since_future.items.is_empty());
    let utf8 = b
        .search(&a, &q(&|q| q.subject = Some("Café".into())), page(50))
        .await
        .unwrap();
    assert_eq!(utf8.items.len(), 1, "non-ASCII search via CHARSET UTF-8");
    let attach = b
        .search(&a, &q(&|q| q.has_attachment = Some(true)), page(50))
        .await
        .unwrap();
    assert_eq!(attach.items.len(), 1);
    let no_attach = b
        .search(&a, &q(&|q| q.has_attachment = Some(false)), page(2))
        .await
        .unwrap();
    assert_eq!(no_attach.items.len(), 2);
    assert!(no_attach.next_cursor.is_some());

    // Full message, body limits, attachment metadata and bytes.
    let msg = b.get_message(&pdf.reference, 100_000).await.unwrap();
    assert_eq!(msg.body.text.as_ref().unwrap().0.trim(), "see file");
    assert_eq!(msg.attachments.len(), 1);
    assert_eq!(msg.attachments[0].filename.as_deref(), Some("a.pdf"));
    let data = b.fetch_attachment(&pdf.reference, 0, 1024).await.unwrap();
    assert!(data.bytes.starts_with(b"%PDF"));
    assert_eq!(
        b.fetch_attachment(&pdf.reference, 0, 2)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded
    );
    let m2 = b.get_message(&flagged.reference, 3).await.unwrap();
    assert!(m2.body.truncated);
    assert!(m2.body.text.unwrap().0.len() <= 3);
    assert_eq!(
        b.list_messages(&a, "Missing", page(5))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::FolderNotFound
    );
}

async fn seed_three(env: &Env) -> ImapBackend {
    let mut admin = env.gm.admin("alice", PW).await;
    admin.create("Archive").await.unwrap();
    for i in 1..=3 {
        admin
            .append(
                "INBOX",
                None,
                None,
                eml(
                    &format!("Mail {i}"),
                    "x@example.com",
                    &format!("o{i}@example.com"),
                    "",
                    "b",
                ),
            )
            .await
            .unwrap();
    }
    backend(
        env,
        vec![writable(alice(env, TlsMode::Implicit))],
        Limits::default(),
    )
}

async fn move_roundtrip(env: &Env, b: &ImapBackend) {
    let a = id("alice");
    let list = b.list_messages(&a, "INBOX", page(10)).await.unwrap();
    let target = list
        .items
        .iter()
        .find(|m| m.subject.0 == "Mail 2")
        .unwrap()
        .reference
        .clone();
    let keep = list
        .items
        .iter()
        .find(|m| m.subject.0 == "Mail 3")
        .unwrap()
        .reference
        .clone();
    let moved = b.move_message(&target, "Archive").await.unwrap();
    assert_eq!(moved.folder, "Archive");
    assert_eq!(moved.account, a);
    assert_eq!(
        b.get_message(&moved, 1000).await.unwrap().summary.subject.0,
        "Mail 2"
    );
    assert_eq!(
        b.get_message(&target, 1000).await.unwrap_err().code(),
        ErrorCode::MessageNotFound
    );
    // Only the target left INBOX; neighbours (even one flagged \Deleted by someone else) stay.
    let inbox = b.list_messages(&a, "INBOX", page(10)).await.unwrap();
    assert_eq!(inbox.items.len(), 2);
    assert!(inbox.items.iter().any(|m| m.reference == keep));
    assert_eq!(
        b.move_message(&keep, "NoSuchFolder")
            .await
            .unwrap_err()
            .code(),
        ErrorCode::FolderNotFound
    );
    assert!(
        b.get_message(&keep, 1000).await.is_ok(),
        "failed move must not lose the message"
    );
    assert_eq!(
        b.move_message(&keep, "INBOX").await.unwrap_err().code(),
        ErrorCode::InvalidInput
    );
    let _ = env;
}

#[tokio::test(flavor = "multi_thread")]
async fn flags_permissions_and_move() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let b = seed_three(&env).await;
    let a = id("alice");
    let list = b.list_messages(&a, "INBOX", page(10)).await.unwrap();
    let r = list.items[0].reference.clone();

    b.set_seen(&r, true).await.unwrap();
    b.set_flagged(&r, true).await.unwrap();
    let m = b.get_message(&r, 1000).await.unwrap();
    assert!(m.summary.flags.seen && m.summary.flags.flagged);
    b.set_seen(&r, false).await.unwrap();
    b.set_flagged(&r, false).await.unwrap();
    let m = b.get_message(&r, 1000).await.unwrap();
    assert!(!m.summary.flags.seen && !m.summary.flags.flagged);
    let ghost = MessageRef {
        uid: 9999,
        ..r.clone()
    };
    assert_eq!(
        b.set_seen(&ghost, true).await.unwrap_err().code(),
        ErrorCode::MessageNotFound
    );

    // Server-side MOVE path.
    move_roundtrip(&env, &b).await;

    // Read-only accounts cannot write, regardless of the caller.
    let ro = backend(
        &env,
        vec![alice(&env, TlsMode::Implicit)],
        Limits::default(),
    );
    assert_eq!(
        ro.set_seen(&r, true).await.unwrap_err().code(),
        ErrorCode::ReadOnlyAccount
    );
    assert_eq!(
        ro.move_message(&r, "Archive").await.unwrap_err().code(),
        ErrorCode::ReadOnlyAccount
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn move_falls_back_to_copy_and_uid_expunge_without_move_capability() {
    let Some(env) = env(Mode::Implicit, true).await else {
        return;
    };
    let b = seed_three(&env).await;
    let report = b.test_connection(&id("alice")).await.unwrap();
    assert!(
        !report.capabilities.iter().any(|c| c == "MOVE"),
        "proxy must hide MOVE: {:?}",
        report.capabilities
    );
    assert!(report.capabilities.iter().any(|c| c == "UIDPLUS"));
    // A bystander flagged \Deleted must survive: plain EXPUNGE would destroy it.
    let mut admin = env.gm.admin("alice", PW).await;
    admin.select("INBOX").await.unwrap();
    let _: Vec<_> =
        futures::TryStreamExt::try_collect(admin.store("3", "+FLAGS (\\Deleted)").await.unwrap())
            .await
            .unwrap();
    move_roundtrip(&env, &b).await;
    let mut admin = env.gm.admin("alice", PW).await;
    let mb = admin.select("INBOX").await.unwrap();
    assert_eq!(
        mb.exists, 2,
        "bystander flagged \\Deleted is still present (UID EXPUNGE only)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uidvalidity_change_makes_references_and_cursors_stale() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let mut admin = env.gm.admin("alice", PW).await;
    admin.create("Temp").await.unwrap();
    for i in 1..=3 {
        admin
            .append(
                "Temp",
                None,
                None,
                eml(
                    &format!("T{i}"),
                    "x@example.com",
                    &format!("t{i}@example.com"),
                    "",
                    "b",
                ),
            )
            .await
            .unwrap();
    }
    let b = backend(
        &env,
        vec![writable(alice(&env, TlsMode::Implicit))],
        Limits::default(),
    );
    let a = id("alice");
    let first = b.list_messages(&a, "Temp", page(2)).await.unwrap();
    let cursor = first.next_cursor.clone().unwrap();
    let r = first.items[0].reference.clone();
    assert!(b.get_message(&r, 100).await.is_ok());

    // Recreate the folder: a real server must issue a new UIDVALIDITY.
    admin.delete("Temp").await.unwrap();
    admin.create("Temp").await.unwrap();
    admin
        .append(
            "Temp",
            None,
            None,
            eml("New", "x@example.com", "new@example.com", "", "b"),
        )
        .await
        .unwrap();
    let status = b.folder_status(&a, "Temp").await.unwrap();
    assert_ne!(
        status.uid_validity, r.uid_validity,
        "greenmail should assign a new UIDVALIDITY on recreate"
    );
    assert_eq!(
        b.get_message(&r, 100).await.unwrap_err().code(),
        ErrorCode::StaleReference
    );
    assert_eq!(
        b.set_seen(&r, true).await.unwrap_err().code(),
        ErrorCode::StaleReference
    );
    let paged = b
        .list_messages(
            &a,
            "Temp",
            PageRequest {
                cursor: Some(cursor),
                limit: 2,
            },
        )
        .await;
    assert_eq!(paged.unwrap_err().code(), ErrorCode::StaleReference);

    // A reference forged with the wrong validity is stale even on an untouched folder.
    let inbox_ref = MessageRef {
        account: a.clone(),
        folder: "INBOX".into(),
        uid_validity: 1,
        uid: 1,
    };
    assert_eq!(
        b.get_message(&inbox_ref, 100).await.unwrap_err().code(),
        ErrorCode::StaleReference
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_after_server_side_disconnect() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let b = backend(
        &env,
        vec![alice(&env, TlsMode::Implicit)],
        Limits::default(),
    );
    let a = id("alice");
    b.list_folders(&a).await.unwrap();
    assert_eq!(env.proxy.stats.total.load(Ordering::SeqCst), 1);

    // Pooled session is killed behind the pool's back; the next call must transparently reconnect.
    env.proxy.kill_all();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let folders = b.list_folders(&a).await.unwrap();
    assert!(folders.iter().any(|f| f.name == "INBOX"));
    assert_eq!(
        env.proxy.stats.total.load(Ordering::SeqCst),
        2,
        "exactly one reconnect"
    );

    // Several kills in a row stay recoverable.
    for _ in 0..2 {
        env.proxy.kill_all();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(b.folder_status(&a, "INBOX").await.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_limits_are_enforced() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };

    // Per-account cap: 8 concurrent calls on a max_connections=1 account share one socket.
    let mut one = alice(&env, TlsMode::Implicit);
    one.max_connections = 1;
    let b = std::sync::Arc::new(backend(&env, vec![one], Limits::default()));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let b = b.clone();
            tokio::spawn(async move { b.folder_status(&id("alice"), "INBOX").await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(env.proxy.stats.peak.load(Ordering::SeqCst), 1);

    // 100 configured accounts, global cap 4: never more than 4 live sockets, every call succeeds.
    let env2 = self::env(Mode::Implicit, false).await.unwrap();
    let accounts: Vec<_> = (0..100)
        .map(|i| {
            account(
                &format!("acct-{i}"),
                "alice",
                "PW",
                env2.proxy.port,
                TlsMode::Implicit,
            )
        })
        .collect();
    let limits = Limits {
        max_global_connections: 4,
        ..Limits::default()
    };
    let b = std::sync::Arc::new(backend(&env2, accounts, limits));
    assert_eq!(
        env2.proxy.stats.total.load(Ordering::SeqCst),
        0,
        "lazy: nothing connects at construction"
    );
    let tasks: Vec<_> = (0..100)
        .map(|i| {
            let b = b.clone();
            tokio::spawn(async move { b.folder_status(&id(&format!("acct-{i}")), "INBOX").await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let peak = env2.proxy.stats.peak.load(Ordering::SeqCst);
    assert!(peak <= 4, "peak live sockets {peak} exceeded global cap 4");
    assert!(b.pool().open_sessions() <= 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_pool_times_out_with_limit_exceeded() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let mut cfg = alice(&env, TlsMode::Implicit);
    cfg.max_connections = 1;
    cfg.timeout_secs = 1;
    let b = std::sync::Arc::new(backend(&env, vec![cfg], Limits::default()));
    // Hold the only session (as a long-running operation would) so the next caller must wait.
    let held = b.pool().lease(&id("alice")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let err = b.folder_status(&id("alice"), "INBOX").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded);
    drop(held);
    assert!(b.folder_status(&id("alice"), "INBOX").await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn threading_exact_and_heuristic() {
    let Some(env) = env(Mode::Implicit, false).await else {
        return;
    };
    let mut admin = env.gm.admin("alice", PW).await;
    let mails = [
        eml("Launch plan", "a@example.com", "t1@example.com", "", "root"),
        eml(
            "Re: Launch plan",
            "b@example.com",
            "t2@example.com",
            "In-Reply-To: <t1@example.com>\r\nReferences: <t1@example.com>\r\n",
            "reply",
        ),
        eml(
            "Re: Re: Launch plan",
            "c@example.com",
            "t3@example.com",
            "In-Reply-To: <t2@example.com>\r\nReferences: <t1@example.com> <t2@example.com>\r\n",
            "reply2",
        ),
        eml("Unrelated", "d@example.com", "u1@example.com", "", "other"),
        // Same subject, no header link: heuristic only.
        eml(
            "Launch plan",
            "e@example.com",
            "h1@example.com",
            "",
            "lookalike",
        ),
    ];
    for m in mails {
        admin.append("INBOX", None, None, m).await.unwrap();
    }
    let b = backend(
        &env,
        vec![alice(&env, TlsMode::Implicit)],
        Limits::default(),
    );
    let a = id("alice");
    let all = b.list_messages(&a, "INBOX", page(20)).await.unwrap();
    let by_subject = |s: &str, from: &str| {
        all.items
            .iter()
            .find(|m| m.subject.0 == s && m.from[0].email == from)
            .unwrap()
            .reference
            .clone()
    };
    let middle = by_subject("Re: Launch plan", "b@example.com");

    let thread = b.thread(&middle).await.unwrap();
    let rel = |from: &str| {
        thread
            .iter()
            .find(|e| e.summary.from[0].email == from)
            .map(|e| e.relation)
    };
    assert_eq!(rel("a@example.com"), Some(ThreadRelation::Exact));
    assert_eq!(rel("b@example.com"), Some(ThreadRelation::Anchor));
    assert_eq!(rel("c@example.com"), Some(ThreadRelation::Exact));
    assert_eq!(rel("e@example.com"), Some(ThreadRelation::Heuristic));
    assert_eq!(rel("d@example.com"), None);
    let reply = thread
        .iter()
        .find(|e| e.summary.from[0].email == "c@example.com")
        .unwrap();
    assert_eq!(reply.parent_message_id.as_deref(), Some("t2@example.com"));

    // The trait method returns only header-proven members, oldest first by date then UID.
    let plain = b.get_thread(&middle).await.unwrap();
    let froms: Vec<_> = plain.iter().map(|m| m.from[0].email.as_str()).collect();
    assert_eq!(froms, ["a@example.com", "b@example.com", "c@example.com"]);
}
