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
