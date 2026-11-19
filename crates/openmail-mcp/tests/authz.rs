//! Authorization is enforced on every tool call, before any backend call (security review F1),
//! and mailbox-sourced output is hardened (F3). Everything runs over the real MCP protocol.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/fake.rs"]
mod fake;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fake::{FakeBackend, UID_VALIDITY, config_full_access, msg_ref};
use openmail_core::ids::AccountId;
use openmail_core::model::Untrusted;
use openmail_mcp::{RateLimits, build_server_with};
use openmail_security::{Action, Principal, RateLimitConfig};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

fn principal(accounts: &[&str], scopes: &[Action]) -> Principal {
    Principal::new(
        "test",
        accounts.iter().map(|a| AccountId::new(*a).unwrap()),
        scopes.iter().copied(),
    )
}

async fn connect(
    backend: FakeBackend,
    principal: Principal,
    limits: RateLimits,
) -> (Client, Arc<AtomicUsize>) {
    let calls = Arc::clone(&backend.calls);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = build_server_with(config_full_access(), backend, principal, limits);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    (().serve(client_io).await.unwrap(), calls)
}

fn generous() -> RateLimits {
    RateLimits::default()
}

async fn call(c: &Client, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(map) = args else {
        panic!("args must be an object")
    };
    c.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(map))
        .await
        .unwrap()
}

fn error_of(r: &CallToolResult) -> (String, String) {
    assert_eq!(r.is_error, Some(true), "expected an error result: {r:?}");
    let v = r.structured_content.as_ref().expect("structured error");
    (
        v["error"]["code"].as_str().unwrap().to_owned(),
        v["error"]["message"].as_str().unwrap().to_owned(),
    )
}

/// Arguments that would succeed against `account` for every registered tool. A tool added
/// without an entry here panics, which forces its author to cover it in the deny-all test.
fn args_for(tool: &str, account: &str) -> Value {
    let r = msg_ref(account, 1, UID_VALIDITY).encode();
    match tool {
        "mail_list_accounts" => json!({}),
        "mail_test_connection" | "mail_list_folders" => json!({ "account": account }),
        "mail_get_folder_status" => json!({ "account": account, "folder": "INBOX" }),
        "mail_list_messages" => json!({ "account": account, "folder": "INBOX" }),
        "mail_search_messages" => json!({ "account": account, "subject": "Hello" }),
        "mail_get_message" | "mail_get_headers" | "mail_get_thread" | "mail_list_attachments" => {
            json!({ "message_ref": r })
        }
        "mail_get_attachment" => json!({ "message_ref": r, "index": 0 }),
        "mail_mark_read" | "mail_mark_unread" | "mail_archive_message" | "mail_delete_draft" => {
            json!({ "message_ref": r })
        }
        "mail_flag_message" => json!({ "message_ref": r, "flagged": true }),
        "mail_move_message" => json!({ "message_ref": r, "dest_folder": "Archive" }),
        "mail_create_draft" => json!({
            "account": account, "to": [{ "email": "bob@example.com" }], "subject": "Hi", "text": "x"
        }),
        "mail_update_draft" => json!({
            "message_ref": r, "to": [{ "email": "bob@example.com" }], "subject": "Hi", "text": "x"
        }),
        "mail_prepare_reply" => json!({ "message_ref": r, "text": "ok" }),
        "mail_send_approved" => json!({ "message_ref": r }),
        "mail_forward_approved" => {
            json!({ "message_ref": r, "to": [{ "email": "bob@example.com" }] })
        }
        "brief_generate" => json!({ "accounts": [account] }),
        "brief_get_latest"
        | "brief_get_status"
        | "brief_list_action_items"
        | "brief_get_followups" => json!({ "account": account }),
        other => panic!("tool {other} has no authorization test case; add it to args_for"),
    }
}

#[tokio::test]
async fn every_tool_denies_a_principal_without_access_and_never_reaches_the_backend() {
    let (c, calls) = connect(FakeBackend::default(), principal(&[], &[]), generous()).await;
    let tools = c.list_all_tools().await.unwrap();
    assert!(tools.len() >= 22, "write tools missing: {}", tools.len());
    for t in &tools {
        let r = call(&c, &t.name, args_for(&t.name, "work")).await;
        if t.name == "mail_list_accounts" {
            let v = r.structured_content.unwrap();
            assert_eq!(v["accounts"], json!([]), "listing must not name accounts");
        } else {
            assert_eq!(
                error_of(&r).0,
                "ACCESS_DENIED",
                "{} skipped authorize()",
                t.name
            );
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "backend reached without authorization"
    );
}

#[tokio::test]
async fn principal_for_account_a_cannot_read_account_b_and_unknown_looks_the_same() {
    let (c, calls) = connect(
        FakeBackend::default(),
        principal(&["work"], &[Action::Read]),
        generous(),
    )
    .await;
    let tools = c.list_all_tools().await.unwrap();
    for t in tools.iter().filter(|t| t.name != "mail_list_accounts") {
        let other = call(&c, &t.name, args_for(&t.name, "personal")).await;
        let ghost = call(&c, &t.name, args_for(&t.name, "ghost")).await;
        let (oc, om) = error_of(&other);
        let (gc, gm) = error_of(&ghost);
        assert_eq!(oc, "ACCESS_DENIED", "{}", t.name);
        assert_eq!(gc, "ACCESS_DENIED", "{}", t.name);
        // Existing-but-forbidden and non-existent accounts differ only by the echoed name.
        assert_eq!(
            om.replace("personal", "X"),
            gm.replace("ghost", "X"),
            "{}",
            t.name
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The permitted account still works, and listing shows only it.
    let ok = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_ne!(ok.is_error, Some(true));
    let accts = call(&c, "mail_list_accounts", json!({}))
        .await
        .structured_content
        .unwrap();
    let ids: Vec<_> = accts["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["work"]);
}

#[tokio::test]
async fn principal_without_read_scope_is_denied_even_for_its_own_account() {
    let (c, calls) = connect(
        FakeBackend::default(),
        principal(&["work"], &[Action::Send]),
        generous(),
    )
    .await;
    let r = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(error_of(&r).0, "ACCESS_DENIED");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rate_limit_trips_per_account_without_affecting_others() {
    let limits = RateLimits {
        global: RateLimitConfig {
            capacity: 100,
            refill_per_sec: 0,
        },
        per_account: RateLimitConfig {
            capacity: 2,
            refill_per_sec: 0,
        },
    };
    let (c, calls) = connect(
        FakeBackend::default(),
        principal(&["work", "personal"], &[Action::Read]),
        limits,
    )
    .await;
    for _ in 0..2 {
        let r = call(&c, "mail_list_folders", json!({"account": "work"})).await;
        assert_ne!(r.is_error, Some(true));
    }
    let r = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(error_of(&r).0, "RATE_LIMITED");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "limited call must not reach the backend"
    );
    let other = call(&c, "mail_list_folders", json!({"account": "personal"})).await;
    assert_ne!(other.is_error, Some(true));
}

#[tokio::test]
async fn invisible_and_bidi_characters_are_stripped_from_mailbox_text() {
    let mut backend = FakeBackend::default();
    backend.messages[0].subject = Untrusted("Pay\u{202E}\u{200B}ment\u{E0049}\u{FEFF} due".into());
    let (c, _) = connect(backend, principal(&["work"], &[Action::Read]), generous()).await;
    let v = call(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX"}),
    )
    .await
    .structured_content
    .unwrap();
    assert_eq!(v["messages"][0]["subject"], "Payment due");
}

#[tokio::test]
async fn html_links_are_rendered_as_inert_text() {
    let (c, _) = connect(
        FakeBackend::default(),
        principal(&["work"], &[Action::Read]),
        generous(),
    )
    .await;
    let r = msg_ref("work", 3, UID_VALIDITY).encode();
    let v = call(
        &c,
        "mail_get_message",
        json!({"message_ref": r, "fields": ["html"]}),
    )
    .await
    .structured_content
    .unwrap();
    let html = v["html_sanitized"].as_str().unwrap();
    assert_eq!(html, "<p>x</p>click [https://evil.example/?q=1]");
    assert!(!html.contains("<a"));
}

#[tokio::test]
async fn server_text_is_not_echoed_in_errors_or_connection_detail() {
    let (c, _) = connect(
        FakeBackend::default(),
        principal(&["work"], &[Action::Read]),
        generous(),
    )
    .await;
    let r = call(
        &c,
        "mail_get_folder_status",
        json!({"account": "work", "folder": "Nope"}),
    )
    .await;
    let (code, msg) = error_of(&r);
    assert_eq!(code, "FOLDER_NOT_FOUND");
    assert!(!msg.contains("IGNORE"), "backend text leaked: {msg}");

    let v = call(&c, "mail_test_connection", json!({"account": "work"}))
        .await
        .structured_content
        .unwrap();
    let detail = v["detail"].as_str().unwrap();
    assert!(!detail.contains("xxxx"), "backend detail leaked: {detail}");
    assert_eq!(v["imap_ok"], true);
}
