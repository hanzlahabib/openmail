//! `mail_mark_read_bulk` over the real MCP protocol: confirmation rules, dry run, caps,
//! account scoping and permissions.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/fake.rs"]
mod fake;

use std::sync::{Arc, Mutex};

use fake::{FakeBackend, UID_VALIDITY, config_full_access, msg_ref};
use openmail_core::ids::AccountId;
use openmail_mcp::{RateLimits, build_server_with};
use openmail_security::{Action, Principal};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

async fn connect(scopes: &[Action]) -> (Client, Arc<Mutex<Vec<String>>>) {
    let backend = FakeBackend::default();
    let writes = Arc::clone(&backend.writes);
    let p = Principal::new(
        "t",
        ["work", "personal"]
            .iter()
            .map(|a| AccountId::new(*a).unwrap()),
        scopes.iter().copied(),
    );
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = build_server_with(config_full_access(), backend, p, RateLimits::default());
    tokio::spawn(async move {
        if let Ok(r) = server.serve(server_io).await {
            let _ = r.waiting().await;
        }
    });
    (().serve(client_io).await.unwrap(), writes)
}

async fn call(c: &Client, args: Value) -> CallToolResult {
    let Value::Object(map) = args else { panic!() };
    c.call_tool(CallToolRequestParams::new("mail_mark_read_bulk".to_owned()).with_arguments(map))
        .await
        .unwrap()
}

fn code(r: &CallToolResult) -> String {
    r.structured_content.as_ref().unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn filters_need_confirmation_dry_run_changes_nothing_and_confirmed_marks_only_unread_matches()
{
    let (c, writes) = connect(&[Action::Read, Action::Organize]).await;
    // Fixture: uid1 read; uid2 "Invoice March" unread; uid3 injection subject unread.
    let no_confirm = call(&c, json!({"account": "work", "subject": "Invoice"})).await;
    assert_eq!(code(&no_confirm), "INVALID_INPUT");
    assert!(writes.lock().unwrap().is_empty());

    let dry = call(
        &c,
        json!({"account": "work", "subject": "Invoice", "dry_run": true}),
    )
    .await;
    let v = dry.structured_content.unwrap();
    assert_eq!(
        (
            v["dry_run"].clone(),
            v["matched"].clone(),
            v["marked_read"].clone()
        ),
        (json!(true), json!(1), json!(0))
    );
    assert!(writes.lock().unwrap().is_empty(), "dry run must not write");

    let done = call(
        &c,
        json!({"account": "work", "subject": "Invoice", "all_matching": true}),
    )
    .await;
    let v = done.structured_content.unwrap();
    assert_eq!(
        (
            v["matched"].clone(),
            v["marked_read"].clone(),
            v["failed"].clone(),
            v["truncated"].clone()
        ),
        (json!(1), json!(1), json!(0), json!(false))
    );
    assert_eq!(*writes.lock().unwrap(), ["seen:2:true"]);
}

#[tokio::test]
async fn explicit_refs_are_scoped_to_the_account_and_cannot_mix_with_filters() {
    let (c, writes) = connect(&[Action::Read, Action::Organize]).await;
    let mine = msg_ref("work", 2, UID_VALIDITY).encode();
    let other = msg_ref("personal", 1, UID_VALIDITY).encode();
    let ok = call(
        &c,
        json!({"account": "work", "message_refs": [mine.clone()]}),
    )
    .await;
    assert_eq!(ok.structured_content.unwrap()["marked_read"], 1);
    assert_eq!(*writes.lock().unwrap(), ["seen:2:true"]);
    let foreign = call(
        &c,
        json!({"account": "work", "message_refs": [mine.clone(), other]}),
    )
    .await;
    assert_eq!(code(&foreign), "INVALID_INPUT");
    let mixed = call(
        &c,
        json!({"account": "work", "message_refs": [mine], "subject": "x"}),
    )
    .await;
    assert_eq!(code(&mixed), "INVALID_INPUT");
    let nothing = call(&c, json!({"account": "work"})).await;
    assert_eq!(code(&nothing), "INVALID_INPUT");
    assert_eq!(
        writes.lock().unwrap().len(),
        1,
        "refused calls wrote nothing"
    );
}

#[tokio::test]
async fn needs_organize_permission_on_the_account_and_scope() {
    // Principal without the organize scope.
    let (c, writes) = connect(&[Action::Read]).await;
    let r = call(
        &c,
        json!({"account": "work", "subject": "Invoice", "all_matching": true}),
    )
    .await;
    assert_eq!(code(&r), "ACCESS_DENIED");
    // Account that is read-only in config (personal): denied even with the scope.
    let (c2, writes2) = connect(&[Action::Read, Action::Organize]).await;
    let r2 = call(
        &c2,
        json!({"account": "personal", "subject": "Invoice", "all_matching": true}),
    )
    .await;
    assert_eq!(code(&r2), "READ_ONLY_ACCOUNT");
    assert!(writes.lock().unwrap().is_empty() && writes2.lock().unwrap().is_empty());
}

async fn call_tool(c: &Client, name: &str, args: Value) -> CallToolResult {
    let Value::Object(map) = args else { panic!() };
    c.call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(map))
        .await
        .unwrap()
}

#[tokio::test]
async fn mark_all_read_needs_confirm_counts_first_and_marks_every_unread_message() {
    let (c, writes) = connect(&[Action::Read, Action::Organize]).await;
    let no = call_tool(&c, "mail_mark_all_read", json!({"account": "work"})).await;
    assert_eq!(code(&no), "INVALID_INPUT");
    let dry = call_tool(
        &c,
        "mail_mark_all_read",
        json!({"account": "work", "dry_run": true}),
    )
    .await;
    let v = dry.structured_content.unwrap();
    assert_eq!(
        (v["matched"].clone(), v["marked_read"].clone()),
        (json!(2), json!(0))
    );
    assert!(writes.lock().unwrap().is_empty());
    let done = call_tool(
        &c,
        "mail_mark_all_read",
        json!({"account": "work", "confirm": true}),
    )
    .await;
    let v = done.structured_content.unwrap();
    assert_eq!(
        (v["marked_read"].clone(), v["truncated"].clone()),
        (json!(2), json!(false))
    );
    let mut w = writes.lock().unwrap().clone();
    w.sort();
    assert_eq!(w, ["seen:2:true", "seen:3:true"]);
    let denied = call_tool(
        &c,
        "mail_mark_all_read",
        json!({"account": "personal", "confirm": true}),
    )
    .await;
    assert_eq!(code(&denied), "READ_ONLY_ACCOUNT");
}
