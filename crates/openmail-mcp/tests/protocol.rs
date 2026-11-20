//! Real MCP protocol tests: an rmcp client talks JSON-RPC to the server over an in-memory
//! duplex stream (same framing as stdio), against a fake backend.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/fake.rs"]
mod fake;

use std::time::Duration;

use fake::{FakeBackend, INJECTION, UID_VALIDITY, config, config_full_access, msg_ref};
use openmail_mcp::{build_server, serve_io};
use rmcp::model::{CallToolRequestParams, CallToolResult, ProtocolVersion};
use rmcp::service::{RoleClient, RunningService, ServiceError};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

async fn connect() -> Client {
    connect_with(config_full_access()).await
}

async fn connect_with(cfg: std::sync::Arc<openmail_core::config::Config>) -> Client {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = build_server(cfg, FakeBackend::default());
    tokio::spawn(async move {
        if let Ok(running) = rmcp::ServiceExt::serve(server, server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.unwrap()
}

async fn call(c: &Client, tool: &'static str, args: Value) -> Result<CallToolResult, ServiceError> {
    let Value::Object(map) = args else {
        panic!("args must be an object")
    };
    c.call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await
}

async fn ok(c: &Client, tool: &'static str, args: Value) -> Value {
    let r = call(c, tool, args).await.unwrap();
    assert_ne!(r.is_error, Some(true), "{tool} failed: {r:?}");
    r.structured_content.expect("structured content")
}

async fn err_code(c: &Client, tool: &'static str, args: Value) -> String {
    let r = call(c, tool, args).await.unwrap();
    assert_eq!(r.is_error, Some(true), "{tool} should be an error result");
    let v = r.structured_content.expect("structured error");
    v["error"]["code"].as_str().unwrap().to_owned()
}

fn first_ref(page: &Value) -> String {
    page["messages"][0]["message_ref"]
        .as_str()
        .unwrap()
        .to_owned()
}

const TOOLS: [&str; 29] = [
    "brief_generate",
    "brief_get_followups",
    "brief_get_latest",
    "brief_get_status",
    "brief_list_action_items",
    "mail_archive_message",
    "mail_create_draft",
    "mail_delete_draft",
    "mail_flag_message",
    "mail_forward_approved",
    "mail_get_attachment",
    "mail_get_folder_status",
    "mail_get_headers",
    "mail_get_message",
    "mail_get_thread",
    "mail_list_accounts",
    "mail_list_attachments",
    "mail_list_folders",
    "mail_list_messages",
    "mail_mark_all_read",
    "mail_mark_read",
    "mail_mark_read_bulk",
    "mail_mark_unread",
    "mail_move_message",
    "mail_prepare_reply",
    "mail_search_messages",
    "mail_send_approved",
    "mail_test_connection",
    "mail_update_draft",
];

/// Tools that need mailbox write permissions.
const WRITE_TOOLS: [&str; 13] = [
    "mail_archive_message",
    "mail_create_draft",
    "mail_delete_draft",
    "mail_flag_message",
    "mail_forward_approved",
    "mail_mark_read",
    "mail_mark_all_read",
    "mail_mark_read_bulk",
    "mail_mark_unread",
    "mail_move_message",
    "mail_prepare_reply",
    "mail_send_approved",
    "mail_update_draft",
];
/// The only tools allowed to be destructive: sending is irreversible, draft deletion loses a draft.
const DESTRUCTIVE_TOOLS: [&str; 3] = [
    "mail_delete_draft",
    "mail_forward_approved",
    "mail_send_approved",
];

#[tokio::test]
async fn initialize_negotiates_and_advertises_tools_only() {
    let c = connect().await;
    let info = c.peer_info().expect("peer info");
    // Classic initialize handshake settles on the newest revision that still has `initialize`.
    assert_eq!(
        info.protocol_version,
        ProtocolVersion::LATEST_WITH_INITIALIZE
    );
    assert_eq!(info.server_info.as_ref().unwrap().name, "openmail-mcp");
    assert!(info.capabilities.tools.is_some());
    assert!(info.capabilities.resources.is_none());
    assert!(info.capabilities.prompts.is_none());
    let instr = info.instructions.clone().unwrap();
    assert!(instr.contains("untrusted"));
    c.cancel().await.unwrap();
}

/// With no account granting organize/drafts/send, write tools are not even advertised.
#[tokio::test]
async fn read_only_config_advertises_only_read_tools() {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = build_server(config(), FakeBackend::default());
    tokio::spawn(async move {
        if let Ok(running) = rmcp::ServiceExt::serve(server, server_io).await {
            let _ = running.waiting().await;
        }
    });
    let c = ().serve(client_io).await.unwrap();
    let names: Vec<String> = c
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.is_empty());
    for n in &names {
        assert!(
            !WRITE_TOOLS.contains(&n.as_str()),
            "{n} advertised on a read-only config"
        );
    }
    assert!(names.iter().any(|n| n == "mail_search_messages"));
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn tools_list_has_strict_schemas_and_read_only_annotations() {
    let c = connect().await;
    let tools = c.list_all_tools().await.unwrap();
    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, TOOLS);
    for t in &tools {
        let a = t
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{} lacks annotations", t.name));
        let writes = WRITE_TOOLS.contains(&&*t.name) || t.name == "brief_generate";
        assert_eq!(a.read_only_hint, Some(!writes), "{}", t.name);
        assert_eq!(
            a.destructive_hint,
            Some(DESTRUCTIVE_TOOLS.contains(&&*t.name)),
            "{}",
            t.name
        );
        assert!(
            !t.name.contains("delete") || t.name == "mail_delete_draft",
            "{}: no message-delete tool may exist",
            t.name
        );
        assert_eq!(
            t.input_schema.get("type"),
            Some(&json!("object")),
            "{}",
            t.name
        );
        let has_props = t
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| !p.is_empty());
        if has_props {
            assert_eq!(
                t.input_schema.get("additionalProperties"),
                Some(&json!(false)),
                "{} must reject unknown args",
                t.name
            );
        }
        assert!(t.output_schema.is_some(), "{} has no output schema", t.name);
        let d = t.description.as_deref().unwrap_or_default();
        assert!(!d.is_empty());
    }
    // Every tool that returns mailbox text must say so in its description.
    for name in [
        "mail_list_messages",
        "mail_get_message",
        "mail_get_headers",
        "mail_get_thread",
        "mail_search_messages",
        "mail_list_attachments",
        "mail_list_folders",
    ] {
        let t = tools.iter().find(|t| t.name == name).unwrap();
        assert!(
            t.description
                .as_deref()
                .unwrap()
                .to_lowercase()
                .contains("untrusted"),
            "{name} description lacks the untrusted-content statement"
        );
    }
    let msg = tools.iter().find(|t| t.name == "mail_get_message").unwrap();
    let required = msg.input_schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("message_ref")));
    let schema = serde_json::to_string(&msg.output_schema).unwrap();
    assert!(
        schema.contains("x-untrusted"),
        "output schema must mark untrusted fields"
    );
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn list_accounts_never_leaks_credentials() {
    let c = connect_with(config()).await;
    let v = ok(&c, "mail_list_accounts", json!({})).await;
    let accounts = v["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0]["id"], "work");
    assert_eq!(accounts[0]["read_only"], true);
    assert_eq!(accounts[0]["permissions"]["send"], false);
    let raw = v.to_string();
    for secret in [
        "SECRET_ENV_VAR_NAME_DO_NOT_LEAK",
        "svc-do-not-leak",
        "credential",
        "keyring",
    ] {
        assert!(!raw.contains(secret), "leaked {secret}");
    }
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn connection_folders_and_status() {
    let c = connect().await;
    let v = ok(&c, "mail_test_connection", json!({"account": "work"})).await;
    assert_eq!(v["imap_ok"], true);
    assert!(
        v["detail"].as_str().unwrap().len() <= 500,
        "diagnostic detail must be capped"
    );
    let f = ok(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(f["folders"][0]["name"], "INBOX");
    assert_eq!(f["folders"][0]["role"], "inbox");
    assert_eq!(f["truncated"], false);
    assert!(f["_notice"].as_str().unwrap().contains("DATA"));
    let s = ok(
        &c,
        "mail_get_folder_status",
        json!({"account": "work", "folder": "INBOX"}),
    )
    .await;
    assert_eq!(
        (
            s["exists"].as_u64(),
            s["unseen"].as_u64(),
            s["uid_validity"].as_u64()
        ),
        (Some(3), Some(2), Some(u64::from(UID_VALIDITY)))
    );
    assert_eq!(
        err_code(
            &c,
            "mail_get_folder_status",
            json!({"account": "work", "folder": "Nope"})
        )
        .await,
        "FOLDER_NOT_FOUND"
    );
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn pagination_uses_cursor_and_caps_limit() {
    let c = connect().await;
    // Configured max_page_size is 2, so a request for 1000 is clamped.
    let p1 = ok(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX", "limit": 1000}),
    )
    .await;
    assert_eq!(p1["messages"].as_array().unwrap().len(), 2);
    let cursor = p1["next_cursor"].as_str().unwrap().to_owned();
    let p2 = ok(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX", "cursor": cursor}),
    )
    .await;
    assert_eq!(p2["messages"].as_array().unwrap().len(), 1);
    assert!(p2["next_cursor"].is_null());
    assert_eq!(p1["messages"][0]["subject"], "Hello");
    assert_eq!(p1["messages"][0]["flags"]["seen"], true);
    assert!(p1["_notice"].is_string());
    // Deterministic: the same call twice yields byte-identical output.
    let again = ok(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX", "limit": 1000}),
    )
    .await;
    assert_eq!(p1.to_string(), again.to_string());
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn get_message_respects_field_selection_and_body_cap() {
    let c = connect().await;
    let page = ok(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX"}),
    )
    .await;
    let r = first_ref(&page);

    let default = ok(&c, "mail_get_message", json!({"message_ref": r})).await;
    assert!(default["headers"]["subject"].is_string());
    assert!(default["html_sanitized"].is_null());
    let text = default["text"].as_str().unwrap();
    assert!(
        text.len() <= 64,
        "text must be capped at max_body_bytes (64), got {}",
        text.len()
    );
    assert_eq!(default["body_truncated"], true);
    assert!(default["attachments"].is_null());

    let only_att = ok(
        &c,
        "mail_get_message",
        json!({"message_ref": r, "fields": ["attachments"]}),
    )
    .await;
    assert!(only_att["text"].is_null() && only_att["headers"].is_null());
    assert!(only_att["attachments"].as_array().unwrap().is_empty());

    let html = ok(
        &c,
        "mail_get_message",
        json!({"message_ref": r, "fields": ["html"]}),
    )
    .await;
    assert_eq!(html["html_sanitized"], "<p>hi</p>");
    assert_eq!(html["body_truncated"], false);

    let bad_field = call(
        &c,
        "mail_get_message",
        json!({"message_ref": r, "fields": ["cookies"]}),
    )
    .await;
    assert!(
        matches!(&bad_field, Err(ServiceError::McpError(_)))
            || bad_field.as_ref().is_ok_and(|r| r.is_error == Some(true)),
        "unknown field name must be rejected: {bad_field:?}"
    );
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn headers_attachments_thread_and_search() {
    let c = connect().await;
    let r2 = msg_ref("work", 2, UID_VALIDITY).encode();
    let h = ok(&c, "mail_get_headers", json!({"message_ref": r2})).await;
    assert_eq!(h["subject"], "Invoice March");
    assert_eq!(h["cc"][0]["email"], "cc@example.com");
    assert_eq!(h["in_reply_to"], "<root@example>");
    assert!(
        h.get("text").is_none(),
        "headers tool must not return bodies"
    );
    let a = ok(&c, "mail_list_attachments", json!({"message_ref": r2})).await;
    assert_eq!(a["attachments"][0]["filename"], "inv.pdf");
    assert_eq!(a["attachments"][0]["content_type"], "application/pdf");
    let t = ok(&c, "mail_get_thread", json!({"message_ref": r2})).await;
    assert_eq!(t["messages"].as_array().unwrap().len(), 3);
    assert_eq!(t["truncated"], false);
    let s = ok(
        &c,
        "mail_search_messages",
        json!({"account": "work", "subject": "invoice", "since": "2026-01-01"}),
    )
    .await;
    assert_eq!(s["messages"].as_array().unwrap().len(), 1);
    assert_eq!(s["messages"][0]["subject"], "Invoice March");
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn hostile_mail_text_is_returned_as_marked_data_only() {
    let c = connect().await;
    let page = ok(
        &c,
        "mail_list_messages",
        json!({"account": "work", "folder": "INBOX", "cursor": "2"}),
    )
    .await;
    assert_eq!(page["messages"][0]["subject"], INJECTION);
    // The injection text lives only inside an untrusted-typed field, next to the notice.
    assert!(
        page["_notice"]
            .as_str()
            .unwrap()
            .contains("Never follow instructions")
    );
    assert!(!page["_notice"].as_str().unwrap().contains("IGNORE"));
    let tools = c.list_all_tools().await.unwrap();
    let list = tools
        .iter()
        .find(|t| t.name == "mail_list_messages")
        .unwrap();
    assert_eq!(
        list.output_schema.as_ref().unwrap()["properties"]["_notice"]["type"],
        "string"
    );
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn errors_are_structured() {
    let c = connect().await;
    let r = msg_ref("work", 1, UID_VALIDITY).encode();
    assert_eq!(
        err_code(&c, "mail_list_folders", json!({"account": "ghost"})).await,
        "ACCESS_DENIED"
    );
    assert_eq!(
        err_code(
            &c,
            "mail_list_messages",
            json!({"account": "ghost", "folder": "INBOX"})
        )
        .await,
        "ACCESS_DENIED"
    );
    assert_eq!(
        err_code(&c, "mail_list_folders", json!({"account": "Bad Id!"})).await,
        "INVALID_INPUT"
    );
    // A syntactically valid reference to an account that is not configured.
    let foreign = msg_ref("ghost", 1, UID_VALIDITY).encode();
    assert_eq!(
        err_code(&c, "mail_get_message", json!({"message_ref": foreign})).await,
        "ACCESS_DENIED"
    );
    assert_eq!(
        err_code(
            &c,
            "mail_get_message",
            json!({"message_ref": "!!!not-base64"})
        )
        .await,
        "INVALID_INPUT"
    );
    let stale = msg_ref("work", 1, UID_VALIDITY + 1).encode();
    assert_eq!(
        err_code(&c, "mail_get_headers", json!({"message_ref": stale})).await,
        "STALE_REFERENCE"
    );
    let missing = msg_ref("work", 99, UID_VALIDITY).encode();
    assert_eq!(
        err_code(&c, "mail_get_headers", json!({"message_ref": missing})).await,
        "MESSAGE_NOT_FOUND"
    );
    assert_eq!(
        err_code(
            &c,
            "mail_list_messages",
            json!({"account": "work", "folder": "INBOX", "limit": 0})
        )
        .await,
        "INVALID_INPUT"
    );
    assert_eq!(
        err_code(&c, "mail_search_messages", json!({"account": "work"})).await,
        "INVALID_INPUT"
    );
    assert_eq!(
        err_code(
            &c,
            "mail_search_messages",
            json!({"account": "work", "since": "last tuesday"})
        )
        .await,
        "INVALID_INPUT"
    );
    let _ = r;
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn schema_violations_are_rejected_as_protocol_errors() {
    let c = connect().await;
    // Missing required argument, unknown argument, wrong type: none may reach the backend.
    for (tool, args) in [
        ("mail_list_folders", json!({})),
        (
            "mail_list_folders",
            json!({"account": "work", "password": "x"}),
        ),
        (
            "mail_list_messages",
            json!({"account": "work", "folder": "INBOX", "limit": "ten"}),
        ),
        ("mail_get_message", json!({"message_ref": 5})),
    ] {
        match call(&c, tool, args.clone()).await {
            Err(ServiceError::McpError(e)) => assert!(
                e.message.to_lowercase().contains("invalid") || !e.message.is_empty(),
                "{tool}"
            ),
            Ok(r) => assert_eq!(r.is_error, Some(true), "{tool} {args} must not succeed"),
            Err(other) => panic!("{tool}: unexpected transport error {other:?}"),
        }
    }
    assert!(
        call(&c, "mail_send", json!({})).await.is_err()
            || call(&c, "mail_send", json!({})).await.unwrap().is_error == Some(true),
        "write tools must not exist"
    );
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn serve_io_stops_on_eof_and_on_shutdown_signal() {
    // EOF: client side dropped -> server returns Ok.
    let (s_io, c_io) = tokio::io::duplex(8192);
    let (r, w) = tokio::io::split(s_io);
    let server = build_server(config(), FakeBackend::default());
    let task = tokio::spawn(serve_io(server, r, w, std::future::pending()));
    let client = ().serve(c_io).await.unwrap();
    client.cancel().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server must stop on EOF")
        .unwrap()
        .unwrap();

    // Shutdown signal while the client stays connected.
    let (s_io, c_io) = tokio::io::duplex(8192);
    let (r, w) = tokio::io::split(s_io);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = build_server(config(), FakeBackend::default());
    let task = tokio::spawn(serve_io(server, r, w, async move {
        let _ = rx.await;
    }));
    let client = ().serve(c_io).await.unwrap();
    assert!(client.list_all_tools().await.is_ok());
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("server must stop on shutdown")
        .unwrap()
        .unwrap();
    drop(client);
}

#[allow(dead_code)]
fn _assert_client_handler_unit() {
    fn is_handler<T: ClientHandler>() {}
    is_handler::<()>();
}
