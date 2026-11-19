//! Metrics move on real MCP flows: tool latency, denied calls, rate limiting, and nothing but
//! account ids / tool names / error codes ever becomes a label.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/fake.rs"]
mod fake;

use std::sync::Arc;

use fake::{FakeBackend, config_full_access};
use openmail_core::ids::AccountId;
use openmail_mcp::{RateLimits, build_server_with};
use openmail_observe::metrics::{Counter, Histogram, Labels, Metrics};
use openmail_observe::observer::Observer;
use openmail_security::{Action, Principal, RateLimitConfig};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

async fn connect(scopes: &[Action], limits: RateLimits) -> (Client, Arc<Metrics>) {
    let metrics = Arc::new(Metrics::new());
    let principal = Principal::new(
        "test",
        [AccountId::new("work").unwrap()],
        scopes.iter().copied(),
    );
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = build_server_with(
        config_full_access(),
        FakeBackend::default(),
        principal,
        limits,
    )
    .with_observer(Observer::recording(Arc::clone(&metrics)));
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    (().serve(client_io).await.unwrap(), metrics)
}

async fn call(c: &Client, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(map) = args else {
        panic!("args must be an object")
    };
    c.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(map))
        .await
        .unwrap()
}

#[tokio::test]
async fn successful_calls_record_per_tool_latency_and_search_latency() {
    let (c, m) = connect(&[Action::Read], RateLimits::default()).await;
    let r = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_ne!(r.is_error, Some(true));
    let r = call(
        &c,
        "mail_search_messages",
        json!({"account": "work", "subject": "Hello"}),
    )
    .await;
    assert_ne!(r.is_error, Some(true));

    let folders = Labels::none().tool("mail_list_folders").account("work");
    let search = Labels::none().tool("mail_search_messages").account("work");
    assert_eq!(m.histogram_count_with(Histogram::ToolLatency, &folders), 1);
    assert_eq!(m.histogram_count_with(Histogram::ToolLatency, &search), 1);
    assert_eq!(m.histogram_count_with(Histogram::SearchLatency, &search), 1);
    assert_eq!(
        m.histogram_count_with(Histogram::SearchLatency, &folders),
        0
    );
    assert_eq!(m.counter(Counter::McpRequestFailures), 0);
    let text = m.render_prometheus();
    assert!(text.contains(
        "openmail_tool_latency_seconds_count{account=\"work\",tool=\"mail_list_folders\"} 1"
    ));
}

#[tokio::test]
async fn denied_call_counts_a_failure_by_code() {
    let (c, m) = connect(&[Action::Send], RateLimits::default()).await;
    let r = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(r.is_error, Some(true));
    let denied = Labels::none()
        .tool("mail_list_folders")
        .account("work")
        .code("ACCESS_DENIED");
    assert_eq!(m.counter_with(Counter::McpRequestFailures, &denied), 1);
    assert_eq!(m.counter(Counter::RateLimitRejections), 0);
}

#[tokio::test]
async fn rate_limited_call_counts_rejection_and_failure() {
    let limits = RateLimits {
        global: RateLimitConfig {
            capacity: 100,
            refill_per_sec: 0,
        },
        per_account: RateLimitConfig {
            capacity: 1,
            refill_per_sec: 0,
        },
    };
    let (c, m) = connect(&[Action::Read], limits).await;
    let ok = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_ne!(ok.is_error, Some(true));
    let limited = call(&c, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(limited.is_error, Some(true));
    assert_eq!(
        m.counter_with(
            Counter::RateLimitRejections,
            &Labels::none().account("work")
        ),
        1
    );
    let by_code = Labels::none()
        .tool("mail_list_folders")
        .account("work")
        .code("RATE_LIMITED");
    assert_eq!(m.counter_with(Counter::McpRequestFailures, &by_code), 1);
}

#[tokio::test]
async fn unknown_tools_and_hostile_arguments_cannot_mint_labels() {
    let (c, m) = connect(&[Action::Read], RateLimits::default()).await;
    // Not a registered tool: rejected at the protocol level, must not become a `tool` label.
    let _ = c
        .call_tool(CallToolRequestParams::new(
            "evil@example.invalid".to_owned(),
        ))
        .await;
    // An address in the account argument is not a valid account id and so never a label.
    let _ = call(
        &c,
        "mail_list_folders",
        json!({"account": "jane.doe@example.invalid"}),
    )
    .await;
    let text = m.render_prometheus();
    assert!(!text.contains("evil"), "{text}");
    assert!(!text.contains("jane"), "{text}");
    assert!(!text.contains("example.invalid"), "{text}");
}

/// Collects formatted log output in memory.
#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// Runs a `mail_get_message` call under `directives` and returns everything that was logged.
async fn logs_for_get_message(directives: &str) -> String {
    let buf = LogBuf::default();
    let filter = openmail_observe::tracing_init::build_filter(Some(directives)).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let (c, _m) = connect(&[Action::Read], RateLimits::default()).await;
    let r = call(
        &c,
        "mail_get_message",
        json!({ "message_ref": fake::msg_ref("work", 3, fake::UID_VALIDITY).encode() }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

// The fake backend's body is 100 x "é"; a run of eight is a body leak, never log boilerplate.
const BODY_FRAGMENT: &str = "éééééééé";

#[tokio::test(flavor = "current_thread")]
async fn debug_logging_never_prints_mail_bodies() {
    let capped = logs_for_get_message("debug").await;
    assert!(!capped.contains(BODY_FRAGMENT), "body leaked:\n{capped}");
    // Control: without the cap rmcp does log the body, so the assertion above is not vacuous.
    let open = logs_for_get_message("debug,rmcp=debug").await;
    assert!(
        open.contains(BODY_FRAGMENT),
        "control failed, rmcp no longer logs bodies at debug; re-check the cap:\n{open}"
    );
}
