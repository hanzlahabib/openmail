//! `brief_*` tools over the real MCP protocol: authorization, per-principal filtering of stored
//! briefs, pagination and caps, processed-mail tracking, and mail text staying data.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/fake.rs"]
mod fake;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fake::{FakeBackend, config};
use openmail_briefs::classify::Classifier;
use openmail_briefs::engine::{BriefEngine, EngineSettings, SharedStore};
use openmail_briefs::model::{
    AccountRunStatus, ActionItem, AiSummary, Brief, BriefItem, Evidence, FollowUp, Provenance,
};
use openmail_briefs::store::BriefStore;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::Untrusted;
use openmail_mcp::{OpenMailServer, RateLimits, build_server_with};
use openmail_security::{Action, Principal};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

type Client = RunningService<RoleClient, ()>;

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn principal(accounts: &[&str]) -> Principal {
    Principal::new("t", accounts.iter().map(|a| id(a)), [Action::Read])
}

fn now_minus_hours(h: i64) -> String {
    (OffsetDateTime::now_utc() - time::Duration::hours(h))
        .format(&Rfc3339)
        .unwrap()
}

/// Recent mail so the default 24h window contains it.
fn recent_backend() -> FakeBackend {
    let mut b = FakeBackend::default();
    for (i, m) in b.messages.iter_mut().enumerate() {
        m.date = Some(now_minus_hours(i64::try_from(i).unwrap() + 1));
    }
    b.messages[1].subject = Untrusted("Invoice March is overdue".into());
    b
}

fn store() -> (SharedStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let s = BriefStore::open(&dir.path().join("briefs.db")).unwrap();
    (Arc::new(Mutex::new(s)), dir)
}

fn engine(backend: Arc<FakeBackend>, store: SharedStore) -> Arc<BriefEngine<FakeBackend>> {
    Arc::new(BriefEngine::new(
        backend,
        store,
        EngineSettings::default(),
        Classifier::heuristics_only(),
    ))
}

async fn connect(server: OpenMailServer<FakeBackend>) -> Client {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.unwrap()
}

async fn call(c: &Client, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(map) = args else {
        panic!("args must be an object")
    };
    c.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(map))
        .await
        .unwrap()
}

fn ok(r: &CallToolResult) -> &Value {
    assert_ne!(r.is_error, Some(true), "unexpected error: {r:?}");
    r.structured_content.as_ref().unwrap()
}

fn error_code(r: &CallToolResult) -> String {
    assert_eq!(r.is_error, Some(true), "expected an error: {r:?}");
    r.structured_content.as_ref().unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Server plus engine sharing one backend instance, as `serve` wires them.
fn wired(who: &[&str], store: SharedStore) -> OpenMailServer<FakeBackend> {
    let server = build_server_with(
        config(),
        recent_backend(),
        principal(who),
        RateLimits::default(),
    );
    let eng = engine(server.backend(), store);
    server.with_briefs(eng)
}

async fn live(who: &[&str]) -> (Client, tempfile::TempDir) {
    let (store, dir) = store();
    (connect(wired(who, store)).await, dir)
}

fn item(account: &str, uid: u32, title: &str, reason: &str) -> BriefItem {
    BriefItem {
        source: MessageRef {
            account: id(account),
            folder: "INBOX".into(),
            uid_validity: 7,
            uid,
        },
        title: Untrusted(title.into()),
        evidence: vec![Evidence {
            reason: reason.into(),
            excerpt: None,
        }],
        provenance: Provenance::Heuristic,
    }
}

fn seeded_brief(n_actions: u32) -> Brief {
    Brief {
        generated_at: "2026-11-19T08:00:00Z".into(),
        window_start: "2026-11-18T08:00:00Z".into(),
        window_end: "2026-11-19T08:00:00Z".into(),
        accounts: BTreeMap::from([
            (id("work"), AccountRunStatus::Ok),
            (
                id("personal"),
                AccountRunStatus::Failed {
                    reason: "ConnectionFailed".into(),
                },
            ),
        ]),
        highlights: vec![item(
            "personal",
            1,
            "Secret personal lead",
            "looks like new_lead",
        )],
        actions: (1..=n_actions)
            .map(|i| ActionItem {
                item: item(
                    if i % 2 == 0 { "personal" } else { "work" },
                    i,
                    &format!("Invoice {i}"),
                    "looks like payment_related",
                ),
                due: None,
            })
            .collect(),
        follow_ups: vec![FollowUp {
            item: item("work", 99, "Proposal", "no reply after 4 day(s)"),
            waiting_since: "2026-11-15T08:00:00Z".into(),
        }],
        ai_summary: Some(AiSummary {
            text: Untrusted("Both mailboxes are busy".into()),
            provenance: Provenance::Ai,
            messages: 4,
        }),
        notes: vec![
            "personal: no Sent folder found, follow-ups were not checked".into(),
            "work: no Sent folder found, follow-ups were not checked".into(),
        ],
    }
}

async fn seeded(who: &[&str], n_actions: u32) -> (Client, tempfile::TempDir) {
    let (store, dir) = store();
    store
        .lock()
        .unwrap()
        .save_brief(&seeded_brief(n_actions))
        .unwrap();
    (connect(wired(who, store)).await, dir)
}

#[tokio::test]
async fn generate_returns_sourced_labelled_items_and_does_not_repeat_processed_mail() {
    let (c, _d) = live(&["work"]).await;
    let first = call(&c, "brief_generate", json!({"accounts": ["work"]})).await;
    let v = ok(&first);
    assert!(
        v["disclaimer"]
            .as_str()
            .unwrap()
            .contains("not authoritative")
    );
    assert_eq!(v["accounts"][0]["status"], "ok");
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 1, "{v}");
    let a = &actions[0];
    assert_eq!(a["title"], "Invoice March is overdue");
    assert_eq!(a["provenance"], "heuristic");
    // The ref resolves back to the message through the ordinary read tool.
    let got = call(
        &c,
        "mail_get_message",
        json!({"message_ref": a["message_ref"]}),
    )
    .await;
    assert_eq!(ok(&got)["headers"]["subject"], "Invoice March is overdue");

    let again = call(&c, "brief_generate", json!({"accounts": ["work"]})).await;
    assert!(
        ok(&again)["actions"].as_array().unwrap().is_empty(),
        "processed mail re-reported"
    );
    let all = call(
        &c,
        "brief_generate",
        json!({"accounts": ["work"], "include_processed": true}),
    )
    .await;
    assert_eq!(ok(&all)["actions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn injection_in_a_subject_is_data_it_creates_no_item_and_changes_nothing() {
    let (c, _d) = live(&["work"]).await;
    let v = call(&c, "brief_generate", json!({"accounts": ["work"]})).await;
    let v = ok(&v);
    let all: Vec<&Value> = ["actions", "highlights", "follow_ups"]
        .iter()
        .flat_map(|k| v[k].as_array().unwrap())
        .collect();
    assert!(
        all.iter()
            .all(|i| !i["title"].as_str().unwrap().contains("IGNORE")),
        "an unclassified injection subject must not surface: {v}"
    );
    assert!(v["_notice"].as_str().unwrap().contains("DATA"));
}

#[tokio::test]
async fn stored_brief_is_filtered_to_the_callers_accounts() {
    let (c, _d) = seeded(&["work"], 4).await;
    let v = call(&c, "brief_get_latest", json!({})).await;
    let b = &ok(&v)["brief"];
    let accounts: Vec<&str> = b["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["account"].as_str().unwrap())
        .collect();
    assert_eq!(accounts, ["work"], "other account's name leaked");
    let text = b.to_string();
    assert!(
        !text.contains("personal") && !text.contains("Secret personal lead"),
        "{text}"
    );
    assert!(
        b["ai_summary"].is_null(),
        "model text spans a hidden account"
    );
    assert_eq!(b["notes"].as_array().unwrap().len(), 1);
    assert_eq!(b["actions"].as_array().unwrap().len(), 2);
    assert_eq!(b["follow_ups"][0]["waiting_since"], "2026-11-15T08:00:00Z");

    // A caller who may read both sees the model overview, labelled as such.
    let (c2, _d2) = seeded(&["work", "personal"], 4).await;
    let v2 = call(&c2, "brief_get_latest", json!({})).await;
    let b2 = &ok(&v2)["brief"];
    assert_eq!(b2["ai_summary"]["provenance"], "ai");
    assert_eq!(b2["accounts"].as_array().unwrap().len(), 2);
    // BTreeMap order: personal (failed) precedes work.
    assert_eq!(b2["accounts"][0]["status"], "failed");
}

#[tokio::test]
async fn principal_without_access_is_denied_and_unknown_looks_the_same() {
    let (c, _d) = seeded(&["work"], 2).await;
    for tool in [
        "brief_get_latest",
        "brief_get_status",
        "brief_list_action_items",
        "brief_get_followups",
    ] {
        let other = call(&c, tool, json!({"account": "personal"})).await;
        let ghost = call(&c, tool, json!({"account": "ghost"})).await;
        assert_eq!(error_code(&other), "ACCESS_DENIED", "{tool}");
        assert_eq!(error_code(&ghost), "ACCESS_DENIED", "{tool}");
    }
    let gen_denied = call(&c, "brief_generate", json!({"accounts": ["personal"]})).await;
    assert_eq!(error_code(&gen_denied), "ACCESS_DENIED");

    let (none, _d2) = seeded(&[], 2).await;
    for tool in [
        "brief_get_latest",
        "brief_get_status",
        "brief_list_action_items",
        "brief_get_followups",
    ] {
        let r = call(&none, tool, json!({})).await;
        assert_eq!(error_code(&r), "ACCESS_DENIED", "{tool}");
    }
}

#[tokio::test]
async fn lists_are_paginated_by_cursor_and_the_brief_is_size_capped() {
    // 120 actions: work owns the odd ones (60); page size is capped at 2 by the fixture config.
    let (c, _d) = seeded(&["work"], 120).await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"limit": 50});
        if let Some(cur) = &cursor {
            args["cursor"] = json!(cur);
        }
        let r = call(&c, "brief_list_action_items", args).await;
        let v = ok(&r);
        let items = v["items"].as_array().unwrap();
        assert!(
            items.len() <= 2,
            "server page cap not applied: {}",
            items.len()
        );
        seen.extend(
            items
                .iter()
                .map(|i| i["title"].as_str().unwrap().to_owned()),
        );
        match v["next_cursor"].as_str() {
            Some(n) => cursor = Some(n.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 60);
    let unique: std::collections::BTreeSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 60, "pages overlapped");

    let latest = call(&c, "brief_get_latest", json!({})).await;
    let b = &ok(&latest)["brief"];
    assert_eq!(b["actions"].as_array().unwrap().len(), 50);
    assert_eq!(b["truncated"], true);

    let bad = call(&c, "brief_list_action_items", json!({"cursor": "abc"})).await;
    assert_eq!(error_code(&bad), "INVALID_INPUT");
}

#[tokio::test]
async fn status_reports_runs_and_ai_flag_and_unsupported_without_an_engine() {
    let (c, _d) = live(&["work"]).await;
    let before = call(&c, "brief_get_status", json!({})).await;
    assert_eq!(ok(&before)["accounts"][0]["last_run_status"], Value::Null);
    call(&c, "brief_generate", json!({"accounts": ["work"]})).await;
    let after = call(&c, "brief_get_status", json!({})).await;
    let v = ok(&after);
    assert_eq!(v["accounts"][0]["last_run_status"], "ok");
    assert_eq!(v["ai_enabled"], false);
    assert!(v["latest_generated_at"].is_string());

    // A server built without an engine still authorizes first, then says briefs are off.
    let server = build_server_with(
        config(),
        FakeBackend::default(),
        principal(&["work"]),
        RateLimits::default(),
    );
    let c2 = connect(server).await;
    let r = call(&c2, "brief_get_latest", json!({"account": "work"})).await;
    assert_eq!(error_code(&r), "UNSUPPORTED");
}

#[tokio::test]
async fn tool_descriptions_say_briefs_are_heuristic() {
    let (c, _d) = live(&["work"]).await;
    let tools = c.list_all_tools().await.unwrap();
    let names: Vec<_> = tools
        .iter()
        .filter(|t| t.name.starts_with("brief_"))
        .collect();
    assert_eq!(names.len(), 5);
    for t in names {
        let d = t.description.as_deref().unwrap_or_default().to_lowercase();
        assert!(
            d.contains("heuristic") || d.contains("status"),
            "{} lacks the caveat",
            t.name
        );
    }
}
