//! What the engine lets an AI provider see, observed at a local HTTP double behind real IMAP
//! accounts: metadata only by default, only allowed accounts, nothing when AI is not configured
//! or the policy covers no account.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/greenmail.rs"]
mod harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness::*;
use openmail_briefs::ai::{AiPolicy, ContentField, HttpSummarizer};
use openmail_briefs::classify::Classifier;
use openmail_briefs::engine::{
    AiStage, BriefAccount, BriefEngine, EngineSettings, GenerateRequest,
};
use openmail_briefs::model::Provenance;
use openmail_briefs::store::BriefStore;
use openmail_core::config::{Limits, TlsMode};
use openmail_core::ids::AccountId;
use openmail_imap::ImapBackend;
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PW: &str = "secret";
const REPLY: &str = r#"{"choices":[{"message":{"content":"- two messages need a look"}}]}"#;

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// Local provider double: records every raw request, answers each with `REPLY`.
async fn provider() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    data.extend_from_slice(&tmp[..n]);
                    let text = String::from_utf8_lossy(&data).into_owned();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if data.len() >= h + 4 + len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&data).into_owned());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REPLY}",
                    REPLY.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    (url, seen)
}

struct Setup {
    _gm: Greenmail,
    _proxy: TlsProxy,
    _dir: tempfile::TempDir,
    backend: Arc<ImapBackend>,
    store: Arc<Mutex<BriefStore>>,
}

async fn setup() -> Option<Setup> {
    let gm = Greenmail::start(&[("alice", PW), ("bob", PW)])?;
    gm.deliver(
        "alice",
        "INBOX",
        &fresh_eml(
            "Invoice SECRETSUBJECT overdue",
            "billing@vendor.example",
            "alice@localhost",
            "a1@vendor.example",
            "TOPSECRETBODY",
        ),
    )
    .await;
    gm.deliver(
        "bob",
        "INBOX",
        &fresh_eml(
            "BOBPRIVATE pricing question",
            "lead@prospect.example",
            "bob@localhost",
            "b1@prospect.example",
            "BOBBODY",
        ),
    )
    .await;
    let proxy = TlsProxy::spawn(gm.port, Mode::Implicit, false).await;
    let backend = Arc::new(
        ImapBackend::with_extra_roots(
            vec![
                account("alice", "alice", "PW", proxy.port, TlsMode::Implicit),
                account("bob", "bob", "PW", proxy.port, TlsMode::Implicit),
            ],
            Limits::default(),
            secrets(&[("PW", PW)]),
            std::slice::from_ref(&proxy.cert),
        )
        .unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Mutex::new(
        BriefStore::open(&dir.path().join("briefs.db")).unwrap(),
    ));
    Some(Setup {
        _gm: gm,
        _proxy: proxy,
        _dir: dir,
        backend,
        store,
    })
}

fn policy(allowed: &[&str]) -> AiPolicy {
    AiPolicy {
        allowed_accounts: allowed.iter().map(|a| id(a)).collect(),
        allowed_hosts: vec!["127.0.0.1".into()],
        ..AiPolicy::default()
    }
}

fn engine(s: &Setup, ai: Option<(AiPolicy, &str)>) -> BriefEngine<ImapBackend> {
    let e = BriefEngine::new(
        Arc::clone(&s.backend),
        Arc::clone(&s.store),
        EngineSettings {
            per_account_timeout: Duration::from_secs(20),
            ..EngineSettings::default()
        },
        Classifier::heuristics_only(),
    );
    match ai {
        Some((policy, url)) => {
            let z = HttpSummarizer::new(policy.clone(), url, "m", SecretString::from("k")).unwrap();
            e.with_ai(AiStage::new(z, policy))
        }
        None => e,
    }
}

fn both() -> GenerateRequest {
    GenerateRequest {
        accounts: ["alice", "bob"]
            .iter()
            .map(|n| BriefAccount {
                id: id(n),
                email: format!("{n}@localhost"),
                sent_folder: None,
            })
            .collect(),
        lookback: Duration::from_secs(24 * 3600),
        include_processed: true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn default_policy_sends_metadata_of_allowed_accounts_only() {
    let Some(s) = setup().await else { return };
    let (url, seen) = provider().await;
    let brief = engine(&s, Some((policy(&["alice"]), &url)))
        .generate(&both())
        .await
        .unwrap();

    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "exactly one provider call");
    let wire = &requests[0];
    // Metadata the policy lists is there...
    assert!(wire.contains("billing@vendor.example"), "{wire}");
    // ...mail text and the other account's data are not, anywhere in the request.
    for secret in [
        "SECRETSUBJECT",
        "TOPSECRETBODY",
        "BOBPRIVATE",
        "BOBBODY",
        "lead@prospect.example",
        "bob@localhost",
    ] {
        assert!(
            !wire.contains(secret),
            "{secret} leaked to the provider: {wire}"
        );
    }
    assert!(wire.contains("untrusted_mail_data"));

    let ai = brief.ai_summary.expect("summary present");
    assert_eq!(ai.provenance, Provenance::Ai);
    assert_eq!(ai.messages, 1);
    assert!(ai.text.0.contains("need a look"));
    // The deterministic part of the brief is unaffected by the provider's answer.
    assert!(
        brief
            .actions
            .iter()
            .any(|a| a.item.title.0.contains("SECRETSUBJECT"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_policy_not_the_engine_decides_what_content_is_sent() {
    let Some(s) = setup().await else { return };
    let (url, seen) = provider().await;
    let mut p = policy(&["alice"]);
    // Owner opted in to subject and body; the endpoint is loopback, so data stays on this machine.
    p.allowed_fields
        .extend([ContentField::Subject, ContentField::Body]);
    engine(&s, Some((p, &url))).generate(&both()).await.unwrap();
    let wire = seen.lock().unwrap().join("");
    assert!(
        wire.contains("SECRETSUBJECT") && wire.contains("TOPSECRETBODY"),
        "{wire}"
    );
    assert!(
        !wire.contains("BOBPRIVATE") && !wire.contains("BOBBODY"),
        "{wire}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_ai_when_not_configured_or_when_the_policy_covers_no_covered_account() {
    let Some(s) = setup().await else { return };
    let (url, seen) = provider().await;

    let plain = engine(&s, None).generate(&both()).await.unwrap();
    assert!(plain.ai_summary.is_none());

    // Policy allows an account that is not part of this run: nothing may be sent.
    let none = engine(&s, Some((policy(&["carol"]), &url)))
        .generate(&both())
        .await
        .unwrap();
    assert!(none.ai_summary.is_none());
    assert!(
        none.notes.iter().any(|n| n.contains("ai summary skipped")),
        "{:?}",
        none.notes
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "provider was called anyway"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_provider_degrades_the_brief_it_does_not_fail_it() {
    let Some(s) = setup().await else { return };
    let dead = format!("http://127.0.0.1:{}/v1/chat/completions", dead_port());
    let brief = engine(&s, Some((policy(&["alice"]), &dead)))
        .generate(&both())
        .await
        .unwrap();
    assert!(brief.ai_summary.is_none());
    assert!(
        brief
            .notes
            .iter()
            .any(|n| n.contains("ai summary unavailable")),
        "{:?}",
        brief.notes
    );
    assert!(!brief.actions.is_empty());
}
