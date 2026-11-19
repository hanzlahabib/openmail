//! End-to-end: the real `OpenMailServer` behind the real edge (auth, Origin, limits, rate limit,
//! session binding) over real TLS on loopback, driven by a real rmcp client and plain reqwest.
//! Tokens are genuine ES256 JWTs verified against a JWKS; the TLS CA is generated per run.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openmail_core::backend::{
    AttachmentSource, MailBackend, MailDrafts, MailOrganizer, SentFolder,
};
use openmail_core::config::Config;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::*;
use openmail_core::{Error, ErrorCode, Result as CoreResult};
use openmail_mcp::{RateLimits, build_server_with_resolver};
use openmail_remote::auth::{
    AuthError, AuthState, Authenticator, JwksFetcher, JwtConfig, JwtValidator,
    ProtectedResourceMetadata,
};
use openmail_remote::http::{HttpConfig, Readiness, router, serve_listener};
use openmail_remote::mcp::{HttpPrincipalResolver, StreamableHttpServerConfig, mcp_router};
use openmail_remote::tls::{TlsListener, server_config};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use url::Url;

const ISS: &str = "https://idp.example.com";
const AUD: &str = "https://mail.example.com/mcp";
const METADATA_URL: &str = "https://mail.example.com/.well-known/oauth-protected-resource";

// Throwaway P-256 key generated for tests only.
const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf52HVVQ19hOO/IIl\nfD4b+/WhbWyZnJF/ScNrXpRhlsKhRANCAATYyz/BuaM9rL1RFvj1YmMSL4RdHVgw\nvnBnlFzits3IMBQHxIQ6VFFgOTY6UOuVSmF7Hws+qDEV+KGFLJWbWPgv\n-----END PRIVATE KEY-----\n";
const KEY_X: &str = "2Ms_wbmjPay9URb49WJjEi-EXR1YML5wZ5Rc4rbNyDA";
const KEY_Y: &str = "FAfEhDpUUWA5NjpQ65VKYXsfCz6oMRX4oYUslZtY-C8";

const CONFIG: &str = r#"
version = 1
[[account]]
id = "work"
display_name = "Work"
email = "me@work.example"
auth = "password"
credential = { kind = "env", var = "OPENMAIL_T37_UNUSED_A" }
imap = { host = "imap.work.example", port = 993, tls = "implicit" }
[[account]]
id = "personal"
display_name = "Personal"
email = "me@home.example"
auth = "password"
credential = { kind = "env", var = "OPENMAIL_T37_UNUSED_B" }
imap = { host = "imap.home.example", port = 993, tls = "implicit" }
"#;

/// Backend whose only live operation names the account it was asked about, so a test can tell
/// that a call really reached the backend for that account.
#[derive(Debug, Clone, Copy)]
struct EchoBackend;

fn unsupported<T>() -> CoreResult<T> {
    Err(Error::new(ErrorCode::Unsupported, "not used by this test"))
}

impl MailBackend for EchoBackend {
    async fn test_connection(&self, _: &AccountId) -> CoreResult<ConnectionReport> {
        unsupported()
    }
    async fn list_folders(&self, account: &AccountId) -> CoreResult<Vec<Folder>> {
        Ok(vec![Folder {
            name: format!("INBOX-of-{account}"),
            delimiter: Some('/'),
            role: Some("inbox".into()),
            selectable: true,
        }])
    }
    async fn folder_status(&self, _: &AccountId, _: &str) -> CoreResult<FolderStatus> {
        unsupported()
    }
    async fn list_messages(
        &self,
        _: &AccountId,
        _: &str,
        _: PageRequest,
    ) -> CoreResult<Page<MessageSummary>> {
        unsupported()
    }
    async fn search(
        &self,
        _: &AccountId,
        _: &SearchQuery,
        _: PageRequest,
    ) -> CoreResult<Page<MessageSummary>> {
        unsupported()
    }
    async fn get_message(&self, _: &MessageRef, _: usize) -> CoreResult<Message> {
        unsupported()
    }
    async fn get_thread(&self, _: &MessageRef) -> CoreResult<Vec<MessageSummary>> {
        unsupported()
    }
}

impl MailOrganizer for EchoBackend {
    async fn set_seen(&self, _: &MessageRef, _: bool) -> CoreResult<()> {
        unsupported()
    }
    async fn set_flagged(&self, _: &MessageRef, _: bool) -> CoreResult<()> {
        unsupported()
    }
    async fn move_message(&self, _: &MessageRef, _: &str) -> CoreResult<MessageRef> {
        unsupported()
    }
}

impl MailDrafts for EchoBackend {
    async fn create_draft(&self, _: &AccountId, _: DraftInput) -> CoreResult<MessageRef> {
        unsupported()
    }
    async fn update_draft(&self, _: &MessageRef, _: DraftInput) -> CoreResult<MessageRef> {
        unsupported()
    }
    async fn delete_draft(&self, _: &MessageRef) -> CoreResult<()> {
        unsupported()
    }
}

impl AttachmentSource for EchoBackend {
    async fn get_attachment(&self, _: &MessageRef, _: u32, _: usize) -> CoreResult<AttachmentData> {
        unsupported()
    }
}

impl SentFolder for EchoBackend {
    async fn append_sent(&self, _: &AccountId, _: Vec<u8>) -> CoreResult<()> {
        unsupported()
    }
}

/// Serves a fixed JWKS containing the test key.
#[derive(Debug)]
struct FixedJwks(Vec<u8>);

impl JwksFetcher for FixedJwks {
    async fn fetch(&self, _: &Url) -> Result<Vec<u8>, AuthError> {
        Ok(self.0.clone())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mint(client: &str, scope: &str, aud: &str, exp: u64) -> String {
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some("k1".into());
    let claims = json!({"iss": ISS, "aud": aud, "exp": exp, "client_id": client, "scope": scope});
    encode(
        &h,
        &claims,
        &EncodingKey::from_ec_pem(KEY_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// Reads `mail:read mail:work` => may read account `work` only.
fn alice() -> String {
    mint("alice", "mail:read mail:work", AUD, now() + 300)
}

fn bob() -> String {
    mint("bob", "mail:read mail:personal", AUD, now() + 300)
}

struct Server {
    addr: SocketAddr,
    http: reqwest::Client,
    ca_pem: String,
    readiness: Readiness,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), openmail_remote::http::HttpError>>,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.addr.port())
    }

    fn mcp_url(&self) -> String {
        self.url("/mcp")
    }

    /// A real rmcp client speaking Streamable HTTP over TLS with `token`.
    async fn client(&self, token: &str) -> RunningService<RoleClient, ()> {
        let transport = StreamableHttpClientTransport::with_client(
            self.http.clone(),
            StreamableHttpClientTransportConfig::with_uri(self.mcp_url()).auth_header(token),
        );
        ().serve(transport).await.unwrap()
    }
}

async fn start(tweak: impl FnOnce(&mut HttpConfig)) -> Server {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let ca_pem = cert.cert.pem();
    let tls = server_config(
        ca_pem.as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();

    let jwks = serde_json::to_vec(&json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": KEY_X, "y": KEY_Y
    }]}))
    .unwrap();
    let scopes = BTreeMap::from([
        ("mail:work".to_owned(), vec!["work".to_owned()]),
        ("mail:personal".to_owned(), vec!["personal".to_owned()]),
    ]);
    let jwt = JwtConfig::new(ISS, AUD, "https://idp.example.com/jwks", scopes).unwrap();
    let auth = Arc::new(AuthState {
        authenticator: Arc::new(Authenticator::Jwt(JwtValidator::new(jwt, FixedJwks(jwks)))),
        resource_metadata_url: METADATA_URL.to_owned(),
    });

    let config = Arc::new(Config::from_toml(CONFIG).unwrap());
    let mcp = mcp_router(
        move || {
            Ok(build_server_with_resolver(
                Arc::clone(&config),
                EchoBackend,
                Arc::new(HttpPrincipalResolver),
                RateLimits::default(),
            ))
        },
        StreamableHttpServerConfig::default().with_allowed_hosts(["127.0.0.1"]),
    );

    let mut cfg = HttpConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.auth = Some(auth);
    cfg.resource_metadata = Some(ProtectedResourceMetadata::new(
        AUD,
        ISS,
        &["mail:read", "mail:work", "mail:personal"],
    ));
    tweak(&mut cfg);
    let readiness = Readiness::default();
    let app = router(cfg, mcp, readiness.clone()).unwrap();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = TlsListener::new(tcp, tls).unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(serve_listener(listener, app, readiness.clone(), async {
        let _ = rx.await;
    }));
    while !readiness.is_ready() {
        tokio::task::yield_now().await;
    }
    let http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    Server {
        addr,
        http,
        ca_pem,
        readiness,
        stop: Some(stop),
        task,
    }
}

fn args(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => panic!("args must be an object"),
    }
}

async fn call(c: &RunningService<RoleClient, ()>, tool: &'static str, a: Value) -> CallToolResult {
    c.call_tool(CallToolRequestParams::new(tool).with_arguments(args(a)))
        .await
        .unwrap()
}

fn error_code(r: &CallToolResult) -> String {
    assert_eq!(r.is_error, Some(true), "expected an error result: {r:?}");
    r.structured_content.as_ref().unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

const INIT_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}"#;

fn raw_post(s: &Server, token: Option<&str>, body: &str) -> reqwest::RequestBuilder {
    let mut r = s
        .http
        .post(s.mcp_url())
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_owned());
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    r
}

#[tokio::test]
async fn unauthenticated_and_bad_tokens_get_401_with_challenge() {
    let s = start(|_| {}).await;

    let none = raw_post(&s, None, INIT_BODY).send().await.unwrap();
    assert_eq!(none.status(), 401);
    let challenge = none.headers()["www-authenticate"].to_str().unwrap();
    assert!(challenge.starts_with("Bearer"), "{challenge}");
    assert!(challenge.contains(METADATA_URL), "{challenge}");

    let expired = mint("alice", "mail:read mail:work", AUD, now() - 3600);
    let r = raw_post(&s, Some(&expired), INIT_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(
        r.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );

    let wrong_aud = mint(
        "alice",
        "mail:read mail:work",
        "https://other.example/mcp",
        now() + 300,
    );
    let r = raw_post(&s, Some(&wrong_aud), INIT_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let r = raw_post(&s, Some("not-a-jwt"), INIT_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn protected_resource_metadata_and_probes_need_no_token() {
    let s = start(|_| {}).await;
    let m: Value = s
        .http
        .get(s.url("/.well-known/oauth-protected-resource"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["resource"], AUD);
    assert_eq!(m["authorization_servers"][0], ISS);
    assert_eq!(
        s.http.get(s.url("/healthz")).send().await.unwrap().status(),
        200
    );
    assert_eq!(
        s.http.get(s.url("/readyz")).send().await.unwrap().status(),
        200
    );
    s.readiness.set(false);
    assert_eq!(
        s.http.get(s.url("/readyz")).send().await.unwrap().status(),
        503
    );
}

#[tokio::test]
async fn principal_limited_to_one_account_cannot_reach_the_other() {
    let s = start(|_| {}).await;

    let a = s.client(&alice()).await;
    let accounts = call(&a, "mail_list_accounts", json!({})).await;
    let listed = accounts.structured_content.unwrap()["accounts"].clone();
    let ids: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["work"], "alice must not even see `personal`");

    let own = call(&a, "mail_list_folders", json!({"account": "work"})).await;
    assert_ne!(own.is_error, Some(true), "{own:?}");
    assert!(
        own.structured_content
            .unwrap()
            .to_string()
            .contains("INBOX-of-work"),
        "the call must reach the backend for `work`"
    );

    let other = call(&a, "mail_list_folders", json!({"account": "personal"})).await;
    assert_eq!(error_code(&other), "ACCESS_DENIED");

    // The mirror image: bob sees only `personal`, on the same server instance.
    let b = s.client(&bob()).await;
    let other = call(&b, "mail_list_folders", json!({"account": "work"})).await;
    assert_eq!(error_code(&other), "ACCESS_DENIED");
    let own = call(&b, "mail_list_folders", json!({"account": "personal"})).await;
    assert_ne!(own.is_error, Some(true), "{own:?}");

    let _ = a.cancel().await;
    let _ = b.cancel().await;
}

#[tokio::test]
async fn a_session_cannot_be_used_by_another_principal() {
    let s = start(|_| {}).await;
    let init = raw_post(&s, Some(&alice()), INIT_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(init.status(), 200);
    let session = init.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();

    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    // Bob presents alice's session id with his own valid token.
    let stolen = raw_post(&s, Some(&bob()), list)
        .header("mcp-session-id", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(stolen.status(), 404);

    // Alice herself is not affected by the attempt.
    let mine = raw_post(&s, Some(&alice()), list)
        .header("mcp-session-id", &session)
        .send()
        .await
        .unwrap();
    assert_ne!(mine.status(), 404);
}

#[tokio::test]
async fn disallowed_origin_is_rejected_even_with_a_valid_token() {
    let s = start(|_| {}).await;
    let bad = raw_post(&s, Some(&alice()), INIT_BODY)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403);
    let ok = raw_post(&s, Some(&alice()), INIT_BODY)
        .header("origin", "http://localhost:3000")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let s = start(|c| c.max_body_bytes = 256).await;
    let big = format!(r#"{{"pad":"{}"}}"#, "a".repeat(1024));
    let r = raw_post(&s, Some(&alice()), &big).send().await.unwrap();
    assert_eq!(r.status(), 413);
}

#[tokio::test]
async fn request_rate_is_limited_per_client() {
    let s = start(|c| {
        c.rate_burst = 3;
        c.rate_per_sec = 0.01;
    })
    .await;
    for _ in 0..3 {
        assert_eq!(
            s.http.get(s.url("/healthz")).send().await.unwrap().status(),
            200
        );
    }
    let r = s.http.get(s.url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert!(r.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn plaintext_http_is_not_served_and_untrusted_ca_is_refused() {
    let s = start(|_| {}).await;
    // The listener only speaks TLS: a plaintext request never yields an HTTP response.
    let plain = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/healthz", s.addr.port()))
        .send()
        .await;
    assert!(plain.is_err(), "plaintext must not get a response");
    // A client that does not trust the server's CA cannot connect either.
    let strict = reqwest::Client::new().get(s.url("/healthz")).send().await;
    assert!(
        strict.is_err(),
        "self-signed cert must not be trusted by default"
    );
    assert!(s.ca_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn graceful_shutdown_flips_readiness_and_stops_listening() {
    let mut s = start(|_| {}).await;
    let c = s.client(&alice()).await;
    assert_ne!(
        call(&c, "mail_list_accounts", json!({})).await.is_error,
        Some(true)
    );
    let _ = c.cancel().await;

    let _ = s.stop.take().unwrap().send(());
    tokio::time::timeout(Duration::from_secs(15), &mut s.task)
        .await
        .expect("server must stop within the grace period")
        .unwrap()
        .unwrap();
    assert!(!s.readiness.is_ready());
    let after = s.http.get(s.url("/healthz")).send().await;
    assert!(after.is_err(), "no new connections after shutdown");
}
