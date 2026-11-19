//! Streamable-HTTP front for the MCP service: health probes, DNS-rebinding
//! (Origin) defence, bearer auth, body/time limits, per-IP rate limiting,
//! trusted-proxy handling and graceful shutdown.
//!
//! The MCP protocol handler itself is supplied by the caller as an
//! [`axum::Router`] mounted at [`MCP_PATH`]; this module only hardens the edge.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::serve::{IncomingStream, Listener};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::auth::{AuthState, ProtectedResourceMetadata, require_auth};

/// Path the MCP service is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// RFC 9728 well-known location of the protected-resource metadata.
pub const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// MCP requests are small JSON-RPC envelopes; 1 MiB leaves room for large
/// tool arguments (drafts) without letting a client stream unbounded bodies.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Upper bound for producing response headers; streaming bodies are not cut.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Sustained per-IP request rate; mail tools are human/LLM paced.
pub const DEFAULT_RATE_PER_SEC: f64 = 20.0;
/// Short bursts (client reconnect + initialize + list) must not be throttled.
pub const DEFAULT_RATE_BURST: u32 = 40;
/// Idle buckets are dropped once the table exceeds this, bounding memory
/// under address-spraying clients.
const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("refusing to bind non-loopback address {0} without bearer auth configured")]
    UnauthenticatedPublicBind(SocketAddr),
    #[error("invalid rate limit: rate must be > 0 and burst >= 1")]
    InvalidRateLimit,
    #[error("failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("server error: {0}")]
    Serve(#[source] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    /// Authenticates every `/mcp` request and attaches the caller's
    /// [`openmail_security::Principal`]. `None` is only legal on a loopback bind.
    pub auth: Option<Arc<AuthState>>,
    /// Served unauthenticated at `/.well-known/oauth-protected-resource` (RFC 9728).
    pub resource_metadata: Option<ProtectedResourceMetadata>,
    /// Exact `Origin` values (`scheme://host[:port]`) accepted from browsers.
    pub allowed_origins: Vec<String>,
    /// Accept `http(s)://localhost|127.0.0.1|[::1]` origins on any port.
    pub allow_loopback_origins: bool,
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub rate_per_sec: f64,
    pub rate_burst: u32,
    /// Peers whose `X-Forwarded-For` is believed (reverse proxies we run).
    pub trusted_proxies: Vec<IpAddr>,
    /// Extra unauthenticated routes served beside `/mcp` (the built-in OAuth authorization
    /// server's metadata, registration, authorize and token endpoints). They bring their own
    /// body limits and are covered by the same per-client rate limit as the probes.
    pub public_routes: Option<Router>,
}

impl HttpConfig {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            auth: None,
            resource_metadata: None,
            allowed_origins: Vec::new(),
            allow_loopback_origins: true,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            rate_per_sec: DEFAULT_RATE_PER_SEC,
            rate_burst: DEFAULT_RATE_BURST,
            trusted_proxies: Vec::new(),
            public_routes: None,
        }
    }

    pub fn validate(&self) -> Result<(), HttpError> {
        if self.auth.is_none() && !self.bind.ip().is_loopback() {
            return Err(HttpError::UnauthenticatedPublicBind(self.bind));
        }
        if !(self.rate_per_sec.is_finite() && self.rate_per_sec > 0.0) || self.rate_burst == 0 {
            return Err(HttpError::InvalidRateLimit);
        }
        Ok(())
    }
}

/// Readiness flag shared with the embedding process (`/readyz`).
#[derive(Debug, Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// TCP peer address as seen by the per-IP rate limiter; a newtype so it can implement
/// [`Connected`] for both the plain and the TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub SocketAddr);

impl Connected<IncomingStream<'_, tokio::net::TcpListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, crate::tls::TlsListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, crate::tls::TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
struct RateLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    fn new(rate: f64, burst: u32) -> Self {
        Self {
            rate,
            burst: f64::from(burst),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `Ok(())` if allowed, else the wait until a token is available.
    fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        // A poisoned lock only means another request panicked; the map is still valid.
        let mut map = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= MAX_TRACKED_IPS && !map.contains_key(&ip) {
            let full_after = Duration::from_secs_f64(self.burst / self.rate);
            map.retain(|_, b| now.duration_since(b.last) < full_after);
        }
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate))
        }
    }
}

#[derive(Debug)]
struct Shared {
    config: HttpConfig,
    limiter: RateLimiter,
    readiness: Readiness,
}

type AppState = Arc<Shared>;

/// Real client address: the TCP peer, unless it is a trusted proxy, in which
/// case the right-most `X-Forwarded-For` hop that is not itself trusted.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    for hop in hops.iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) if trusted.contains(&ip) => continue,
            Ok(ip) => return ip,
            // Garbage in the chain: do not guess, attribute to the proxy.
            Err(_) => return peer,
        }
    }
    peer
}

fn origin_allowed(origin: &str, config: &HttpConfig) -> bool {
    if config
        .allowed_origins
        .iter()
        .any(|o| o.eq_ignore_ascii_case(origin))
    {
        return true;
    }
    if !config.allow_loopback_origins {
        return false;
    }
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    let host = if let Some(v6) = rest.strip_prefix('[') {
        v6.split(']')
            .next()
            .map(|h| format!("[{h}]"))
            .unwrap_or_default()
    } else {
        rest.split(':').next().unwrap_or_default().to_owned()
    };
    let port_ok = match rest.rsplit_once(':') {
        Some((_, port)) if !rest.ends_with(']') => port.chars().all(|c| c.is_ascii_digit()),
        _ => true,
    };
    port_ok && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

fn deny(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

async fn rate_limit(
    State(state): State<AppState>,
    ConnectInfo(ClientAddr(peer)): ConnectInfo<ClientAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(peer.ip(), req.headers(), &state.config.trusted_proxies);
    match state.limiter.check(ip, Instant::now()) {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            tracing::warn!(%ip, "rate limit exceeded");
            let secs = wait.as_secs().saturating_add(1).to_string();
            let mut resp = deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            if let Ok(v) = HeaderValue::from_str(&secs) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            resp
        }
    }
}

/// MCP spec: servers MUST validate `Origin` to prevent DNS-rebinding. Requests
/// without an Origin (non-browser clients) pass; any present Origin must be allowed.
async fn validate_origin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let allowed = origin
            .to_str()
            .is_ok_and(|o| origin_allowed(o, &state.config));
        if !allowed {
            tracing::warn!("rejected request with disallowed Origin");
            return deny(StatusCode::FORBIDDEN, "origin not allowed");
        }
    }
    next.run(req).await
}

/// Authenticate with the configured [`AuthState`]. The loopback-only
/// no-auth mode passes requests through without a principal; a handler
/// that needs one must treat its absence as a denial.
async fn require_principal(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match &state.config.auth {
        Some(auth) => require_auth(State(Arc::clone(auth)), req, next).await,
        None => next.run(req).await,
    }
}

async fn resource_metadata(State(state): State<AppState>) -> Response {
    match &state.config.resource_metadata {
        Some(m) => match serde_json::to_vec(m) {
            Ok(body) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                body,
            )
                .into_response(),
            Err(_) => deny(StatusCode::INTERNAL_SERVER_ERROR, "metadata unavailable"),
        },
        None => deny(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.readiness.is_ready() {
        (StatusCode::OK, "ready").into_response()
    } else {
        deny(StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Wrap `mcp` (the rmcp Streamable-HTTP service) with the edge protections.
/// Probes are unauthenticated and not Origin-checked, but still rate limited.
pub fn router(config: HttpConfig, mcp: Router, readiness: Readiness) -> Result<Router, HttpError> {
    config.validate()?;
    let public_routes = config.public_routes.clone();
    let state: AppState = Arc::new(Shared {
        limiter: RateLimiter::new(config.rate_per_sec, config.rate_burst),
        readiness,
        config,
    });
    let protected = mcp
        // Innermost: size and time bounds on the actual MCP handler.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            state.config.request_timeout,
        ))
        .layer(RequestBodyLimitLayer::new(state.config.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_principal,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            validate_origin,
        ));
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(RESOURCE_METADATA_PATH, get(resource_metadata))
        .with_state(state.clone())
        .nest(MCP_PATH, protected);
    if let Some(public) = public_routes {
        app = app.merge(public);
    }
    Ok(app
        // Outermost so unauthenticated floods are throttled before auth work.
        .layer(middleware::from_fn_with_state(state, rate_limit)))
}

/// After shutdown begins, in-flight requests get this long to finish. Long-lived
/// SSE streams would otherwise hold the process open forever.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Bind plain TCP, mark ready, serve until `shutdown` resolves, then drain
/// in-flight requests. `/readyz` flips to 503 as soon as shutdown begins so
/// load balancers stop routing before connections close. Plaintext is only
/// acceptable on loopback or behind a trusted TLS-terminating proxy; see
/// [`serve_tls`].
pub async fn serve(
    config: HttpConfig,
    mcp: Router,
    readiness: Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), HttpError> {
    let addr = config.bind;
    let app = router(config, mcp, readiness.clone())?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| HttpError::Bind { addr, source })?;
    serve_listener(listener, app, readiness, shutdown).await
}

/// Like [`serve`] but terminates TLS in-process.
pub async fn serve_tls(
    config: HttpConfig,
    mcp: Router,
    readiness: Readiness,
    tls: Arc<tokio_rustls::rustls::ServerConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), HttpError> {
    let addr = config.bind;
    let app = router(config, mcp, readiness.clone())?;
    let tcp = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| HttpError::Bind { addr, source })?;
    let listener = crate::tls::TlsListener::new(tcp, tls).map_err(HttpError::Serve)?;
    serve_listener(listener, app, readiness, shutdown).await
}

/// Serve on an already-bound listener (lets callers learn an ephemeral port).
pub async fn serve_listener<L>(
    listener: L,
    app: Router,
    readiness: Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), HttpError>
where
    L: Listener,
    L::Addr: std::fmt::Debug,
    ClientAddr: for<'a> Connected<IncomingStream<'a, L>>,
{
    readiness.set(true);
    let flag = readiness.clone();
    let (begun_tx, begun_rx) = tokio::sync::oneshot::channel::<()>();
    let server = std::future::IntoFuture::into_future(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ClientAddr>(),
        )
        .with_graceful_shutdown(async move {
            shutdown.await;
            flag.set(false);
            // The receiver is gone only if serving already ended.
            let _ = begun_tx.send(());
        }),
    );
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result.map_err(HttpError::Serve),
        () = async {
            if begun_rx.await.is_ok() {
                tokio::time::sleep(SHUTDOWN_GRACE).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!("shutdown grace period elapsed; closing remaining connections");
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::{Authenticator, HttpsJwksFetcher, StaticBearer};
    use axum::routing::post;
    use openmail_core::ids::AccountId;
    use openmail_security::Action;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;

    const TOKEN: &str = "test-token-not-a-real-secret";

    struct Harness {
        addr: SocketAddr,
        readiness: Readiness,
        stop: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), HttpError>>,
    }

    fn test_auth() -> Arc<AuthState> {
        Arc::new(AuthState {
            authenticator: Arc::new(Authenticator::<HttpsJwksFetcher>::Static(
                StaticBearer::new(TOKEN, [Action::Read], [AccountId::new("work").unwrap()]),
            )),
            resource_metadata_url: "https://mail.example.com/.well-known/oauth-protected-resource"
                .into(),
        })
    }

    fn mcp_stub() -> Router {
        Router::new().route(
            "/",
            post(|body: axum::body::Bytes| async move { format!("len={}", body.len()) }),
        )
    }

    async fn start(tweak: impl FnOnce(&mut HttpConfig)) -> Harness {
        let mut cfg = HttpConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.auth = Some(test_auth());
        tweak(&mut cfg);
        let readiness = Readiness::default();
        let app = router(cfg, mcp_stub(), readiness.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(serve_listener(listener, app, readiness.clone(), async {
            let _ = rx.await;
        }));
        // serve_listener sets readiness before accepting.
        while !readiness.is_ready() {
            tokio::task::yield_now().await;
        }
        Harness {
            addr,
            readiness,
            stop: Some(tx),
            task,
        }
    }

    /// Returns (status, raw head+body text).
    async fn raw(addr: SocketAddr, request: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(request).await.unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    fn post_req(extra: &str, body: &str) -> Vec<u8> {
        format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn auth() -> String {
        format!("Authorization: Bearer {TOKEN}\r\n")
    }

    #[tokio::test]
    async fn health_ready_and_shutdown() {
        let mut h = start(|_| {}).await;
        let get = |p: &str| {
            format!("GET {p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes()
        };
        assert_eq!(raw(h.addr, &get("/healthz")).await.0, 200);
        assert_eq!(raw(h.addr, &get("/readyz")).await.0, 200);
        h.readiness.set(false);
        assert_eq!(raw(h.addr, &get("/readyz")).await.0, 503);
        let _ = h.stop.take().unwrap().send(());
        h.task.await.unwrap().unwrap();
        assert!(!h.readiness.is_ready());
    }

    #[tokio::test]
    async fn rejects_missing_and_wrong_token_with_401() {
        let h = start(|_| {}).await;
        let (s, text) = raw(h.addr, &post_req("", "{}")).await;
        assert_eq!(s, 401);
        assert!(
            text.to_ascii_lowercase()
                .contains("www-authenticate: bearer")
        );
        assert_eq!(
            raw(h.addr, &post_req("Authorization: Bearer nope\r\n", "{}"))
                .await
                .0,
            401
        );
        assert_eq!(
            raw(h.addr, &post_req("Authorization: Basic abc\r\n", "{}"))
                .await
                .0,
            401
        );
        let (s, text) = raw(h.addr, &post_req(&auth(), "{}")).await;
        assert_eq!(s, 200);
        assert!(text.ends_with("len=2"));
    }

    #[tokio::test]
    async fn origin_validation_blocks_rebinding() {
        let h = start(|c| c.allowed_origins.push("https://app.example.com".into())).await;
        let with = |o: &str| post_req(&format!("{}Origin: {o}\r\n", auth()), "{}");
        assert_eq!(raw(h.addr, &with("http://evil.example")).await.0, 403);
        assert_eq!(
            raw(h.addr, &with("http://localhost.evil.example")).await.0,
            403
        );
        assert_eq!(
            raw(h.addr, &with("http://127.0.0.1.evil.example:80"))
                .await
                .0,
            403
        );
        assert_eq!(raw(h.addr, &with("https://app.example.com")).await.0, 200);
        assert_eq!(raw(h.addr, &with("http://localhost:3000")).await.0, 200);
        assert_eq!(raw(h.addr, &with("http://[::1]:3000")).await.0, 200);
        // Origin is checked before auth: a bad origin never reaches token checks.
        assert_eq!(
            raw(h.addr, &post_req("Origin: http://evil.example\r\n", "{}"))
                .await
                .0,
            403
        );
    }

    #[tokio::test]
    async fn enforces_body_limit() {
        let h = start(|c| c.max_body_bytes = 16).await;
        assert_eq!(
            raw(h.addr, &post_req(&auth(), &"a".repeat(16))).await.0,
            200
        );
        assert_eq!(
            raw(h.addr, &post_req(&auth(), &"a".repeat(17))).await.0,
            413
        );
    }

    #[tokio::test]
    async fn rate_limits_per_ip() {
        let h = start(|c| {
            c.rate_burst = 3;
            c.rate_per_sec = 0.01;
        })
        .await;
        let get = b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        for _ in 0..3 {
            assert_eq!(raw(h.addr, get).await.0, 200);
        }
        let (s, text) = raw(h.addr, get).await;
        assert_eq!(s, 429);
        assert!(text.to_ascii_lowercase().contains("retry-after:"));
    }

    #[tokio::test]
    async fn times_out_slow_handlers() {
        let slow = Router::new().route(
            "/",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        );
        let mut cfg = HttpConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.request_timeout = Duration::from_millis(100);
        let app = router(cfg, slow, Readiness::default()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ready = Readiness::default();
        tokio::spawn(serve_listener(listener, app, ready, std::future::pending()));
        assert_eq!(raw(addr, &post_req("", "{}")).await.0, 408);
    }

    #[test]
    fn refuses_public_bind_without_auth() {
        let cfg = HttpConfig::new("0.0.0.0:8080".parse().unwrap());
        assert!(matches!(
            cfg.validate(),
            Err(HttpError::UnauthenticatedPublicBind(_))
        ));
        let mut ok = HttpConfig::new("0.0.0.0:8080".parse().unwrap());
        ok.auth = Some(test_auth());
        assert!(ok.validate().is_ok());
        assert!(
            HttpConfig::new("[::1]:8080".parse().unwrap())
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn forwarded_for_only_trusted_from_proxies() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.9".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 203.0.113.9, 10.0.0.1"),
        );
        // Untrusted peer: header ignored (spoofing attempt).
        assert_eq!(client_ip(client, &h, &[proxy]), client);
        // Trusted proxy: right-most non-trusted hop, not the spoofable left-most.
        assert_eq!(client_ip(proxy, &h, &[proxy]), client);
        let mut bad = HeaderMap::new();
        bad.insert("x-forwarded-for", HeaderValue::from_static("garbage"));
        assert_eq!(client_ip(proxy, &bad, &[proxy]), proxy);
    }

    #[test]
    fn limiter_refills_over_time() {
        let l = RateLimiter::new(1.0, 1);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(l.check(ip, t0).is_ok());
        assert!(l.check(ip, t0).is_err());
        assert!(l.check(ip, t0 + Duration::from_secs(2)).is_ok());
    }
}
