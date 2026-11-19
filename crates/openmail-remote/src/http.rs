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
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Path the MCP service is mounted at.
pub const MCP_PATH: &str = "/mcp";
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
    #[error("bearer auth is configured with no tokens")]
    EmptyTokenSet,
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

/// Set of accepted bearer tokens, kept only as SHA-256 digests and compared
/// without early exit.
#[derive(Clone)]
pub struct BearerTokens {
    digests: Vec<[u8; 32]>,
}

impl std::fmt::Debug for BearerTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokens")
            .field("count", &self.digests.len())
            .finish()
    }
}

impl BearerTokens {
    pub fn new<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Result<Self, HttpError> {
        let digests: Vec<[u8; 32]> = tokens
            .into_iter()
            .filter(|t| !t.is_empty())
            .map(|t| Sha256::digest(t.as_bytes()).into())
            .collect();
        if digests.is_empty() {
            return Err(HttpError::EmptyTokenSet);
        }
        Ok(Self { digests })
    }

    fn verify(&self, candidate: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        // Fold over every stored digest so timing does not reveal which matched.
        self.digests.iter().fold(false, |ok, known| {
            let diff = known
                .iter()
                .zip(digest.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            ok | (diff == 0)
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    /// `None` is only legal on a loopback bind.
    pub auth: Option<BearerTokens>,
    /// Exact `Origin` values (scheme://host[:port]) accepted from browsers.
    pub allowed_origins: Vec<String>,
    /// Accept `http(s)://localhost|127.0.0.1|[::1]` origins on any port.
    pub allow_loopback_origins: bool,
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub rate_per_sec: f64,
    pub rate_burst: u32,
    /// Peers whose `X-Forwarded-For` is believed (reverse proxies we run).
    pub trusted_proxies: Vec<IpAddr>,
}

impl HttpConfig {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            auth: None,
            allowed_origins: Vec::new(),
            allow_loopback_origins: true,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            rate_per_sec: DEFAULT_RATE_PER_SEC,
            rate_burst: DEFAULT_RATE_BURST,
            trusted_proxies: Vec::new(),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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

async fn require_bearer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(tokens) = &state.config.auth {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim());
        if !presented.is_some_and(|t| tokens.verify(t)) {
            let mut resp = deny(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return resp;
        }
    }
    next.run(req).await
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
            require_bearer,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            validate_origin,
        ));
    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state.clone())
        .nest(MCP_PATH, protected)
        // Outermost so unauthenticated floods are throttled before auth work.
        .layer(middleware::from_fn_with_state(state, rate_limit)))
}

/// Bind, mark ready, serve until `shutdown` resolves, then drain in-flight
/// requests. `/readyz` flips to 503 as soon as shutdown begins so load
/// balancers stop routing before connections close.
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

async fn serve_listener(
    listener: tokio::net::TcpListener,
    app: Router,
    readiness: Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), HttpError> {
    readiness.set(true);
    let flag = readiness.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        flag.set(false);
    })
    .await
    .map_err(HttpError::Serve)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::routing::post;
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

    fn mcp_stub() -> Router {
        Router::new().route(
            "/",
            post(|body: axum::body::Bytes| async move { format!("len={}", body.len()) }),
        )
    }

    async fn start(tweak: impl FnOnce(&mut HttpConfig)) -> Harness {
        let mut cfg = HttpConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.auth = Some(BearerTokens::new([TOKEN]).unwrap());
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
        ok.auth = Some(BearerTokens::new([TOKEN]).unwrap());
        assert!(ok.validate().is_ok());
        assert!(
            HttpConfig::new("[::1]:8080".parse().unwrap())
                .validate()
                .is_ok()
        );
        assert!(BearerTokens::new(["", ""]).is_err());
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
