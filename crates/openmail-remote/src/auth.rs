//! OAuth 2.1 resource-server side of the MCP authorization spec.
//!
//! * RFC 9728 protected-resource metadata + `WWW-Authenticate` challenge.
//! * JWT access-token validation against a cached, rotating JWKS.
//! * A constant-time static bearer mode for self-hosting.
//! * An axum middleware that yields a [`Principal`] and never forwards the
//!   inbound token downstream (no token passthrough).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use openmail_core::ids::AccountId;
use openmail_security::{Action, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::{Host, Url};

/// Upper bound on a JWKS document; real key sets are a few KiB.
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
/// A hung identity provider must not hold request handlers.
pub const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a fetched key set is trusted before a refresh.
pub const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(600);
/// Minimum gap between refetches triggered by unknown `kid`s, so garbage
/// tokens cannot turn this server into a JWKS-endpoint flood.
pub const DEFAULT_MIN_REFETCH: Duration = Duration::from_secs(30);
/// Clock skew tolerated for `exp`/`nbf`.
pub const DEFAULT_LEEWAY_SECS: u64 = 30;

/// OAuth scope strings that grant a tool action. Unknown scopes grant nothing.
pub const SCOPE_READ: &str = "mail:read";
pub const SCOPE_ORGANIZE: &str = "mail:organize";
pub const SCOPE_DRAFT: &str = "mail:draft";
pub const SCOPE_SEND: &str = "mail:send";
pub const SCOPE_DELETE: &str = "mail:delete";

/// The action a token scope grants, if it is one of ours.
pub fn action_for_scope(scope: &str) -> Option<Action> {
    match scope {
        SCOPE_READ => Some(Action::Read),
        SCOPE_ORGANIZE => Some(Action::Organize),
        SCOPE_DRAFT => Some(Action::Draft),
        SCOPE_SEND => Some(Action::Send),
        SCOPE_DELETE => Some(Action::Delete),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),
    #[error("token expired")]
    Expired,
    #[error("jwks url rejected: {0}")]
    UnsafeJwksUrl(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
}

impl AuthError {
    fn rfc6750_error(&self) -> Option<&'static str> {
        match self {
            Self::MissingToken => None,
            Self::InvalidToken(_) | Self::Expired => Some("invalid_token"),
            // Our own infrastructure failure is not the client's fault, but a
            // 401 with invalid_token is still the safe answer (fail closed).
            Self::UnsafeJwksUrl(_) | Self::JwksFetch(_) => Some("invalid_token"),
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 9728 metadata + challenge
// ---------------------------------------------------------------------------

/// Body of `/.well-known/oauth-protected-resource`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    /// Omitted when there is no authorization server (static-bearer mode), so an OAuth client
    /// following the metadata learns there is nothing to authorize against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn new(resource: &str, authorization_server: &str, scopes: &[&str]) -> Self {
        Self {
            resource: resource.to_owned(),
            authorization_servers: vec![authorization_server.to_owned()],
            scopes_supported: scopes.iter().map(|s| (*s).to_owned()).collect(),
            bearer_methods_supported: vec!["header".to_owned()],
        }
    }
}

impl ProtectedResourceMetadata {
    /// Static-bearer deployments have no OAuth authorization server; advertising one (or
    /// ourselves as one) would send an OAuth client into a dead end. ChatGPT cannot use this mode.
    pub fn static_bearer(resource: &str) -> Self {
        Self {
            resource: resource.to_owned(),
            authorization_servers: Vec::new(),
            scopes_supported: Vec::new(),
            bearer_methods_supported: vec!["header".to_owned()],
        }
    }
}

/// Build the `WWW-Authenticate` value pointing clients at the metadata URL.
pub fn www_authenticate(resource_metadata_url: &str, error: Option<&AuthError>) -> String {
    let mut v = String::from("Bearer");
    if let Some(code) = error.and_then(AuthError::rfc6750_error) {
        v.push_str(&format!(" error=\"{code}\","));
    }
    // Quotes in a configured URL would break the header; strip rather than escape.
    let url = resource_metadata_url.replace(['"', '\\', '\r', '\n'], "");
    v.push_str(&format!(" resource_metadata=\"{url}\""));
    v
}

// ---------------------------------------------------------------------------
// JWKS fetching with SSRF protection
// ---------------------------------------------------------------------------

/// True for loopback, private, link-local, CGNAT, multicast, unspecified,
/// documentation and other non-globally-routable addresses.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return forbidden_v4(mapped);
            }
            forbidden_v6(v6)
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT 100.64/10
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
        || o[0] >= 240 // reserved
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
}

/// Static checks on a JWKS URL: https only, no credentials, no private IP
/// literals, no obviously internal hostnames. DNS results are checked again at
/// fetch time by [`HttpsJwksFetcher`].
pub fn validate_jwks_url(raw: &str) -> Result<Url, AuthError> {
    let reject = |why: &str| AuthError::UnsafeJwksUrl(why.to_owned());
    let url = Url::parse(raw).map_err(|_| reject("unparseable"))?;
    if url.scheme() != "https" {
        return Err(reject("scheme must be https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(reject("credentials in url"));
    }
    match url.host().ok_or_else(|| reject("no host"))? {
        Host::Ipv4(ip) if is_forbidden_ip(IpAddr::V4(ip)) => Err(reject("private address")),
        Host::Ipv6(ip) if is_forbidden_ip(IpAddr::V6(ip)) => Err(reject("private address")),
        Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let internal = d == "localhost"
                || d.ends_with(".localhost")
                || d.ends_with(".local")
                || d.ends_with(".internal")
                || !d.contains('.');
            if internal {
                Err(reject("internal hostname"))
            } else {
                Ok(url)
            }
        }
        _ => Ok(url),
    }
}

/// Source of raw JWKS bytes. Abstracted so the validator is testable offline.
pub trait JwksFetcher: Send + Sync {
    fn fetch(&self, url: &Url) -> impl Future<Output = Result<Vec<u8>, AuthError>> + Send;
}

/// Production fetcher: resolves DNS itself, rejects any forbidden address, then
/// pins the connection to the vetted address (defeats DNS rebinding), with no
/// redirects, a timeout and a body size cap.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpsJwksFetcher;

impl JwksFetcher for HttpsJwksFetcher {
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>, AuthError> {
        let url = validate_jwks_url(url.as_str())?;
        let fail = |e: &dyn std::fmt::Display| AuthError::JwksFetch(e.to_string());
        let host = url.host_str().ok_or_else(|| fail(&"no host"))?.to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| fail(&e))?
            .collect();
        if addrs.is_empty() || addrs.iter().any(|a| is_forbidden_ip(a.ip())) {
            return Err(AuthError::UnsafeJwksUrl(
                "host resolves to forbidden address".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(JWKS_FETCH_TIMEOUT)
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| fail(&e))?;
        let mut resp = client.get(url).send().await.map_err(|e| fail(&e))?;
        if !resp.status().is_success() {
            return Err(fail(&format!("status {}", resp.status())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| fail(&e))? {
            if body.len() + chunk.len() > MAX_JWKS_BYTES {
                return Err(fail(&"jwks too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// JWT validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub issuer: String,
    /// Must equal this server's canonical resource URI (RFC 8707); tokens minted
    /// for another resource are rejected.
    pub audience: String,
    pub jwks_url: Url,
    /// Scope -> account ids it grants. Unmapped scopes grant no accounts.
    pub scope_accounts: BTreeMap<String, Vec<String>>,
    pub jwks_ttl: Duration,
    pub min_refetch: Duration,
    pub leeway_secs: u64,
}

impl JwtConfig {
    pub fn new(
        issuer: &str,
        audience: &str,
        jwks_url: &str,
        scope_accounts: BTreeMap<String, Vec<String>>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            jwks_url: validate_jwks_url(jwks_url)?,
            scope_accounts,
            jwks_ttl: DEFAULT_JWKS_TTL,
            min_refetch: DEFAULT_MIN_REFETCH,
            leeway_secs: DEFAULT_LEEWAY_SECS,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    client_id: Option<String>,
    azp: Option<String>,
    sub: Option<String>,
    scope: Option<String>,
    scp: Option<Vec<String>>,
}

#[derive(Debug)]
struct CachedKeys {
    keys: JwkSet,
    fetched: Instant,
}

/// Algorithms accepted from the identity provider. Symmetric (HS*) algorithms
/// are excluded to rule out key-confusion attacks; `none` is unrepresentable.
const ALLOWED_ALGS: [Algorithm; 5] = [
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug)]
pub struct JwtValidator<F> {
    config: JwtConfig,
    fetcher: F,
    cache: RwLock<Option<CachedKeys>>,
}

impl<F: JwksFetcher> JwtValidator<F> {
    pub fn new(config: JwtConfig, fetcher: F) -> Self {
        Self {
            config,
            fetcher,
            cache: RwLock::new(None),
        }
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        let bytes = self.fetcher.fetch(&self.config.jwks_url).await?;
        let keys: JwkSet = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::JwksFetch(format!("malformed jwks: {e}")))?;
        *self.cache.write().await = Some(CachedKeys {
            keys,
            fetched: Instant::now(),
        });
        Ok(())
    }

    /// Find the verification key, refreshing the cache when stale or when the
    /// `kid` is unknown (key rotation), subject to the refetch rate limit.
    async fn key_for(&self, kid: Option<&str>) -> Result<DecodingKey, AuthError> {
        for attempt in 0..2 {
            let age = {
                let guard = self.cache.read().await;
                if let Some(c) = guard.as_ref() {
                    let fresh = c.fetched.elapsed() < self.config.jwks_ttl;
                    let jwk = match kid {
                        Some(k) => c.keys.find(k),
                        None if c.keys.keys.len() == 1 => c.keys.keys.first(),
                        None => None,
                    };
                    if let (Some(jwk), true) = (jwk, fresh) {
                        return DecodingKey::from_jwk(jwk)
                            .map_err(|_| AuthError::InvalidToken("unusable key"));
                    }
                    Some(c.fetched.elapsed())
                } else {
                    None
                }
            };
            let may_fetch = age.is_none_or(|a| a >= self.config.min_refetch);
            if attempt == 1 || !may_fetch {
                break;
            }
            self.refresh().await?;
        }
        Err(AuthError::InvalidToken("unknown signing key"))
    }

    pub async fn validate(&self, token: &str) -> Result<Principal, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken("bad header"))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(AuthError::InvalidToken("algorithm not allowed"));
        }
        let key = self.key_for(header.kid.as_deref()).await?;

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[&self.config.issuer]);
        v.set_audience(&[&self.config.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_exp = true;
        v.validate_nbf = true;
        v.leeway = self.config.leeway_secs;

        let data = decode::<Claims>(token, &key, &v).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind as K;
            match e.kind() {
                K::ExpiredSignature => AuthError::Expired,
                K::InvalidAudience => AuthError::InvalidToken("wrong audience"),
                K::InvalidIssuer => AuthError::InvalidToken("wrong issuer"),
                K::ImmatureSignature => AuthError::InvalidToken("not yet valid"),
                K::InvalidSignature => AuthError::InvalidToken("bad signature"),
                _ => AuthError::InvalidToken("rejected"),
            }
        })?;
        let c = data.claims;
        let client_id = c
            .client_id
            .or(c.azp)
            .or(c.sub)
            .ok_or(AuthError::InvalidToken("no client identity"))?;
        let scopes: BTreeSet<String> = match (c.scope, c.scp) {
            (Some(s), _) => s.split_whitespace().map(str::to_owned).collect(),
            (None, Some(list)) => list.into_iter().collect(),
            (None, None) => BTreeSet::new(),
        };
        let accounts = scopes
            .iter()
            .filter_map(|s| self.config.scope_accounts.get(s))
            .flatten()
            .filter_map(|raw| match AccountId::new(raw) {
                Ok(id) => Some(id),
                Err(_) => {
                    tracing::warn!("scope mapping names an invalid account id; ignored");
                    None
                }
            });
        let actions = scopes.iter().filter_map(|s| action_for_scope(s));
        Ok(Principal::new(client_id, accounts, actions))
    }
}

// ---------------------------------------------------------------------------
// Static bearer (self-hosting)
// ---------------------------------------------------------------------------

/// Audit identity of the static-bearer principal.
pub const STATIC_BEARER_CLIENT_ID: &str = "static-bearer";

/// One shared secret for single-user deployments. Only its SHA-256 digest is
/// kept, and comparison is constant-time on equal-length digests (so neither
/// content nor length of the secret leaks via timing).
pub struct StaticBearer {
    digest: [u8; 32],
    principal: Principal,
}

impl std::fmt::Debug for StaticBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticBearer")
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

impl StaticBearer {
    pub fn new(
        token: &str,
        actions: impl IntoIterator<Item = Action>,
        accounts: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        Self {
            digest: Sha256::digest(token.as_bytes()).into(),
            principal: Principal::new(STATIC_BEARER_CLIENT_ID, accounts, actions),
        }
    }

    pub fn validate(&self, token: &str) -> Result<Principal, AuthError> {
        let given: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if bool::from(given.ct_eq(&self.digest)) {
            Ok(self.principal.clone())
        } else {
            Err(AuthError::InvalidToken("bad token"))
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Authenticator<F> {
    Static(StaticBearer),
    Jwt(JwtValidator<F>),
}

impl<F: JwksFetcher> Authenticator<F> {
    pub async fn authenticate(&self, token: &str) -> Result<Principal, AuthError> {
        match self {
            Self::Static(s) => s.validate(token),
            Self::Jwt(j) => j.validate(token).await,
        }
    }
}

/// Object-safe seam so the HTTP edge need not be generic over the JWKS fetcher.
pub trait TokenAuthenticator: std::fmt::Debug + Send + Sync {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, AuthError>> + Send + 'a>>;
}

impl<F: JwksFetcher + std::fmt::Debug + 'static> TokenAuthenticator for Authenticator<F> {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, AuthError>> + Send + 'a>> {
        Box::pin(Authenticator::authenticate(self, token))
    }
}

/// Shared state for [`require_auth`].
#[derive(Debug)]
pub struct AuthState {
    pub authenticator: Arc<dyn TokenAuthenticator>,
    pub resource_metadata_url: String,
}

fn bearer_token(req: &Request) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn unauthorized(state_url: &str, err: &AuthError) -> Response {
    let challenge = www_authenticate(state_url, Some(err));
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(v) = HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// axum middleware: authenticate, attach [`Principal`], and strip the inbound
/// `Authorization` header so the token can never be forwarded (no passthrough).
pub async fn require_auth(
    State(state): State<Arc<AuthState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(&req).map(str::to_owned) else {
        return unauthorized(&state.resource_metadata_url, &AuthError::MissingToken);
    };
    match state.authenticator.authenticate(&token).await {
        Ok(principal) => {
            req.headers_mut().remove(header::AUTHORIZATION);
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Err(err) => {
            tracing::warn!(reason = %err, "rejected bearer token");
            unauthorized(&state.resource_metadata_url, &err)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    // Throwaway P-256 keys generated for these tests only.
    const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf52HVVQ19hOO/IIl\nfD4b+/WhbWyZnJF/ScNrXpRhlsKhRANCAATYyz/BuaM9rL1RFvj1YmMSL4RdHVgw\nvnBnlFzits3IMBQHxIQ6VFFgOTY6UOuVSmF7Hws+qDEV+KGFLJWbWPgv\n-----END PRIVATE KEY-----\n";
    const KEY_A_X: &str = "2Ms_wbmjPay9URb49WJjEi-EXR1YML5wZ5Rc4rbNyDA";
    const KEY_A_Y: &str = "FAfEhDpUUWA5NjpQ65VKYXsfCz6oMRX4oYUslZtY-C8";
    const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYfvYvOYMGMoZFJiP\nqz+Vjq8/7aowkEWkcUn7Xenrp/KhRANCAARR/jswZ80jSZjEaXV7RAE9TyHSp3s/\ndG2SX1O8kIvuC6yw7n+XNXXPz9W7uwyThSgLwD/OeAkUHZNFCOw+jp8T\n-----END PRIVATE KEY-----\n";
    const KEY_B_X: &str = "Uf47MGfNI0mYxGl1e0QBPU8h0qd7P3Rtkl9TvJCL7gs";
    const KEY_B_Y: &str = "rLDuf5c1dc_P1bu7DJOFKAvAP854CRQdk0UI7D6OnxM";

    const ISS: &str = "https://idp.example.com";
    const AUD: &str = "https://mail.example.com/mcp";

    fn account(id: &str) -> AccountId {
        AccountId::new(id).unwrap()
    }

    fn jwk(kid: &str, x: &str, y: &str) -> serde_json::Value {
        serde_json::json!({"kty":"EC","crv":"P-256","kid":kid,"alg":"ES256","use":"sig","x":x,"y":y})
    }

    /// Serves a mutable JWKS and counts fetches.
    #[derive(Debug)]
    struct FakeFetcher {
        body: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
    }
    impl JwksFetcher for FakeFetcher {
        async fn fetch(&self, _url: &Url) -> Result<Vec<u8>, AuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.body.lock().map(|b| b.clone()).unwrap_or_default())
        }
    }

    struct Harness {
        validator: JwtValidator<FakeFetcher>,
        body: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
    }

    fn set_keys(body: &Arc<Mutex<Vec<u8>>>, keys: &[serde_json::Value]) {
        let doc = serde_json::json!({ "keys": keys }).to_string().into_bytes();
        *body.lock().unwrap() = doc;
    }

    fn harness() -> Harness {
        let body = Arc::new(Mutex::new(Vec::new()));
        set_keys(&body, &[jwk("a", KEY_A_X, KEY_A_Y)]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut map = BTreeMap::new();
        map.insert("mail:work".to_owned(), vec!["work".to_owned()]);
        let mut cfg = JwtConfig::new(ISS, AUD, "https://idp.example.com/jwks.json", map).unwrap();
        cfg.min_refetch = Duration::ZERO;
        let fetcher = FakeFetcher {
            body: body.clone(),
            calls: calls.clone(),
        };
        Harness {
            validator: JwtValidator::new(cfg, fetcher),
            body,
            calls,
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn mint(pem: &str, kid: &str, iss: &str, aud: &str, exp: u64) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(kid.to_owned());
        let claims = serde_json::json!({
            "iss": iss, "aud": aud, "exp": exp, "sub": "user-1",
            "client_id": "client-1", "scope": "mail:work mail:read"
        });
        encode(
            &h,
            &claims,
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn valid_token_maps_scopes_to_accounts() {
        let h = harness();
        let t = mint(KEY_A_PEM, "a", ISS, AUD, now() + 300);
        let p = h.validator.validate(&t).await.unwrap();
        // "mail:work" only maps accounts; "mail:read" is the sole action scope.
        assert_eq!(
            p,
            Principal::new("client-1", [account("work")], [Action::Read])
        );
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let h = harness();
        let t = mint(KEY_A_PEM, "a", ISS, AUD, now() - 3600);
        assert!(matches!(
            h.validator.validate(&t).await,
            Err(AuthError::Expired)
        ));
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let h = harness();
        let t = mint(
            KEY_A_PEM,
            "a",
            ISS,
            "https://other.example.com",
            now() + 300,
        );
        assert!(matches!(
            h.validator.validate(&t).await,
            Err(AuthError::InvalidToken("wrong audience"))
        ));
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let h = harness();
        let t = mint(KEY_A_PEM, "a", "https://evil.example.com", AUD, now() + 300);
        assert!(matches!(
            h.validator.validate(&t).await,
            Err(AuthError::InvalidToken("wrong issuer"))
        ));
    }

    #[tokio::test]
    async fn alg_none_and_hs256_rejected() {
        let h = harness();
        let b64 = |s: &str| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
        };
        let none = format!(
            "{}.{}.",
            b64(r#"{"alg":"none","typ":"JWT","kid":"a"}"#),
            b64(&format!(
                r#"{{"iss":"{ISS}","aud":"{AUD}","exp":{},"sub":"x"}}"#,
                now() + 300
            ))
        );
        assert!(h.validator.validate(&none).await.is_err());

        // HS256 signed with the public x coordinate as the "secret".
        let mut hdr = Header::new(Algorithm::HS256);
        hdr.kid = Some("a".into());
        let claims = serde_json::json!({"iss": ISS, "aud": AUD, "exp": now() + 300, "sub": "x"});
        let hs = encode(
            &hdr,
            &claims,
            &EncodingKey::from_secret(KEY_A_X.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            h.validator.validate(&hs).await,
            Err(AuthError::InvalidToken("algorithm not allowed"))
        ));
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let h = harness();
        // Signed with key B but claims kid "a".
        let t = mint(KEY_B_PEM, "a", ISS, AUD, now() + 300);
        assert!(matches!(
            h.validator.validate(&t).await,
            Err(AuthError::InvalidToken("bad signature"))
        ));
    }

    #[tokio::test]
    async fn key_rotation_refetches_on_unknown_kid() {
        let h = harness();
        let old = mint(KEY_A_PEM, "a", ISS, AUD, now() + 300);
        h.validator.validate(&old).await.unwrap();
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);

        // IdP rotates: key "b" appears, "a" is retired.
        set_keys(&h.body, &[jwk("b", KEY_B_X, KEY_B_Y)]);
        let fresh = mint(KEY_B_PEM, "b", ISS, AUD, now() + 300);
        h.validator.validate(&fresh).await.unwrap();
        assert_eq!(h.calls.load(Ordering::SeqCst), 2);
        // Retired key no longer verifies.
        assert!(h.validator.validate(&old).await.is_err());
    }

    #[tokio::test]
    async fn unknown_kid_refetch_is_rate_limited() {
        let h = harness();
        let mut cfg = h.validator.config.clone();
        cfg.min_refetch = Duration::from_secs(3600);
        let v = JwtValidator::new(
            cfg,
            FakeFetcher {
                body: h.body.clone(),
                calls: h.calls.clone(),
            },
        );
        let bogus = mint(KEY_A_PEM, "zzz", ISS, AUD, now() + 300);
        for _ in 0..5 {
            assert!(v.validate(&bogus).await.is_err());
        }
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ssrf_urls_rejected() {
        for bad in [
            "http://idp.example.com/jwks",
            "https://127.0.0.1/jwks",
            "https://10.0.0.5/jwks",
            "https://192.168.1.1/jwks",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/jwks",
            "https://[::1]/jwks",
            "https://[fd00::1]/jwks",
            "https://[::ffff:10.0.0.1]/jwks",
            "https://localhost/jwks",
            "https://intranet/jwks",
            "https://db.internal/jwks",
            "https://user:pw@idp.example.com/jwks",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(
                matches!(validate_jwks_url(bad), Err(AuthError::UnsafeJwksUrl(_))),
                "{bad} should be rejected"
            );
        }
        assert!(validate_jwks_url("https://idp.example.com/.well-known/jwks.json").is_ok());
        assert!(JwtConfig::new(ISS, AUD, "http://169.254.169.254/", BTreeMap::new()).is_err());
    }

    #[tokio::test]
    async fn real_fetcher_refuses_loopback_before_connecting() {
        let url = Url::parse("https://127.0.0.1/jwks").unwrap();
        assert!(matches!(
            HttpsJwksFetcher.fetch(&url).await,
            Err(AuthError::UnsafeJwksUrl(_))
        ));
    }

    #[test]
    fn challenge_header_format() {
        let m = "https://mail.example.com/.well-known/oauth-protected-resource";
        assert_eq!(
            www_authenticate(m, None),
            format!("Bearer resource_metadata=\"{m}\"")
        );
        let c = www_authenticate(m, Some(&AuthError::Expired));
        assert!(c.starts_with("Bearer error=\"invalid_token\","));
        // Injection attempt is neutralised.
        assert!(!www_authenticate("x\"\r\ny", None).contains('\n'));
    }

    #[test]
    fn metadata_serialises_per_rfc9728() {
        let m = ProtectedResourceMetadata::new(AUD, ISS, &["mail:read"]);
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["resource"], AUD);
        assert_eq!(v["authorization_servers"][0], ISS);
    }

    #[test]
    fn static_bearer_metadata_names_no_authorization_server() {
        let v = serde_json::to_value(ProtectedResourceMetadata::static_bearer(AUD)).unwrap();
        assert_eq!(v["resource"], AUD);
        assert!(v.get("authorization_servers").is_none(), "{v}");
        assert_eq!(v["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn static_bearer_accepts_only_exact_token() {
        let s = StaticBearer::new("correct-horse", [Action::Read], [account("home")]);
        let p = s.validate("correct-horse").unwrap();
        assert_eq!(p.client_id(), STATIC_BEARER_CLIENT_ID);
        assert_eq!(
            p,
            Principal::new(STATIC_BEARER_CLIENT_ID, [account("home")], [Action::Read])
        );
        assert!(s.validate("correct-horse ").is_err());
        assert!(s.validate("").is_err());
        assert!(s.validate("x").is_err());
    }

    fn app(state: Arc<AuthState>) -> Router {
        async fn whoami(
            Extension(p): Extension<Principal>,
            headers: axum::http::HeaderMap,
        ) -> String {
            format!(
                "{}|{}",
                p.client_id(),
                headers.contains_key(header::AUTHORIZATION)
            )
        }
        Router::new()
            .route("/mcp", get(whoami))
            .layer(from_fn_with_state(state, require_auth))
    }

    fn static_state() -> Arc<AuthState> {
        Arc::new(AuthState {
            authenticator: Arc::new(Authenticator::<FakeFetcher>::Static(StaticBearer::new(
                "s3cret",
                [Action::Read],
                [account("home")],
            ))),
            resource_metadata_url: "https://mail.example.com/.well-known/oauth-protected-resource"
                .into(),
        })
    }

    #[tokio::test]
    async fn middleware_challenges_and_strips_token() {
        let missing = app(static_state())
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let ch = missing.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(ch.contains("resource_metadata="));

        let wrong = app(static_state())
            .oneshot(
                Request::get("/mcp")
                    .header(header::AUTHORIZATION, "Bearer nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let ok = app(static_state())
            .oneshot(
                Request::get("/mcp")
                    .header(header::AUTHORIZATION, "Bearer s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ok.into_body(), 1024).await.unwrap();
        // Principal visible downstream, inbound token not forwarded.
        assert_eq!(&body[..], b"static-bearer|false");
    }
}
