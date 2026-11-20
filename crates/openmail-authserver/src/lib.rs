//! A deliberately small OAuth 2.1 authorization server for ONE owner, so a self-hosted
//! OpenMail can be connected to clients that only speak OAuth (ChatGPT, Claude) without a
//! paid or third-party identity provider.
//!
//! Scope: authorization-code flow with mandatory PKCE (S256), public clients only (no client
//! secrets), RFC 7591 dynamic client registration with an allowlist of redirect hosts, RFC 8414
//! metadata, RFC 8707 `resource` binding, RFC 9207 `iss`, ES256 JWT access tokens and rotating
//! refresh tokens. Not a general IdP: one owner, authenticated by an Argon2id-hashed password,
//! and only the scopes in [`Config::scopes`] (default read-only) can ever be granted.
mod keys;
mod oauth;
mod pages;
mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher as _};
use axum::Router;

pub use oauth::router;

/// Open registration for `minutes` (1 to 60) by writing the window file the server checks.
pub fn open_registration_window(state_dir: &std::path::Path, minutes: u32) -> Result<i64, Error> {
    let until = now() + i64::from(minutes.clamp(1, 60)) * 60;
    std::fs::create_dir_all(state_dir)
        .map_err(|e| Error::Config(format!("state dir: {}", e.kind())))?;
    std::fs::write(state_dir.join(REGISTRATION_WINDOW_FILE), until.to_string())
        .map_err(|e| Error::Config(format!("writing the registration window: {}", e.kind())))?;
    Ok(until)
}

/// Close it immediately.
pub fn close_registration_window(state_dir: &std::path::Path) {
    let _ = std::fs::remove_file(state_dir.join(REGISTRATION_WINDOW_FILE));
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("signing key: {0}")]
    Key(String),
    #[error("oauth store: {0}")]
    Store(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("too many registered clients")]
    TooManyClients,
}

/// Hosts a client may redirect to when none are configured: the assistants this server is
/// meant for. Loopback redirects (native apps) are always allowed on any port.
pub const DEFAULT_REDIRECT_HOSTS: [&str; 5] = [
    "chatgpt.com",
    "chat.openai.com",
    "platform.openai.com",
    "claude.ai",
    "claude.com",
];

/// One hour: long enough to avoid constant refreshes during a conversation, short enough that a
/// leaked access token is of limited use.
pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(3600);
/// Refresh tokens rotate on every use; 30 days of inactivity ends the connection.
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// A user must finish the consent screen within this time.
const PENDING_TTL_SECS: i64 = 600;
/// Authorization codes are redeemed immediately by the client (RFC 6749 suggests <= 10 min).
const CODE_TTL_SECS: i64 = 60;
/// Bound on in-memory pending authorizations and codes (unauthenticated endpoints feed them).
const MAX_IN_FLIGHT: usize = 1000;
/// Failed owner-password attempts allowed per window before sign-in pauses for everyone.
/// Wrong passwords allowed on ONE consent page before it is destroyed.
pub(crate) const MAX_TX_ATTEMPTS: u32 = 5;
/// Global pause: high enough that an anonymous attacker burning pages cannot easily lock the
/// owner out, low enough to make online guessing hopeless (each page also dies after 5).
const MAX_LOGIN_FAILURES: usize = 30;
/// Most consent pages one client may have open at once.
pub(crate) const MAX_PENDING_PER_CLIENT: usize = 20;
/// File in the state directory holding the unix time until which registration is open.
const REGISTRATION_WINDOW_FILE: &str = "registration-open-until";
const LOGIN_WINDOW_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct Config {
    /// Public origin, e.g. `https://mail-mcp.example.com` (no trailing slash).
    pub issuer: String,
    /// The protected resource tokens are minted for (the MCP endpoint URL).
    pub resource: String,
    /// PHC string from [`hash_password`].
    pub owner_password_hash: String,
    pub state_dir: PathBuf,
    /// Scopes that may be granted; requests for others are refused.
    pub scopes: Vec<String>,
    pub allowed_redirect_hosts: Vec<String>,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
}

/// Hash an owner password for `Config::owner_password_hash` (Argon2id, random salt).
pub fn hash_password(password: &str) -> Result<String, Error> {
    if password.chars().count() < 12 {
        return Err(Error::Config(
            "the owner password needs at least 12 characters".into(),
        ));
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| Error::Config(format!("hashing failed: {e}")))
}

pub(crate) struct Pending {
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub scope: String,
    pub state: Option<String>,
    pub expires: i64,
    /// Wrong-password attempts on this one consent page; it is dropped after a few.
    pub attempts: u32,
}

pub(crate) struct Code {
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub scope: String,
    pub expires: i64,
}

pub struct AuthServer {
    pub(crate) cfg: Config,
    pub(crate) key: keys::SigningKey,
    pub(crate) store: store::Store,
    pub(crate) pending: Mutex<HashMap<String, Pending>>,
    pub(crate) codes: Mutex<HashMap<String, Code>>,
    failures: Mutex<Vec<i64>>,
}

impl std::fmt::Debug for AuthServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServer")
            .field("issuer", &self.cfg.issuer)
            .finish_non_exhaustive()
    }
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 256 random bits, base64url. A failing OS RNG is an error: a predictable token is never acceptable.
pub(crate) fn random_token() -> Result<String, Error> {
    use base64::Engine as _;
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| Error::Key("OS random source unavailable".into()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

impl AuthServer {
    /// Open (creating on first use) the signing key and database in `cfg.state_dir`.
    pub fn open(cfg: Config) -> Result<Arc<Self>, Error> {
        if !cfg.issuer.starts_with("https://") || cfg.issuer.ends_with('/') {
            return Err(Error::Config(
                "issuer must be an https origin without a trailing slash".into(),
            ));
        }
        PasswordHash::new(&cfg.owner_password_hash)
            .map_err(|_| Error::Config("owner password hash is not a valid PHC string".into()))?;
        if cfg.scopes.is_empty() {
            return Err(Error::Config("at least one scope must be grantable".into()));
        }
        std::fs::create_dir_all(&cfg.state_dir)
            .map_err(|e| Error::Config(format!("state dir: {}", e.kind())))?;
        Ok(Arc::new(Self {
            key: keys::SigningKey::load_or_create(&cfg.state_dir)?,
            store: store::Store::open(&cfg.state_dir.join("oauth.db"))?,
            pending: Mutex::default(),
            codes: Mutex::default(),
            failures: Mutex::default(),
            cfg,
        }))
    }

    /// Public keys for the validator side (and the `jwks_uri` endpoint).
    pub fn jwks_json(&self) -> Vec<u8> {
        self.key.jwks_json().to_vec()
    }

    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    pub fn resource(&self) -> &str {
        &self.cfg.resource
    }

    pub fn scopes(&self) -> &[String] {
        &self.cfg.scopes
    }

    /// `true` while sign-in is paused after repeated failures.
    pub(crate) fn login_locked(&self) -> bool {
        let t = now();
        let mut f = lock(&self.failures);
        f.retain(|&at| at > t - LOGIN_WINDOW_SECS);
        f.len() >= MAX_LOGIN_FAILURES
    }

    pub(crate) fn note_login_failure(&self) {
        lock(&self.failures).push(now());
    }

    pub(crate) fn clear_login_failures(&self) {
        lock(&self.failures).clear();
    }

    pub(crate) fn in_flight_full(&self) -> bool {
        let t = now();
        let mut p = lock(&self.pending);
        p.retain(|_, v| v.expires > t);
        let mut c = lock(&self.codes);
        c.retain(|_, v| v.expires > t);
        p.len() >= MAX_IN_FLIGHT || c.len() >= MAX_IN_FLIGHT
    }

    /// Dynamic client registration is open while no client has ever completed a login (first
    /// connection), or inside a window the owner opened on the server
    /// (`openmail-mcp oauth registration open`). Otherwise anyone on the internet could mint
    /// a client that looks like the owner's assistant and phish the consent page.
    pub(crate) fn registration_open(&self) -> bool {
        if matches!(self.store.any_client_logged_in(), Ok(false)) {
            return true;
        }
        let until = std::fs::read_to_string(self.cfg.state_dir.join(REGISTRATION_WINDOW_FILE))
            .ok()
            .and_then(|t| t.trim().parse::<i64>().ok())
            .unwrap_or(0);
        until > now()
    }

    pub(crate) fn pending_ttl() -> i64 {
        PENDING_TTL_SECS
    }

    pub(crate) fn code_ttl() -> i64 {
        CODE_TTL_SECS
    }
}

/// Convenience for embedding: the router with its state applied.
pub fn into_router(server: Arc<AuthServer>) -> Router {
    router(server)
}
