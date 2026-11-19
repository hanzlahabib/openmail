//! Who may call the tools and how often (security review F1).
//!
//! Every tool goes through `OpenMailServer::authorized`, which consults the `Authorizer` and the
//! rate limiter before any backend call. The stdio transport has exactly one principal, built
//! here; an HTTP transport will construct one per request and call `build_server_with`.
use openmail_core::config::Config;
use openmail_security::{Action, Principal, RateLimitConfig};

/// Client id of the single local stdio peer, for audit logs.
const STDIO_CLIENT_ID: &str = "stdio";

/// Global burst/refill: generous for an interactive model session, but bounded so a runaway
/// agent loop cannot hammer every mail server at once.
const GLOBAL_BURST: u32 = 120;
const GLOBAL_REFILL_PER_SEC: u32 = 20;
/// Per-account burst/refill: IMAP servers commonly throttle or ban around 10-20 logins/s.
const ACCOUNT_BURST: u32 = 60;
const ACCOUNT_REFILL_PER_SEC: u32 = 10;

/// Token-bucket settings for the server's limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub global: RateLimitConfig,
    pub per_account: RateLimitConfig,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            global: RateLimitConfig {
                capacity: GLOBAL_BURST,
                refill_per_sec: GLOBAL_REFILL_PER_SEC,
            },
            per_account: RateLimitConfig {
                capacity: ACCOUNT_BURST,
                refill_per_sec: ACCOUNT_REFILL_PER_SEC,
            },
        }
    }
}

/// The principal for the stdio transport: the local user who launched the process. It may read
/// every configured account and nothing else; write scopes are never granted implicitly.
pub fn stdio_principal(config: &Config) -> Principal {
    Principal::new(
        STDIO_CLIENT_ID,
        config.accounts.iter().map(|a| a.id.clone()),
        [Action::Read],
    )
}

/// Resolves the calling principal from the transport's per-request data (HTTP bearer auth).
///
/// `extensions` is the rmcp request-context bag. For Streamable HTTP rmcp inserts the original
/// `http::request::Parts` into it, so an HTTP resolver reads headers or middleware-set extensions
/// via `extensions.get::<http::request::Parts>()`. `None` means "unauthenticated" and every tool
/// call is then denied before any backend call. stdio never uses a resolver: it keeps its fixed
/// principal ([`stdio_principal`]).
pub trait PrincipalResolver: Send + Sync + 'static {
    fn resolve(&self, extensions: &rmcp::model::Extensions) -> Option<Principal>;
}
