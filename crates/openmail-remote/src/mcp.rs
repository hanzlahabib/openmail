//! Mounts rmcp's Streamable HTTP service and binds each MCP session to the
//! principal that created it.
//!
//! The authenticated [`openmail_security::Principal`] travels to tool calls as a
//! request extension: rmcp copies the request's `http::request::Parts`
//! (including extensions) into every handler's `RequestContext`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use openmail_mcp::PrincipalResolver;
use openmail_security::Principal;
use rmcp::ServerHandler;
pub use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

/// Reads the principal that the auth middleware attached to the HTTP request.
/// Fails closed: no attached principal (auth not configured, or a non-HTTP
/// request) resolves to `None`, which the MCP server turns into a denial.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpPrincipalResolver;

impl PrincipalResolver for HttpPrincipalResolver {
    fn resolve(&self, extensions: &rmcp::model::Extensions) -> Option<Principal> {
        extensions
            .get::<Parts>()?
            .extensions
            .get::<Principal>()
            .cloned()
    }
}

/// Header carrying the MCP session id (MCP Streamable HTTP spec).
const SESSION_HEADER: &str = "mcp-session-id";
/// Live sessions tracked per process. Each costs one map entry plus rmcp's own
/// session state; the cap stops a single client from exhausting memory by
/// opening sessions without bound.
pub const MAX_SESSIONS: usize = 1024;

/// Which principal owns which session id.
#[derive(Debug, Default)]
struct SessionOwners {
    owners: Mutex<HashMap<String, String>>,
}

impl SessionOwners {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        // A poisoned lock only means another request panicked; the map is still valid.
        self.owners.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Reject cross-principal session use and record new sessions. Runs after
/// authentication, so the principal is always present when auth is configured.
async fn bind_sessions(
    State(owners): State<Arc<SessionOwners>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(caller) = req
        .extensions()
        .get::<Principal>()
        .map(|p| p.client_id().to_owned())
    else {
        // Loopback no-auth mode: there is no identity to bind to.
        return next.run(req).await;
    };
    let presented = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let is_delete = req.method() == Method::DELETE;

    match &presented {
        Some(id) => {
            let owner = owners.lock().get(id).cloned();
            // Same answer as an unknown session so ids are not an oracle.
            if owner.as_deref().is_some_and(|o| o != caller) {
                tracing::warn!("session id presented by a different principal");
                return (StatusCode::NOT_FOUND, "session not found").into_response();
            }
        }
        None if owners.lock().len() >= MAX_SESSIONS => {
            return (StatusCode::SERVICE_UNAVAILABLE, "too many sessions").into_response();
        }
        None => {}
    }

    let response = next.run(req).await;

    if presented.is_none() {
        if let Some(id) = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|v: &HeaderValue| v.to_str().ok())
        {
            owners.lock().insert(id.to_owned(), caller);
        }
    } else if is_delete
        && response.status().is_success()
        && let Some(id) = presented
    {
        owners.lock().remove(&id);
    }
    response
}

/// Build the MCP router for `factory`, ready to hand to
/// [`crate::http::serve_tls`]. `config.allowed_hosts` must list the public
/// host name(s) clients use (rmcp defaults to loopback only).
pub fn mcp_router<S>(
    factory: impl Fn() -> Result<S, io::Error> + Send + Sync + 'static,
    config: StreamableHttpServerConfig,
) -> Router
where
    S: ServerHandler + Send + 'static,
{
    let service =
        StreamableHttpService::new(factory, Arc::new(LocalSessionManager::default()), config);
    Router::new()
        .fallback_service(service)
        .layer(middleware::from_fn_with_state(
            Arc::new(SessionOwners::default()),
            bind_sessions,
        ))
}
