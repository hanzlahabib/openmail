# openmail-remote notes

## T12 http.rs (Streamable-HTTP edge)
Versions: axum 0.8.9, tower-http 0.6.11 (`limit`, `timeout`; 0.7 changes layer APIs), rmcp 3.11.0 (cached; the rmcp service is mounted by the caller at `/mcp`, not linked here).
MCP spec points implemented: Origin validation on every request carrying `Origin` (403), bearer auth with `WWW-Authenticate: Bearer` (401), loopback-only bind unless auth configured.
Not done: Host-header allowlist, rmcp `StreamableHttpService` wiring (belongs to the serve command), shutdown grace deadline, RFC 9728 protected-resource metadata endpoint, `Forwarded` (RFC 7239) header.

## T37 bridge (HTTP actually serves)
- rmcp 3.11.0 Streamable HTTP server: `transport-streamable-http-server` feature; `StreamableHttpService::new(factory, Arc<LocalSessionManager>, StreamableHttpServerConfig)` is a tower `Service`, mounted with `Router::fallback_service`. The factory takes no request, so identity is NOT per service instance: rmcp copies each request's `http::request::Parts` (with our request extensions) into `RequestContext.extensions`, and `mcp::HttpPrincipalResolver` (implements `openmail_mcp::PrincipalResolver`) reads the `openmail_security::Principal` the auth middleware attached. No principal => resolver returns `None` => every tool denied.
- rmcp checks `Host` itself (default loopback only): `with_allowed_hosts` must list the public host. Our `http.rs` still does the `Origin` check first.
- F4 fixed: `auth.rs` no longer defines its own Principal; scope strings map to `security::Action`, mapped accounts are validated `AccountId`s (invalid ids in the scope mapping are dropped with a warning).
- `mcp::bind_sessions` records session id -> principal client id on the initialize response and answers 404 when another principal presents that id (rmcp alone accepts any valid session id from any authenticated caller). Capped at `MAX_SESSIONS`. Two tokens sharing one `client_id` share sessions.
- TLS: `tls::TlsListener` is an axum `Listener` (ring provider, TLS 1.2/1.3, ALPN http/1.1); handshakes run in spawned tasks with a 10 s deadline. `ClientAddr` newtype carries the peer address because orphan rules forbid `Connected<..TlsListener> for SocketAddr`.
- Shutdown: `serve_listener` caps the graceful drain at `SHUTDOWN_GRACE` (SSE streams never end on their own); the CLI also cancels rmcp's cancellation token.
- Tests: `tests/https_e2e.rs` = real `OpenMailServer` + real rmcp client over HTTPS on loopback (rcgen cert, ES256 JWTs against a fixed JWKS). Backend is an in-memory double: no real IMAP behind HTTP was exercised.
- Not done: JWKS endpoint of a real IdP, dynamic client registration, mTLS, HTTP/2, `Forwarded` (RFC 7239), per-principal rate limiting beyond the IP bucket + per-account limiter in openmail-mcp, hot reload of the TLS cert (restart to rotate), brief/send tools over HTTP not specifically tested.
