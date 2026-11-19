# openmail-remote notes

## T12 http.rs (Streamable-HTTP edge)
Versions: axum 0.8.9, tower-http 0.6.11 (`limit`, `timeout`; 0.7 changes layer APIs), rmcp 3.11.0 (cached; the rmcp service is mounted by the caller at `/mcp`, not linked here).
MCP spec points implemented: Origin validation on every request carrying `Origin` (403), bearer auth with `WWW-Authenticate: Bearer` (401), loopback-only bind unless auth configured.
Not done: Host-header allowlist, rmcp `StreamableHttpService` wiring (belongs to the serve command), shutdown grace deadline, RFC 9728 protected-resource metadata endpoint, `Forwarded` (RFC 7239) header.
