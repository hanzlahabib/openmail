# ChatGPT integration: local verification record

Date: 2026-11-19. Build: `openmail-mcp 0.1.0` (branch `integration`, debug build).
**A real ChatGPT connection was NOT tested** (needs a public HTTPS endpoint and the owner's
account). Nothing is published to any directory. ChatGPT-native scheduling is not relied on.
This file records only what was run locally with generic MCP clients.

## Rig
- GreenMail via `scripts/test-infra.sh up` (alice/bob, seeded). GreenMail's IMAPS uses its own cert
  and the client has no insecure-TLS option, so a ~20-line Python TLS proxy (private test CA,
  `localhost`, port 13994 -> 13143) fronts IMAP; the binary trusts it via `SSL_CERT_FILE=ca.pem`.
- Test CA + leaf cert for `localhost`/`127.0.0.1` (generated with Python `cryptography`, 2-day
  validity), 32-byte random token file mode 600. All scratch files lived outside the repo.
- Config: two accounts `alice`, `bob`, `credential = { kind = "env" }`, default `read_only` (no write permissions).
- Server (static-bearer mode):
  ```sh
  OPENMAIL_HTTP_TLS_CERT=srv.pem OPENMAIL_HTTP_TLS_KEY=srv.key \
  OPENMAIL_HTTP_AUTH_TOKEN_FILE=token OPENMAIL_HTTP_PUBLIC_URL=https://localhost:8765 \
  OPENMAIL_HTTP_STATIC_ACTIONS=read SSL_CERT_FILE=ca.pem OPENMAIL_T42_ALICE=... OPENMAIL_T42_BOB=... \
  openmail-mcp serve --transport http --bind 127.0.0.1:8765 --config config.toml
  ```
- Clients: (1) a Python `httpx` script speaking raw Streamable HTTP (initialize, initialized,
  tools/list, tools/call); (2) **MCP Inspector CLI** `npx @modelcontextprotocol/inspector@0.17.2 --cli
  https://localhost:8765/mcp --transport http --header "Authorization: Bearer $TOKEN" --method tools/list`
  (user-local via npx, `NODE_EXTRA_CA_CERTS=ca.pem`). No rmcp client was run against the real binary
  here; rmcp is the client in `crates/openmail-remote/tests/https_e2e.rs` (below).

## Results (actual output, trimmed)
| # | Check | Result |
|---|---|---|
| 1 | `serve --transport http` without TLS/auth env | exit 1: `error: refusing --transport http without TLS: set OPENMAIL_HTTP_TLS_CERT and OPENMAIL_HTTP_TLS_KEY` |
| 2 | Binds loopback only; plain HTTP not served | `ss -ltn`: `127.0.0.1:8765`; `curl http://localhost:8765/healthz` -> connection failure (000) |
| 3 | `GET /healthz`, `/readyz` over TLS | 200 `ok`, 200; unknown path 404 |
| 4 | No token | `401`, `www-authenticate: Bearer resource_metadata="https://localhost:8765/.well-known/oauth-protected-resource"` |
| 5 | Wrong token | `401`, `www-authenticate: Bearer error="invalid_token", resource_metadata="..."` |
| 6 | `GET /.well-known/oauth-protected-resource` (no token) | 200 `{"resource":"https://localhost:8765/mcp","authorization_servers":["https://localhost:8765/"],"scopes_supported":[],"bearer_methods_supported":["header"]}` |
| 7 | `Origin: https://evil.example` with valid token / without token | `403 origin not allowed` in both cases |
| 8 | `Host: evil.example` with valid token (DNS rebinding) | `403 Forbidden: Host header is not allowed` |
| 9 | `initialize` with token | 200, `mcp-session-id` header, SSE body, `protocolVersion 2025-03-26`, `serverInfo openmail-mcp 0.1.0` (Inspector negotiated 2025-11-25) |
| 10 | `tools/list` (Python client and Inspector CLI, same result) | 11 tools, all read: `mail_get_attachment, mail_get_folder_status, mail_get_headers, mail_get_message, mail_get_thread, mail_list_accounts, mail_list_attachments, mail_list_folders, mail_list_messages, mail_search_messages, mail_test_connection`. No draft/send/delete/organize tool (accounts have no write permissions). Every tool has `readOnlyHint: true`. |
| 11 | Read tools against real IMAP (GreenMail) | `mail_list_accounts` returns alice+bob with `read_only:true`, all permissions false; `mail_list_messages {account:alice,folder:INBOX,limit:2}` returns real seeded messages with `_notice` untrusted-content banner; `mail_list_folders alice` returns INBOX |
| 12 | Unknown account | `isError`, `ACCESS_DENIED: access to account 'nope' denied` |
| 13 | Unknown/foreign session id | `404 Session not found` |
| 14 | Inspector without a token | `Failed to connect to MCP server: Streamable HTTP error: Error POSTing to endpoint` (401) |

Static-bearer mode grants **every configured account**, so "token for a restricted principal sees
only its accounts" cannot be shown there. It needs JWT mode, whose JWKS fetch refuses loopback,
non-https and single-label hosts (SSRF guard, `validate_jwks_url`), so JWT mode cannot be run
against a local JWKS through the real binary. That property is covered in-process instead:
`cargo test -p openmail-remote --test https_e2e` -> 9 passed, including
`principal_limited_to_one_account_cannot_reach_the_other`, `a_session_cannot_be_used_by_another_principal`,
`disallowed_origin_is_rejected_even_with_a_valid_token`, `unauthenticated_and_bad_tokens_get_401_with_challenge`,
`protected_resource_metadata_and_probes_need_no_token`, `plaintext_http_is_not_served_and_untrusted_ca_is_refused`
(real rmcp client, real TLS, ES256 JWTs against a fixed JWKS; backend is an in-memory double).
Expired / wrong-audience JWT rejection is unit-tested in `openmail-remote/src/auth.rs`, not run via the binary.

## Findings from this run
1. The protected-resource metadata in static mode names **itself** as `authorization_servers`;
   there is no authorization server behind it and `/.well-known/oauth-authorization-server`
   returns 404. An OAuth client following the metadata would dead-end. In JWT mode the issuer
   comes from config.
2. The `401` challenge carries `resource_metadata` but no `scope` parameter.
3. Nothing was verified for: OAuth authorization-code flow, dynamic client registration / CIMD,
   token refresh/revocation, a real IdP, a public hostname/proxy, `/mcp` behind Caddy/nginx.

## Official OpenAI documentation re-check (fetched 2026-11-19)
Sources: <https://developers.openai.com/apps-sdk/build/auth>, <https://developers.openai.com/api/docs/guides/developer-mode>,
<https://developers.openai.com/apps-sdk/deploy/connect-chatgpt> (all HTTP 200). The Help Center article
<https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta> returned **403**, so plan/role availability is UNVERIFIED.

| Claim | Status |
|---|---|
| Self-hosted remote MCP reachable via public HTTPS (or OpenAI "Secure MCP Tunnel"); Streamable HTTP "typically at `/mcp`"; docs also list SSE | Confirmed (connect-chatgpt, developer-mode) |
| Auth choices in the add-server UI: OAuth, No authentication, OAuth or no authentication | Confirmed |
| ChatGPT **cannot present custom API keys / static bearer tokens**, mTLS of your own, or machine-to-machine grants | Confirmed (auth page). **OpenMail's static-bearer mode therefore cannot be used from ChatGPT.** |
| OAuth 2.1 per MCP authorization spec, RFC 9728 metadata (or the `WWW-Authenticate` URL), PKCE `S256`, `resource` parameter copied into token audience, issuer/audience/expiry/scope validation per request | Confirmed |
| Client registration: CIMD preferred, DCR still supported, or pre-registered static client id/secret | Confirmed. OpenMail ships **no authorization server**: the IdP must provide one of these. |
| AS must publish `/.well-known/oauth-authorization-server` or `openid-configuration`, include `S256`; RFC 9207 `iss` in authorization responses | Confirmed (IdP duty, not OpenMail's) |
| Redirect URI: `https://chatgpt.com/connector_platform_oauth_redirect` (stable, when RFC 9207 is met) else `https://chatgpt.com/connector/oauth/{callback_id}`; copy the exact one shown in ChatGPT | Confirmed; allowlist at the IdP |
| Tool-level linking UI needs `securitySchemes` tool metadata and `_meta["mcp/www_authenticate"]` in tool errors | Documented by OpenAI; **OpenMail does not emit either** (not needed for connector-level OAuth, but ChatGPT will not show per-tool linking UI) |
| Tools without `readOnlyHint` are treated as write actions and need confirmation | Confirmed; all current OpenMail tools set `readOnlyHint: true` |
| ChatGPT presents an OpenAI-managed mTLS client cert and publishes egress IP ranges | Documented; OpenMail does not check it (no mTLS) |
| Plans/roles allowed to add custom MCP servers; Plus availability | UNVERIFIED (help article 403; docs only say workspace permissions and Lockdown apply, web only) |
| Data retention / training terms for tool output | UNVERIFIED (not stated on fetched pages) |
| Scheduled ChatGPT tasks calling custom MCP tools | UNVERIFIED, not relied on |
| Docs now call custom servers "plugins" (chatgpt.com/plugins) | As reported by fetched pages; UI wording may differ per plan |

## Conclusion
The HTTP edge behaves as designed against two generic MCP clients, with real IMAP behind it.
Whether ChatGPT can use it depends on an external OAuth authorization server (OpenMail provides
none and its static token mode is incompatible with ChatGPT). Real ChatGPT connection: **not tested**.
