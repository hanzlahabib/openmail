# Protocol and client compatibility

Researched 2026-11-19 (T29). Source of truth for the remote/ChatGPT work.

**Method and confidence.** Facts below come from official-domain web search results (modelcontextprotocol.io, github.com/modelcontextprotocol, developers.openai.com, help.openai.com, code.claude.com, support.claude.com, claude.com/docs, cursor.com, code.visualstudio.com). Each search returned a summary of those pages; full pages were not fetched and read end to end. Treat every row as "reported by official page, re-check the linked page before depending on it". Anything not found is marked **UNVERIFIED**. Re-verify before each release; these docs move quickly.

## 1. MCP specification

| Fact | Source (checked 2026-11-19) |
|---|---|
| Latest revision is **2026-07-28**, listed as current on the official versioning page. Previous revision is 2025-11-25. | https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning ; https://modelcontextprotocol.io/specification/2026-07-28/changelog |
| 2025-03-26 introduced Streamable HTTP and the OAuth 2.1 authorization framework. | https://modelcontextprotocol.io/specification/2025-03-26/changelog |
| 2026-07-28 Streamable HTTP: one POST endpoint, no GET stream; protocol-level sessions and the `Mcp-Session-Id` header removed; `Last-Event-ID` resumability removed (clients re-issue a request if the stream breaks); requests carry `Mcp-Method` and `Mcp-Name` headers; server-initiated requests (sampling, elicitation) are embedded in results instead of separate streams. | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http ; changelog above |
| 2026-07-28 authorization: servers SHOULD include RFC 9207 `iss`, clients MUST validate it before redeeming a code; clients MUST set `application_type` in Dynamic Client Registration; client credentials are bound to the issuing authorization server and MUST NOT be reused across servers; DCR formally deprecated in favour of Client ID Metadata Documents (still works for compatibility). | changelog above ; https://blog.modelcontextprotocol.io/posts/2026-07-28/ |

Design implication (our decision, not a spec quote): the HTTP edge must keep serving clients that still speak 2025-03-26 / 2025-11-25 (sessions, GET stream) while the newest revision drops them. The exact version-negotiation behaviour of the new revision is **UNVERIFIED** (not read in detail).

## 2. rmcp (official Rust SDK)

| Fact | Source |
|---|---|
| rmcp 3.x implements the stable 2026-07-28 spec and stays compatible with 2025-11-25 and earlier. | https://github.com/modelcontextprotocol/rust-sdk |
| Per the 3.0.0 migration guide, `ProtocolVersion::LATEST` still points at 2025-11-25, so 2026-07-28 must be selected explicitly. The README wording differs ("newest stable"); the migration guide is more specific. **Conflict, verify against the pinned crate source.** | https://github.com/modelcontextprotocol/rust-sdk/discussions/969 |
| MSRV 1.88 per migration guide. | same |
| GitHub releases showed `rmcp-v3.9.0` as latest tag (5 Nov). docs.rs `latest` page showed 3.6.0 (stale). Check crates.io for the real current version. | https://github.com/modelcontextprotocol/rust-sdk/releases ; https://docs.rs/crate/rmcp/latest |

## 3. ChatGPT (OpenAI)

| Fact | Source |
|---|---|
| Server must be at a stable, publicly reachable **HTTPS** endpoint; Streamable HTTP, typically `/mcp`. Developer-mode docs list SSE and streaming HTTP as supported. A private server needs a public HTTPS proxy. | https://developers.openai.com/plugins/build/mcp-server ; https://developers.openai.com/api/docs/guides/developer-mode |
| Auth options when adding a custom server: OAuth, no authentication, or either. Servers exposing customer data or write actions should authenticate. | https://developers.openai.com/api/docs/guides/developer-mode ; https://developers.openai.com/plugins/build/auth.md |
| OAuth must follow the MCP authorization spec: protected-resource metadata at a well-known URL; `401` with `WWW-Authenticate` when no valid token; authorization-code flow with PKCE `S256`; `resource` parameter echoed through the flow; server verifies audience and scopes on every call. | https://developers.openai.com/plugins/build/auth.md |
| Plans: custom MCP servers / full MCP on **Business and Enterprise/Edu** (web). Enterprise/Edu: admins/owners create connections, RBAC can delegate; developer mode is a separate workspace permission there. Business: admins/owners create and publish workspace apps. **Pro**: reported as read/fetch-only custom connections. **Plus**: no source found for custom servers (**UNVERIFIED**; prebuilt partner connectors only). | https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt ; https://help.openai.com/en/articles/12515353-building-with-the-apps-sdk |
| Developer mode is reportedly no longer required to add a custom server from Plugins (still a separate permission on Enterprise/Edu). | help article above |
| Secure MCP Tunnel lets a private server connect without inbound ports; private testing only, not for public distribution. | https://developers.openai.com/api/docs/guides/secure-mcp-tunnels |
| Directory/public submission: requires the stable public HTTPS endpoint. Review process, branding, and any other submission requirements: **UNVERIFIED** (not read). Product naming in OpenAI docs shifted between "Apps SDK" and "plugins"; some pages were 400+ days old. | https://developers.openai.com/apps-sdk/deploy ; https://developers.openai.com/plugins/deploy/connect-chatgpt |

Implication: a local-only stdio OpenMail cannot be reached by ChatGPT; ChatGPT needs the remote HTTPS edge with OAuth (PKCE S256, protected-resource metadata, resource indicator, audience check).

## 4. Other clients

| Client | stdio | Remote | Source |
|---|---|---|---|
| Claude Code | Yes (child process; not restarted on crash). | `--transport http` recommended; SSE deprecated; HTTP/SSE reconnect with exponential backoff (5 attempts, 1s doubling). `.mcp.json` entries need explicit `"type": "http"`. | https://code.claude.com/docs/en/mcp |
| Claude Desktop | Yes, local servers; packaged as `.mcpb` desktop extensions (one-click install). Directory listings for extensions reported deprecated. Admin may disable extensions on third-party deployments. | Custom connectors by URL on Free (1 connector), Pro, Max, Ultra, Team, Enterprise. Connections originate from Anthropic's cloud, so the server must be publicly reachable. | https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop ; https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp ; https://claude.com/docs/connectors/building/mcpb |
| Cursor | Yes (`command`, `args`, `env`, `envFile`). | Streamable HTTP and SSE, OAuth (auth code + PKCE, DCR as public client; static `auth` object with `CLIENT_ID` for non-DCR providers). Cloud agents: HTTP or stdio only, no SSE. Config `.cursor/mcp.json` / `~/.cursor/mcp.json`. | https://cursor.com/docs/mcp |
| VS Code | Yes (`type: "stdio"`). | Tries Streamable HTTP, falls back to SSE; SSE deprecated. Config `.vscode/mcp.json` (`servers` key) with `${input:...}` secrets; pre-registered OAuth client ID since 1.123. | https://code.visualstudio.com/docs/agents/reference/mcp-configuration |

## 5. Not done / UNVERIFIED

- No page was fetched in full; all rows rest on search summaries of official pages.
- 2026-07-28 version negotiation and backward-compat rules for servers: UNVERIFIED.
- Which protocol version rmcp 3.x actually advertises by default in the pinned version: conflicting sources, check the crate.
- ChatGPT Plus/Pro exact limits, current plan matrix, and public directory submission/review requirements: UNVERIFIED.
- Claude Desktop remote-connector OAuth specifics (callback URLs, DCR vs CIMD support): not researched.
- ChatGPT/Claude OAuth callback URL allowlists: not researched.
