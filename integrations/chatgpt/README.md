# Connecting OpenMail MCP to ChatGPT

**Status: server side verified locally; ChatGPT connection NOT tested, NOT PUBLISHED.** Nobody has
connected a live ChatGPT workspace to this server (that needs a public HTTPS endpoint and an
OAuth authorization server, plus an owner account). The HTTP endpoint itself was exercised with
generic MCP clients against real IMAP: see [VERIFICATION.md](VERIFICATION.md) (2026-11-19). OpenAI
claims below were re-checked against official OpenAI pages on 2026-11-19 (URLs in VERIFICATION.md);
anything not confirmable is marked UNVERIFIED. OpenMail is **not** listed in any ChatGPT directory,
and ChatGPT-native scheduling is not relied on (see [Briefs](#briefs-and-scheduling)).

## Reference deployment (2026-11-20)

A pre-release build runs at `https://openmail.hanzla.com/mcp` on the maintainer's VPS: unprivileged
`openmail` system user, hardened systemd unit (`docs/deployment/REMOTE.md`), in-process TLS on
`127.0.0.1:8765`, LiteSpeed reverse proxy with a Let's Encrypt certificate. Static-bearer mode is
active (usable by Claude/Cursor/curl, **not** by ChatGPT). Verified from the public internet:
valid TLS, `/healthz` 200, `/mcp` 401 without a token, MCP `initialize` OK with the token.
The single configured account is a read-only placeholder until its password is set.

**Remaining for ChatGPT**: an OAuth 2.1 authorization server (the one thing OpenMail does not ship), then switch the
service from token mode to JWT mode:

```bash
# /etc/openmail/env: remove OPENMAIL_HTTP_AUTH_TOKEN_FILE, add (values from your IdP)
OPENMAIL_HTTP_JWT_ISSUER=https://<idp>/
OPENMAIL_HTTP_JWT_AUDIENCE=https://openmail.hanzla.com/mcp
OPENMAIL_HTTP_JWT_JWKS_URL=https://<idp>/.well-known/jwks.json
OPENMAIL_HTTP_JWT_SCOPE_ACCOUNTS='mail:read=main'
systemctl restart openmail-mcp
```

Then add `https://openmail.hanzla.com/mcp` as a custom MCP server in ChatGPT (developer mode), choose OAuth, allowlist
the redirect URI ChatGPT shows at the IdP, and run [TEST_CHECKLIST.md](TEST_CHECKLIST.md).

## What ChatGPT needs, and what OpenMail has

| ChatGPT requirement (OpenAI docs, 2026-11-19) | OpenMail |
|---|---|
| Public HTTPS Streamable HTTP endpoint, typically `/mcp` (SSE also listed), or OpenAI's "Secure MCP Tunnel" for private servers | `openmail-mcp serve --transport http` serves `POST/GET/DELETE /mcp` over in-process TLS and refuses to start without TLS and auth. You provide the public name (reverse proxy re-encrypting to the upstream, see `docs/deployment/REMOTE.md`). Locally verified; no public deployment tested. |
| Auth options in ChatGPT: OAuth, No authentication, or mixed. ChatGPT **cannot send custom API keys / static bearer tokens** | OpenMail's static bearer token mode (`OPENMAIL_HTTP_AUTH_TOKEN_FILE`) is **incompatible with ChatGPT**; it is for other clients (curl, Inspector, Claude, VS Code). For ChatGPT use JWT mode. "No authentication" must not be used for a mailbox. |
| OAuth 2.1 per MCP authorization spec: RFC 9728 metadata, `WWW-Authenticate` challenge, auth code + PKCE `S256`, `resource` param copied into token audience, per-request issuer/audience/expiry/scope checks | OpenMail is the **resource server only**. It serves `/.well-known/oauth-protected-resource`, answers 401 with `WWW-Authenticate: Bearer resource_metadata="..."`, and in JWT mode validates iss/aud/exp/scopes (ES/RS/PS/EdDSA) against the IdP's JWKS. It runs **no authorization server**: you need an external one that publishes `/.well-known/oauth-authorization-server` (or OIDC discovery) with `S256`, issues tokens whose `aud` is exactly `https://<host>/mcp`, and supports CIMD, DCR, or a pre-registered client id/secret entered in ChatGPT. |
| ChatGPT redirect URI to allowlist at the IdP | `https://chatgpt.com/connector_platform_oauth_redirect` (or the `.../connector/oauth/{callback_id}` URL ChatGPT shows you); copy the exact value from ChatGPT. |
| Tool metadata: tools lacking `readOnlyHint` are treated as write actions | All current OpenMail tools set `readOnlyHint: true`. OpenMail does not emit `securitySchemes` / `_meta["mcp/www_authenticate"]`, so ChatGPT will not show a per-tool sign-in UI; connector-level OAuth is what applies. |
| Plan availability for custom MCP servers | UNVERIFIED (OpenAI help article returned 403; docs only say workspace permissions and Lockdown apply, web only). |

## Steps (end to end not tested)

1. **Config.** Keep every account read-only (the default, no write permissions).
   ```toml
   [[account]]
   id = "work"
   read_only = true
   ```
2. **Public HTTPS + JWT mode** (not the token file; ChatGPT cannot send it):
   ```bash
   OPENMAIL_HTTP_TLS_CERT=... OPENMAIL_HTTP_TLS_KEY=... \
   OPENMAIL_HTTP_PUBLIC_URL=https://mail-mcp.example.com \
   OPENMAIL_HTTP_JWT_ISSUER=https://idp.example.com/ \
   OPENMAIL_HTTP_JWT_AUDIENCE=https://mail-mcp.example.com/mcp \
   OPENMAIL_HTTP_JWT_JWKS_URL=https://idp.example.com/.well-known/jwks.json \
   OPENMAIL_HTTP_JWT_SCOPE_ACCOUNTS='mail:read=work' \
   openmail-mcp serve --transport http --bind 127.0.0.1:8765 --config ~/.config/openmail-mcp/config.toml
   ```
   The JWKS URL must be a public https host (loopback, private and single-label hosts are refused).
   Put the proxy in front per `docs/deployment/REMOTE.md`. For private testing without inbound
   ports OpenAI documents a Secure MCP Tunnel (OpenAI-side feature; not tried here).
3. **Authorization server.** Configure it as in the table. Unmapped scopes grant no accounts.
4. **Add the server in ChatGPT** (docs call it adding a plugin / custom MCP server, web only;
   wording varies), enter `https://<your-host>/mcp`, choose OAuth and the registration method your
   IdP supports.
5. **Run [TEST_CHECKLIST.md](TEST_CHECKLIST.md).**

Known limitation seen in verification: in static-token mode the protected-resource metadata lists
the server itself as `authorization_servers` (there is none). In JWT mode it lists your issuer.

## Recommended tool subset and permissions

Default posture: **read-only plus briefs, send OFF.**

| Capability | Recommendation |
|---|---|
| List/search/read messages and folders | ON (read-only account) |
| Briefs (read-only summaries) | ON |
| Organize (move/flag), drafts | OFF unless you explicitly need them |
| **Send** | **OFF.** Not enabled by `read_only = true`; also requires `permissions.send = true` plus SMTP config. Even if enabled later, rely on OpenMail's server-side approval policy, not on ChatGPT's confirmation prompts. |
| Delete | OFF |

Enforcement lives in `openmail-security` and the account config, not in tool descriptions or in
ChatGPT's UI. Prefer a dedicated low-privilege mailbox or an app-password/OAuth scope that cannot
send, so a policy bug cannot become an outgoing message. Tools are named `mail_*` (read: `mail_list_accounts`, `mail_list_folders`, `mail_list_messages`,
`mail_search_messages`, `mail_get_message`, `mail_get_headers`, `mail_get_thread`,
`mail_list_attachments`, `mail_get_attachment`, `mail_get_folder_status`, `mail_test_connection`);
write groups appear only where an account grants the permission. Check `tools/list` on your build.

## Prompt injection

Mail bodies are attacker-controlled text and the model reads them. OpenMail wraps mailbox text as
untrusted, but a ChatGPT session can still be steered by a hostile email. Keeping send/delete OFF is
the main mitigation. Do not combine this connection with other tools that can exfiltrate data
(web browsing, other write-capable connectors) in the same conversation.

## Privacy and data disclosure

- Message content returned by tool calls (headers, snippets, bodies, attachment text) is sent to
  OpenAI as conversation context and is then handled under your OpenAI plan's data terms
  (retention, training and admin-visibility settings differ by plan; read them, they were not
  verified here).
- Workspace admins may see connector configuration and, depending on plan, logs. Third-party
  recipients' mail is included in what you disclose; check your employer policy and local law
  before connecting a work mailbox.
- OpenMail itself sends no telemetry (verify with your build); it stores mail credentials via env or
  keyring, never in the config file, and nothing in this guide requires sharing them with OpenAI.
- Limit exposure: restrict the account/scope, use a test mailbox first, and revoke the OAuth grant
  and rotate credentials when finished.

## Briefs and scheduling

ChatGPT has no OpenMail-specific scheduling here. Briefs are produced by `openmail-mcp brief ...`
(and delivered by OpenMail's own scheduler where configured), not by ChatGPT. Do not expect ChatGPT
to run a brief on a timer. Whether ChatGPT offers any generic scheduled-task feature that can call a
custom MCP server: UNVERIFIED and not claimed.

## Apps SDK assessment: not needed for this integration

Needed only for custom ChatGPT UI (widgets/components rendered in the conversation) or if you want
to publish a directory app. A plain MCP server with text/structured tool results connects without
it, per the OpenAI docs summarized in the compatibility doc.

- **Not needed now**: OpenMail's value is tools and briefs, which render fine as text; a widget adds
  an attack surface (rendering mail content in an iframe) without a requirement driving it.
- **Would become needed** for a branded inbox widget, or if directory submission requires it.
  Directory requirements, review process and branding rules: UNVERIFIED.
- Directory publication: **not submitted, not claimed.** It would also require a stable public
  endpoint and an operator-hosted deployment, which an open-source local-first project does not
  provide by default.

## Not verified / not done

- **No live ChatGPT connection**; no OAuth flow run; no IdP configured; no public HTTPS endpoint.
- Plan matrix (Plus etc.), retention/training terms, and scheduled tasks calling custom MCP: UNVERIFIED.
- No directory submission; no Apps SDK widget.
- Locally verified only (see VERIFICATION.md): TLS + bearer edge, 401/challenge, metadata, Origin/Host
  rejection, session handling, read tools over real IMAP via Inspector CLI and a raw client.
  JWT mode through the real binary was not run (JWKS fetch refuses loopback); it is covered by
  in-process tests only.
- No reference authorization server configuration is provided.
