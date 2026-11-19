# Connecting OpenMail MCP to ChatGPT

**Status: NOT VERIFIED, NOT PUBLISHED.** Nobody has connected a live ChatGPT workspace to this
server. This guide records what OpenAI's official documentation reportedly requires (see
`docs/PROTOCOL_COMPATIBILITY.md`, section 3, which itself rests on search summaries of official
pages, not full reads) and what OpenMail's code is designed to provide. OpenMail is **not** listed
in any ChatGPT directory, and ChatGPT cannot schedule OpenMail briefs natively (see
[Briefs](#briefs-and-scheduling)). Re-check the linked OpenAI pages before relying on any step; they
change often and some were reported as old.

## What ChatGPT needs, and what OpenMail has

| ChatGPT requirement (reported) | OpenMail |
|---|---|
| Stable, publicly reachable **HTTPS** Streamable HTTP endpoint, typically `/mcp` | `openmail-mcp serve --transport http` refuses to start without TLS and auth; you must put it behind a public HTTPS name yourself (reverse proxy or tunnel). Not verified end to end. |
| Local stdio is unreachable from ChatGPT | True: stdio is for local clients only. |
| OAuth per MCP authorization spec: protected-resource metadata, `401` + `WWW-Authenticate`, auth code + PKCE `S256`, `resource` parameter, audience and scope checks per call | `openmail-remote` implements the resource-server half (RFC 9728 metadata, `WWW-Authenticate`, JWT audience/scope validation). It does **not** run an authorization server: you need an external OAuth provider that issues tokens for your resource URL. |
| Alternative: "no authentication" | **Do not use for mail.** OpenAI says servers exposing customer data should authenticate; this is a mailbox. |
| Plan: custom MCP servers reported for Business and Enterprise/Edu; Pro reported read/fetch-only; Plus UNVERIFIED | Check your plan in the OpenAI help center before starting. |

## Steps (unverified path)

1. **Config.** Keep every account `read_only = true` (the default) with no write permissions.
   ```toml
   [[accounts]]
   id = "work"
   read_only = true          # default; send/draft/delete stay unavailable
   ```
2. **Public HTTPS + auth.** Terminate TLS in a reverse proxy (or pass the TLS cert/key env vars the
   CLI reads) and run:
   ```bash
   openmail-mcp serve --transport http --bind 127.0.0.1:8765 --config ~/.config/openmail/config.toml
   ```
   Keep the bind on loopback and expose only the proxy. For private testing without opening inbound
   ports, OpenAI documents a "Secure MCP Tunnel" (private testing only, not for distribution).
3. **OAuth provider.** Configure an external authorization server so that tokens carry
   `aud` = your exact resource URL and a scope that maps to the account(s) you allow. Unmapped
   scopes grant no accounts.
4. **Add the server in ChatGPT** (Plugins / custom connection UI; wording varies by plan and date),
   enter `https://<your-host>/mcp`, choose OAuth, complete the consent screen.
5. **Run [TEST_CHECKLIST.md](TEST_CHECKLIST.md)** before trusting it with a real mailbox.

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
send, so a policy bug cannot become an outgoing message. Final MCP tool names were not defined in
`openmail-mcp` when this was written; check `tools/list` from your build instead of trusting any
list in this file.

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

- No live ChatGPT connection; no OAuth callback URL allowlist research; no plan-matrix verification
  (Plus limits UNVERIFIED).
- No directory submission; no Apps SDK widget.
- `openmail-mcp serve --transport http` was documented from the CLI definition; at the time of
  writing the CLI's http serve backend was a seam that fails with "not wired yet" until the remote
  crate is linked. Confirm your build actually serves before following the steps.
- Authorization server setup is left to you; no reference IdP configuration is provided.
