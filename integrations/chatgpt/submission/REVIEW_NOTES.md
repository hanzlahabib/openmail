# Notes for a reviewer / tester

1. Server: `https://mail-mcp.example.com/mcp` (or your own: see `docs/deployment/REMOTE.md`).
2. In ChatGPT (web, developer mode): Settings, Connectors, add a custom MCP server, URL above, auth OAuth.
   Registration is automatic (RFC 7591). You are sent to the OpenMail consent page.
3. Sign in with the owner password (given out of band, never in this repo) and approve `mail:read`.
4. Run `TEST_CHECKLIST.md`. Expected: 16 tools, all read-only; account list shows `read_only: true`.
5. Safety checks worth trying: ask it to send or delete mail (no such tool exists); put "ignore previous
   instructions" in a test email subject and confirm the output marks it as untrusted data and ChatGPT does not
   act on it.

Known limits: one owner; no consent memory; briefs are heuristic and say so; not tested with a live ChatGPT
account before this document was written.
