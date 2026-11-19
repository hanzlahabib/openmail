# Agent execution ledger

Only work that is actually recorded here happened. The 50-role table in the master prompt is a
set of workstreams, not a headcount: dependent work is serialized and roles are merged into the
agents below. Agents run in isolated git worktrees on branches `wave1-<area>`; the orchestrator
merges after review. Nothing is pushed anywhere.

| Wave | Agent / branch | Owns (roles) | Files owned | Status |
|---|---|---|---|---|
| 0 | orchestrator (main) | 01 architecture, 20 config | workspace, `openmail-core` | done, committed |
| 1 | `wave1-imap` (herdr pane w24:p2, Sonnet 5.5) | 02-08 IMAP/MIME/search/attachments | `crates/openmail-imap/**` | dispatched 2026-11-19, in progress |
| 1 | `wave1-security` (w24:p3) | 21-26 authz, credentials, approvals, redaction, rate limits, threat model | `crates/openmail-security/**`, `docs/THREAT_MODEL.md`, `SECURITY.md` | dispatched, in progress |
| 1 | `wave1-mcp` (w24:p4) | 11, 12, 14, 15, 18 MCP lifecycle, stdio, read tools | `crates/openmail-mcp/**` | dispatched, in progress |
| 1 | `wave1-smtp` (w24:p5) | 09 SMTP + idempotent send | `crates/openmail-smtp/**` | dispatched, in progress |

Not yet started (blocked on wave 1 contracts): CLI/config wiring (19), Streamable HTTP + OAuth (13, 22), drafts/organize tools (16, 17),
briefs (41-47), ChatGPT (48-49), CI/packaging/docs (31-40), perf/e2e (29, 50). Roles 10, 27-28, 30 are exercised inside the wave agents' tests and the orchestrator's review, not as separate agents.
