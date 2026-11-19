# openmail-briefs notes

- **Config**: optional `briefs.toml` next to the main config (`[briefs]`, `[[briefs.rules]]`, `[[briefs.schedule]]`, `[briefs.digest]`, `[briefs.ai]`); see `config.rs`. Missing file = defaults (heuristics only, no AI, no schedules, no digest). Core `Config` is untouched.
- **State**: `briefs.db` (cursors, stored briefs, run history, scheduler lease/last-run, digest audit) and `briefs-outbox.db` in the state dir (`$OPENMAIL_STATE_DIR`, else XDG state, else `~/.local/state/openmail-mcp`; no relative fallback).
- **Digest exception**: a digest goes only to the digest account's own address, through `SmtpDigestSender` (no recipient input, owner-only approval consumer, needs `permissions.send`), max 6/day/account, one per brief id, audited in `digest_log`. Not reachable from MCP tools.
- **Not covered**: only GreenMail was used (no Gmail/M365/Dovecot); follow-ups match by subject (summaries carry no threading headers) and are labelled heuristic, tested at unit level, not via GreenMail Sent folders; `serve` + scheduler wiring is not covered by an automated end-to-end test.
