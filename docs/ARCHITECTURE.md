# Architecture

Status legend: **[built]** exists and tested, **[planned]** not yet implemented.

## Crates and ownership

| Crate | Responsibility | Depends on | Status |
|---|---|---|---|
| `openmail-core` | Domain models, config + validation, error codes, `MessageRef`, `MailBackend`/`MailOrganizer` traits. No I/O. | – | **[built]** (10 unit tests) |
| `openmail-security` | Secret resolution (env/keyring), authorization policy, send approvals, redaction, rate limits | core | [planned] |
| `openmail-imap` | `MailBackend` over IMAP (async-imap), MIME parsing, bounded session pool, search translation, threading | core | [planned] |
| `openmail-smtp` | lettre transport, message building, idempotent sends, audit records | core, security | [planned] |
| `openmail-mcp` | rmcp server, tool schemas, stdio + Streamable HTTP, generic over `MailBackend` | core, security | [planned] |
| `openmail-briefs` | Briefing engine, scheduler, delivery | core | [planned] |
| `openmail-cli` | `openmail-mcp` binary: init, doctor, accounts, serve, brief | all | [planned] |

Rules: no cycles; the MCP crate never touches IMAP types directly (only the `MailBackend` trait);
authorization lives in `openmail-security`, not in tool descriptions; all mailbox text is
`Untrusted<T>`.

## Shared contracts (frozen unless the architecture owner approves a change)
- `MessageRef` = base64url(`v1\0account\0folder\0uidvalidity\0uid`). UIDVALIDITY mismatch → `ErrorCode::StaleReference`.
- Config is TOML, `deny_unknown_fields`, secrets only as `CredentialRef`. Accounts default to `read_only = true`.
- Error codes (`ErrorCode`) are append-only.
- Backends are used generically (no `dyn`), native async-fn-in-trait.
