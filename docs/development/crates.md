# Crate map

Dependencies must stay acyclic. The MCP crate never touches IMAP types; it is generic over the `MailBackend` trait.

| Crate | Responsibility |
|---|---|
| `openmail-core` | Domain models, config + validation, `ErrorCode`, `MessageRef`, `MailBackend`/`MailOrganizer` traits. No I/O. **Frozen contracts.** |
| `openmail-security` | Secret resolution, authorization policy, send approvals, redaction, rate limits |
| `openmail-imap` | `MailBackend` over IMAP, MIME parsing, session pool, search translation |
| `openmail-smtp` | Message building, SMTP transport, idempotent sends, audit records |
| `openmail-mcp` | MCP server, tool schemas, stdio and HTTP transports |
| `openmail-briefs` | Briefing engine, scheduler, delivery |
| `openmail-oauth` | OAuth providers and token refresh |
| `openmail-remote` | Remote (HTTP) serving and its authentication |
| `openmail-observe` | Tracing init, metrics, diagnostics |
| `openmail-cli` | The `openmail-mcp` binary: init, doctor, accounts, serve, brief |

The authoritative, status-tagged table is [ARCHITECTURE.md](../ARCHITECTURE.md); check it and `crates/` for what is actually built, since some crates are still in progress.

## Ownership
Change a crate in a PR that is about that crate. Cross-crate changes to `openmail-core` contracts need maintainer sign-off. Add dependencies with explicit versions in the crate's own `Cargo.toml`; check licence (`deny.toml`), maintenance status and MSRV first.
