# Decisions

| # | Date | Decision | Evidence / reason |
|---|---|---|---|
| D1 | 2026-11-19 | Toolchain: Rust stable 1.100.0, edition 2024 | `rustup update stable`; installed 1.88 was too old for current `mail-parser` (MSRV 1.98 per `cargo info`) |
| D2 | 2026-11-19 | Native async-fn-in-trait, generic backends instead of `async_trait`/`dyn` | Modern idiom; MCP server generic over `MailBackend` |
| D3 | 2026-11-19 | Config rejects unknown keys and inline secrets | A typo must not silently loosen security |
| D4 | 2026-11-19 | Accounts are read-only unless explicitly granted write permissions; `delete` permission is separate | Product principle 4/11 |
| D5 | 2026-11-19 | MIT license file added now; dependency-license audit is a Gate-6 item, not yet done | Honesty: audit pending |
