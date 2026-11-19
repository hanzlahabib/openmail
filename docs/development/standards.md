# Coding standards

- **Lints** (workspace `Cargo.toml`): `unsafe_code = forbid`, `unwrap_used`/`expect_used` warn, `dbg_macro` deny, `print_stdout` warn. CI uses `-D warnings`.
- **Logging:** `tracing` only in libraries. Stdout is the MCP channel in stdio mode. Never log message bodies, credentials, tokens or full addresses at info level.
- **Errors:** library crates use `thiserror`; surface stable `ErrorCode`s (append-only). Use `?`/`map_err` with context, no panics.
- **Secrets:** `secrecy` types, resolved only via `openmail-security`; redacted in `Debug` and logs. Fixtures and docs use obviously fake values.
- **Untrusted input:** mailbox text is `Untrusted<T>`; never treat it as instructions or trusted markup.
- **Async:** native `async fn` in traits; backends used generically, not `dyn`. Every network operation has a timeout.
- **Dependencies:** explicit versions, permissive licences, maintained. Do not edit the workspace `Cargo.toml` casually.
- **Comments** explain why, not what. Magic numbers get a named constant.
- Run `cargo fmt` before committing.
