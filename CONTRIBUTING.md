# Contributing to OpenMail MCP

Thanks for helping. This guide is the short version; the detail lives in
[`docs/development/`](docs/development/README.md).

## Quick start

```bash
git clone <your fork>
cd openmail-mcp
rustup show                      # rust-toolchain.toml selects stable; MSRV 1.100 is enforced by Cargo.toml rust-version + CI
cargo fmt --all -- --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo test -p <crate>
```

Edition is 2024, MSRV is 1.100. Do not raise the MSRV in a drive-by PR.

## Ground rules

- **No secrets, ever.** No real hostnames, tokens, app passwords or mailbox content in code, tests, fixtures, issues or logs. Use fake credentials and the disposable test server.
- **No `println!`/`eprintln!` in library crates.** Use `tracing`. In stdio mode stdout *is* the MCP JSON-RPC channel; a stray print corrupts the protocol.
- **No `unwrap()`/`expect()` outside tests**; no `dbg!`; `unsafe` is forbidden. These are workspace lints (`Cargo.toml`), enforced by clippy with `-D warnings`.
- **No mock or placeholder production code.** Fakes live in `#[cfg(test)]` or `tests/`.
- **Frozen contracts** in `openmail-core` (`MessageRef` format, config schema, `ErrorCode`) change only with maintainer approval. `ErrorCode` is append-only.
- Authorization lives in `openmail-security`, never in tool descriptions. All mailbox text is `Untrusted<T>`.

## Workflow

1. Open an issue first for anything larger than a small fix.
2. Branch from `main` (`feat/…`, `fix/…`, `docs/…`).
3. Keep changes focused; one concern per PR. Add or update tests with real assertions.
4. Run the checks above for every crate you touched.
5. Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
6. Open a PR using the template. Security-sensitive changes must complete the checklist in [`docs/development/security-checklist.md`](docs/development/security-checklist.md).

Commit messages: short imperative summary, `area: what changed` (for example `imap: bound session pool`).

## Reporting security problems

Do not open a public issue. Use the repository's private security advisory feature
(GitHub Security tab) once the public repository exists; until then contact the maintainers directly.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
