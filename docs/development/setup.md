# Setup

## Toolchain
`rust-toolchain.toml` selects the `stable` channel with `rustfmt` and `clippy`. With rustup installed, entering the repo selects it automatically. Workspace: edition 2024, `rust-version = "1.100"`, resolver 3.

## Common commands
```bash
cargo build -p openmail-cli              # builds the openmail-mcp binary
cargo fmt --all
cargo clippy -p <crate> --all-targets -- -D warnings
cargo test -p <crate>
```
Prefer `-p <crate>` while iterating; CI runs the whole workspace (fmt, clippy, cross-OS tests, MSRV, cargo-deny, cargo-audit, docs).

## Optional tools
- Docker with the compose plugin, for the test mail server ([testing.md](testing.md)).
- `cargo-deny` and `cargo-audit` for `scripts/audit.sh` (policy in `deny.toml`).
- Python 3, used by the test-infra scripts.

## Configuration
Config is TOML with `deny_unknown_fields`; secrets are referenced via `CredentialRef` (environment variable or OS keyring), never inlined. Accounts default to `read_only = true`. See [provider setup pages](../providers/README.md).
