# openmail-security notes

## Built
- `secret`: `EnvKeyringSecretSource` (env + OS keyring via keyring 4.2 `v1` feature → Secret Service on Linux). Providers are injectable.
- `authz`: `Principal`, `Action`, `Authorizer` (deny by default, read_only dominates, per-account permissions, cross-account isolation).
- `approval` / `approval_store`: `SendIntent`, `ApprovalIssuer` (needs `ApprovalGrantor`), `ApprovalVerifier`, `InMemoryApprovalStore`, `SqliteApprovalStore` (rusqlite 0.43 bundled, MIT, MSRV 1.89; file mode 0600).
- `redact`: `Redacted<T>`, log header allowlist. `ratelimit`: per-account + global token bucket, injected `Clock`.
- `docs/THREAT_MODEL.md`, `SECURITY.md` (contact is a TODO(owner) placeholder).

## Commands run (all green at last run)
- `cargo fmt -p openmail-security`
- `cargo clippy -p openmail-security --all-targets -- -D warnings` (exit 0)
- `cargo test -p openmail-security` → 37 passed.

## Failures and fixes
- Clippy `unwrap_used` fired in tests → `#![cfg_attr(test, allow(...))]` in lib.rs.
- A power outage interrupted the session; work was recovered from the WIP snapshot and continued.

## Not done / caveats
- Real OS keyring was NOT exercised (no Secret Service in the test environment); only the error mapping with fakes and the real env provider are tested. Keyring calls are blocking.
- `cargo deny check` cannot pass: no `deny.toml` exists (default policy rejects everything). `cargo deny list` shows only permissive licenses (r-efi is MIT OR Apache OR LGPL, UEFI-only).
- Rate limiter and verifier are not wired into any tool handler (mcp crate's job). No `NEEDS_CORE_CHANGE.md` was needed.
- Approval grantor UI/CLI not implemented (CLI crate).
