# Release readiness (2026-11-20, updated): v0.1.0 PRE-RELEASE, not a stable release

Branch `integration`. Evidence = commands actually run (see `docs/TEST_REPORT.md`, `docs/SECURITY_REVIEW.md`).

| Gate | Status | Evidence / gap |
|---|---|---|
| 1 Foundation | **Passed** | workspace builds; `cargo clippy --workspace --all-targets -D warnings` and `fmt --check` clean; config validation and secret refs tested |
| 2 Core email | **Partly** | real IMAP (GreenMail in Docker): login/folders/fetch/search/flags/move/drafts/attachments/UIDVALIDITY/reconnect/connection limits. Only GreenMail: not Dovecot/Gmail/M365; RFC 6154 special-use untested on a real provider; 3-account isolation tested, 50/100-mailbox load NOT tested |
| 3 MCP | **Passed (local)** | real binary + real MCP client over stdio and HTTPS (TLS + bearer) against real IMAP; read, organize, draft, send-with-approval and brief tools; per-call authorization registry test |
| 4 Outgoing | **Partly** | SMTP engine (idempotency, Uncertain handling, sealed single-use approvals) tested against a scripted server and a real GreenMail SMTP (digest path); human approval CLI exists. Not tested against a real provider |
| 5 Security | **Not passed** | internal review findings F1-F5 fixed in code; no independent re-review; binaries unsigned |
| 6 Distribution | **Not passed** | CI/release/Docker/installers written but never run on GitHub; Docker image and installers not verified end to end here; license audit generated, not independently verified |
| 7 Briefing | **Passed (local)** | engine, MCP tools, CLI, opt-in scheduler with SQLite lease (two-process test), owner-only digest, AI boundary; 3-account GreenMail run incl. one unreachable account |
| 8 ChatGPT | **Not passed** | docs and local verification record only; not tested against a live ChatGPT account |

## Added since the first draft
Built-in single-owner OAuth 2.1 authorization server (PKCE, dynamic client registration, owner-chosen permissions), account registry (`accounts add|remove`, `accounts.d/`, secret files) with classified connection diagnostics, bulk mark-as-read tools, sending wired into `serve` with an owner-chosen approval mode (owner_only / rules / delegated, daily caps), compose-and-send with an explicit `user_confirmed` gate. All have automated tests; an adversarial review of these surfaces is in progress and its findings are tracked in `docs/SECURITY_REVIEW.md`.

## Known issues
- `openmail-imap` `connection_limits_are_enforced` counts live proxy sockets and failed once under heavy parallel load (peak 5 vs cap 4), passing 3/3 in isolation: treat as a flaky test until the socket-accounting race is understood.
- OAuth2 for Gmail/Microsoft is a tested library only; there is no end-to-end login flow.
- Windows/macOS keychain backends are cfg-gated and untested from this Linux host.

## Not done
Independent security audit; Gmail/M365/Dovecot testing; 50/100-mailbox and sustained-load measurements (see `docs/PERFORMANCE_REPORT.md` for what was measured); signed binaries; first GitHub CI/release run; fresh-install verification on Windows/macOS.

## Version
v0.1.0 pre-release. v1.0 requires every gate above.
