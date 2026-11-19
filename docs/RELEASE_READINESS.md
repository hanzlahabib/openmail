# Release readiness (2026-11-19) — NOT READY for a stable release

Branch `integration` (not merged to `main`; nothing pushed or published). Evidence = commands actually run.

| Gate | Status | Evidence / gap |
|---|---|---|
| 1 Foundation | **Passed** | workspace builds; `cargo clippy --workspace --all-targets -D warnings` and `fmt --check` clean; config validation + secret refs unit-tested |
| 2 Core email | **Partly** | real IMAP (GreenMail in Docker) login/folders/fetch/search/flags/move/UIDVALIDITY/reconnect/connection-limit tests pass. Only GreenMail tested — not Dovecot/Gmail/M365; RFC 6154 special-use path untested; 2-account isolation tested, 50-account load NOT tested |
| 3 MCP | **Partly** | real binary + real MCP client over stdio against real IMAP: 3 E2E tests pass. **Remote HTTP is NOT wired** (edge + auth exist as libraries in `openmail-remote`, not bridged to the MCP service); `serve --transport http` refuses to start |
| 4 Outgoing | **Not passed** | SMTP engine (idempotency, Uncertain handling, sealed approvals) tested against a scripted local server. **No draft/send/forward MCP tools exist**; no approval-grant UI/CLI; SMTP not tested against a real server |
| 5 Security | **Not passed** | one read-only independent review; F1/F2/F3 fixed in code pending re-review; F4 (remote principal), F5 open; no executed independent re-review |
| 6 Distribution | **Not passed** | CI/release/Docker/installers written but never run on GitHub; Docker image build and installers not verified end to end; binaries unsigned; license audit generated, not independently verified |
| 7 Briefing | **Not passed** | briefs library (model/store, classify, follow-up, aggregate, scheduler, AI adapter, delivery) has 70 unit tests; **not wired into the CLI or MCP**; no brief_* tools; no real multi-account run |
| 8 ChatGPT | **Not passed** | docs only (integrations/chatgpt); no authenticated remote endpoint, nothing tested against ChatGPT |

## Not done at all
Draft/organize/send/forward/attachment-download MCP tools; briefing tools; HTTP serve; OAuth for Gmail/M365 end-to-end (client library tested against a local token endpoint only); performance numbers (harness exists, nothing measured under load); 50/100-mailbox test; cross-platform binaries; fresh-install verification.

## Version
Nothing here justifies more than a v0.1.0 pre-release of the read-only stdio core. v1.0 requires every gate above.
