# Security review

Status: **one independent read-only code review, 2026-11-19, branch `integration`. Nothing was executed by the reviewer.**
This is NOT a full audit and does not satisfy Gate 5 on its own.

## Live attack surface today
`openmail-mcp serve --transport stdio`: 9 read-only tools over real IMAP. No write/send tools exist. HTTP serve refuses to start.

## Findings (open)
| # | Sev | Finding | Status |
|---|---|---|---|
| F1 | High (latent) | `Authorizer`, `Principal`, `RateLimiter`, `ApprovalVerifier` are library-only; `openmail-mcp` and `openmail-smtp` do not depend on `openmail-security`. Tool handlers resolve accounts via `config.account()` only. Benign today (read-only, single-principal stdio) but must be wired before any write tool or HTTP. | **FIXED in code (2026-11-19), pending re-review.** `openmail-mcp` enforces Authorizer + RateLimiter before every backend call; `tests/authz.rs` enumerates all registered tools and asserts each denies an unauthorized principal without reaching the backend. Unknown account now returns `ACCESS_DENIED` (no existence oracle). stdio uses a single all-accounts read-only principal; per-request principals for HTTP are still F4. |
| F2 | High (latent) | `ApprovalProof::new(hash, token)` in `openmail-smtp` is public; `send` only compares the caller-supplied proof hash to the request hash, never calls `ApprovalVerifier::consume`. Any caller could send without approval. Binding fields differ between security (client/account/recipients/subject) and smtp (content hash incl. cc/bcc/html/references). | **FIXED in code, pending re-review.** `ApprovalProof` is sealed (no public constructor; `compile_fail` doctests), obtainable only via `ApprovalConsumer::consume`; 8 seal tests cover mismatch, expiry, replay across reopen, wrong principal. No send tool is exposed yet regardless. |
| F3 | Medium | Prompt-injection handling is labelling only (`_notice`, `x-untrusted`). Invisible/bidi characters and hidden-CSS text are not stripped; `<a href>` retained (exfiltration channel if a client renders links); server-controlled text reflected in `mail_test_connection.detail`/errors. | **PARTLY FIXED, pending re-review.** Invisible/bidi stripping, inert link rendering, hidden-HTML pruning, fixed server-error text, and hostile-folder-name injection tests added (imap 3 `mailbox_injection` tests, mcp authz tests). Wrapping bodies in a stronger delimiter structure is NOT done; prompt-injection resistance still depends on the client. |
| F4 | Medium (latent) | `openmail-remote` has its own `Principal`, does not depend on security; `require_bearer` only verifies the token and does not attach the principal to the request. | OPEN |
| F5 | Low | XOAUTH2 payload held in a plain `String` (not zeroized); no connect timeout inside `conn.rs` itself (covered at tool level). | OPEN |
| F6 | Low | `docs/THREAT_MODEL.md` rows 2, 3, 8, 10 read "mitigated" but the controls are not wired into the request path; rows 5, 7, 10, 11 say "not mitigated" although some are now. | See banner in THREAT_MODEL.md |

## Verified by the reviewer (read, not run)
IMAP SEARCH quoting rejects control chars; TLS verification cannot be disabled and STARTTLS failure refuses to continue; UIDVALIDITY checked on every fetch/thread/cursor path; strict `MessageRef` decoding; ammonia HTML sanitization (no img/svg/iframe/form, http/https/mailto only); body-size caps; `read_only_hint` on all tools; config `deny_unknown_fields` and read_only/permission conflict checks; Authorizer logic as a library; approval store atomic single-use consume with persisted tombstones; SMTP CR/LF/NUL rejection and length-prefixed content hash; Uncertain sends never replayed; JWT algorithm allowlist (no `none`/HS256) with exp/iss/aud required; JWKS SSRF protections with DNS pinning; constant-time static bearer; Origin validation incl. `localhost.evil.com`; trusted-proxy-only X-Forwarded-For; OAuth token Debug redaction.

## Not verified
async-imap handling of CR/LF in mailbox names; lettre header encoding for non-ASCII; `EnvKeyringSecretSource` log leakage; briefs, CLI init/doctor and OAuth token-file handling.

## Required before claiming Gate 5
Fix F1, F2 (and add a test that fails if any tool skips `authorize()`), F3, F4; re-run an independent review that executes the security tests; resolve the "not verified" list.

## Update after hardening wave (verified by running)
Full workspace: `cargo clippy --workspace --all-targets -D warnings` clean; `cargo test --workspace --no-fail-fast` all pass with `OPENMAIL_REQUIRE_DOCKER=1` (real GreenMail). A real-binary stdio E2E (3 tests) also found and fixed a real leak: rmcp debug logging wrote mail bodies to logs. F4, F5 remain open; Gate 5 is still NOT passed (needs an independent re-review that executes the tests, and the unverified list above).


## Review of the OAuth server, send policy and account registry (2026-11-20)

Adversarial read by a fresh-context reviewer (not independent of the project). Fixed in code, with tests:

| # | Finding | Status |
|---|---|---|
| H1 | Delegated mode: forward and mass sends needed no owner gate; cap counted messages, not recipients; `user_confirmed` is only an instruction to the model | Forwarding is human-only in every mode; delegated sends limited to 5 recipients and a recipient-counted daily cap; `user_confirmed` documented as not a boundary |
| H2 | Consent phishing via open dynamic registration + shared ChatGPT redirect | Registration closes after the first login (owner opens a window with `oauth registration open`); consent page shows redirect host and client age |
| M1 | Anonymous owner lockout | 5 wrong passwords destroy that consent page; global pause only after 30 failures |
| M2 | Registration/pending DoS | Per-client pending cap; stale unused clients evicted |
| M3 | Daily cap overspent by parallel calls | Check-and-record in one write transaction |
| M4 | Unbounded daily-limit setting | Bounded 1-500, effective value logged |
| M5 | Argon2 on the async runtime | Runs on the blocking pool |
| L1 | Unticking every box widened the grant | Refused ("tick at least one") |
| L3 | send-policy DB and state dir permissions | 0600 / 0700 |
| - | Public routes had no request timeout | Timeout layer added |

Open: no refresh-token reuse detection or access-token revocation (L2); the pending-approval queue is unbounded and shows the approver a body hash, not the body (L4); drop-in `credential.path` can point at any file the service user may read, which needs write access to the config directory (L5); the per-IP limits trust `X-Forwarded-For` from loopback, so the reverse proxy must set it itself (L6).
