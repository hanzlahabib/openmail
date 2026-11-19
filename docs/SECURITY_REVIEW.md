# Security review

Status: **one independent read-only code review, 2026-11-19, branch `integration`. Nothing was executed by the reviewer.**
This is NOT a full audit and does not satisfy Gate 5 on its own.

## Live attack surface today
`openmail-mcp serve --transport stdio`: 9 read-only tools over real IMAP. No write/send tools exist. HTTP serve refuses to start.

## Findings (open)
| # | Sev | Finding | Status |
|---|---|---|---|
| F1 | High (latent) | `Authorizer`, `Principal`, `RateLimiter`, `ApprovalVerifier` are library-only; `openmail-mcp` and `openmail-smtp` do not depend on `openmail-security`. Tool handlers resolve accounts via `config.account()` only. Benign today (read-only, single-principal stdio) but must be wired before any write tool or HTTP. | **OPEN — must fix before write tools/HTTP** |
| F2 | High (latent) | `ApprovalProof::new(hash, token)` in `openmail-smtp` is public; `send` only compares the caller-supplied proof hash to the request hash, never calls `ApprovalVerifier::consume`. Any caller could send without approval. Binding fields differ between security (client/account/recipients/subject) and smtp (content hash incl. cc/bcc/html/references). | **OPEN — do not expose any send tool until fixed** |
| F3 | Medium | Prompt-injection handling is labelling only (`_notice`, `x-untrusted`). Invisible/bidi characters and hidden-CSS text are not stripped; `<a href>` retained (exfiltration channel if a client renders links); server-controlled text reflected in `mail_test_connection.detail`/errors. | OPEN |
| F4 | Medium (latent) | `openmail-remote` has its own `Principal`, does not depend on security; `require_bearer` only verifies the token and does not attach the principal to the request. | OPEN |
| F5 | Low | XOAUTH2 payload held in a plain `String` (not zeroized); no connect timeout inside `conn.rs` itself (covered at tool level). | OPEN |
| F6 | Low | `docs/THREAT_MODEL.md` rows 2, 3, 8, 10 read "mitigated" but the controls are not wired into the request path; rows 5, 7, 10, 11 say "not mitigated" although some are now. | See banner in THREAT_MODEL.md |

## Verified by the reviewer (read, not run)
IMAP SEARCH quoting rejects control chars; TLS verification cannot be disabled and STARTTLS failure refuses to continue; UIDVALIDITY checked on every fetch/thread/cursor path; strict `MessageRef` decoding; ammonia HTML sanitization (no img/svg/iframe/form, http/https/mailto only); body-size caps; `read_only_hint` on all tools; config `deny_unknown_fields` and read_only/permission conflict checks; Authorizer logic as a library; approval store atomic single-use consume with persisted tombstones; SMTP CR/LF/NUL rejection and length-prefixed content hash; Uncertain sends never replayed; JWT algorithm allowlist (no `none`/HS256) with exp/iss/aud required; JWKS SSRF protections with DNS pinning; constant-time static bearer; Origin validation incl. `localhost.evil.com`; trusted-proxy-only X-Forwarded-For; OAuth token Debug redaction.

## Not verified
async-imap handling of CR/LF in mailbox names; lettre header encoding for non-ASCII; `EnvKeyringSecretSource` log leakage; briefs, CLI init/doctor and OAuth token-file handling.

## Required before claiming Gate 5
Fix F1, F2 (and add a test that fails if any tool skips `authorize()`), F3, F4; re-run an independent review that executes the security tests; resolve the "not verified" list.
