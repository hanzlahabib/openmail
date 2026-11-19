# Threat model

> **Status warning (2026-11-19):** the authorizer, principal, rate limiter and approval verifier are implemented and unit-tested as libraries in `openmail-security`, but are **not yet wired into the MCP or SMTP request paths** (see docs/SECURITY_REVIEW.md F1, F2). Rows that say "mitigated" for authorization, approvals and rate limiting describe the library, not the running server. The only live surface today is stdio + read-only tools.


Status per row: **Mitigated** (code + test named), **Partly** (what remains is stated), or **NOT YET MITIGATED**.
Tests are in `crates/openmail-security/src/` unless noted. Other crates' mitigations are marked *(owner crate)* and
are NOT verified here.

## Trust boundaries
1. Mailbox content (headers, bodies, attachments) → untrusted input, always.
2. MCP client / LLM → semi-trusted caller acting on untrusted content; may be manipulated.
3. Human operator (CLI/UI) → the only party that can approve a send.
4. Local machine users and processes → may read files, env, process list.
5. Remote network (Streamable HTTP mode, IMAP/SMTP servers) → untrusted transport.
6. Config file → trusted only if owned by the operator; may be edited by others.

## Threats

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| 1 | **Malicious sender / prompt injection**: an email tells the agent to send, forward or delete mail | Permission is never derived from mail text. Send needs an approval id minted out-of-band by a human (`ApprovalIssuer` + `ApprovalGrantor`); the MCP side holds only `ApprovalVerifier`, which cannot create approvals. Writes are off unless configured. | `garbage_and_forged_ids_rejected` (id inside prose rejected), `no_approval_means_not_approved`, `denial_mints_nothing`. Marking mailbox text as `Untrusted<T>` in tool output: NOT YET MITIGATED *(mcp crate)* |
| 2 | **Compromised/over-privileged MCP client** | Deny by default; per-principal account allowlist + action scopes, intersected with per-account permissions; `read_only` dominates | `default_deny_for_empty_principal`, `principal_scopes_narrow_account_permissions`, `read_only_account_blocks_writes_even_with_scopes`, `unvalidated_config_cannot_bypass_read_only_or_missing_smtp` |
| 3 | **Cross-account exfiltration** (read A, leak via B; enumerate accounts) | Principal must be allowed on the specific account; foreign existing and non-existing ids return the same error; listings filtered | `cross_account_isolation`. Cross-account *content* flow (agent copying A's text into B's draft) cannot be prevented by authorization; sends still need human approval showing recipients and subject. |
| 4 | **Approval abuse**: replay, tampering, stale reuse, brute force | Single-use (atomic consume, tombstones persisted), 5 min default / 15 min max TTL, 128-bit random id, only SHA-256 of id stored, binding over client, account, normalized recipients, subject, body hash, attachment hashes with length-prefixed encoding; mismatch fails closed without burning the approval | `happy_path_then_replay_rejected`, `expiry_is_enforced_and_ttl_is_capped`, `any_bound_field_change_fails_and_does_not_burn_the_approval`, `binding_fields_are_length_prefixed`, `sqlite_consumption_persists_across_reopen_and_file_is_private`, `concurrent_consume_succeeds_exactly_once` |
| 5 | **Header/recipient injection** (CRLF in subject or addresses, display-name tricks, Bcc smuggling) | Recipients must be plain `local@domain`; CR/LF/NUL in subject rejected before hashing | `malformed_inputs_rejected`. Final MIME construction safety: NOT YET MITIGATED here *(smtp crate; lettre builder)* |
| 6 | **Credential theft from config/logs/errors** | Config holds only `CredentialRef`; inline secrets rejected by core; `SecretString` for values; error text names the variable/service, never a value; keyring errors are never formatted (some variants embed secret bytes); `Redacted<T>`; log header allowlist | `env_resolves_and_secret_debug_is_redacted`, `missing_env_names_the_var_not_a_value`, `keyring_success_and_failures_map_to_typed_errors`, `debug_of_account_config_never_contains_the_resolved_secret`, `redacted_never_prints_value`, `header_allowlist_drops_pii_and_credentials`; core `inline_password_field_rejected` |
| 7 | **Local user / other process reads secrets** | Env var secrets are visible to same-user processes and `/proc/<pid>/environ`: **Partly** — prefer keyring. Approval DB created `0600` on Unix. | `sqlite_consumption_persists_across_reopen_and_file_is_private`. Config file permission check: NOT YET MITIGATED |
| 8 | **Outgoing abuse / mail flood** | Send needs per-message human approval; per-account and global token buckets on a monotonic clock; bucket map bounded | `burst_then_deny_then_refill`, `accounts_are_independent_but_share_global`, `denied_by_global_does_not_spend_account_tokens`, `wall_clock_jump_does_not_refill`, `id_flooding_cannot_bypass_or_grow_unbounded`. Wiring the limiter into tool handlers: NOT YET MITIGATED *(mcp crate)* |
| 9 | **Config poisoning** (typo or hostile edit loosens policy) | Unknown keys rejected, accounts read-only by default, `read_only` conflicts with write permissions fail validation, send requires SMTP section | core tests `unknown_keys_rejected`, `read_only_conflicts_with_write_permissions`, `send_requires_smtp`. A hostile editor who can write the config can also grant permissions: **Partly** (file ownership is the control; no signing) |
| 10 | **Remote callers** (HTTP transport) | Principal model exists; authentication of remote callers, TLS/origin checks, binding to loopback: NOT YET MITIGATED *(mcp crate)* | – |
| 11 | **Malicious attachments** (malware, zip bombs, path traversal on save) | Attachment content only enters the approval binding by hash. Parsing limits, no auto-execution, safe filenames, size caps: NOT YET MITIGATED *(imap/mcp crates)* | – |
| 12 | **Compromised mail account / provider** | Out of scope for this layer; read-only default limits what an attacker driving the agent can change. Transport TLS enforcement is core config (`TlsMode`, no plaintext variant) | – |
| 13 | **Clock manipulation** | Rate limiting uses a monotonic clock; approvals use wall-clock expiry (an attacker with local clock control could extend a TTL: **Partly**, requires local privilege) | `wall_clock_jump_does_not_refill` |
| 14 | **Dependency/supply chain** | Permissive licenses only in this crate's tree (MIT/Apache/BSD/Unlicense/Zlib; `r-efi` is MIT OR Apache OR LGPL, UEFI-only). `cargo deny` policy and advisory audit: NOT YET MITIGATED (no `deny.toml` exists yet) | `cargo deny list` output recorded in `crates/openmail-security/NOTES.md` |

## Known limits
- The human approval shows what the grantor implementation displays; a CLI that renders subjects unsafely could be spoofed (terminal escapes). Grantor implementations must escape control characters.
- Anyone holding both the issuer path and the approval store can mint approvals; they must run in the operator's trust domain, not inside the MCP server process.
