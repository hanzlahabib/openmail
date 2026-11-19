# openmail-smtp build notes (wave 1)

## Built
- `request.rs`: `SendRequest`/`Attachment`/`SmtpLimits`, validation (CRLF injection, recipient/attachment/total caps, Message-ID format),
  canonical length-prefixed SHA-256 `content_hash` (binds Bcc, attachments by digest; excludes idempotency key).
- `builder.rs`: lettre message builder — plain / HTML / multipart-alternative / mixed with attachments, Cc, Bcc (envelope only),
  display names, `In-Reply-To`/`References` (whole chain), generated `<uuid@account-domain>` Message-ID, IDN domains punycoded,
  sender identity check (account address or explicit alias, kept in this crate's `SmtpOptions`).
- `client.rs`: `SmtpClient<O: OutboxStore, S: SecretSource>::send(account, request, &ApprovalProof)`. Drives lettre's
  `AsyncSmtpConnection` command-by-command to know exactly when DATA starts. Implicit TLS and STARTTLS (required; refuses
  to authenticate or continue unencrypted), rustls + webpki roots (+ optional extra PEM roots; verification cannot be disabled),
  AUTH PLAIN/LOGIN for passwords, XOAUTH2 for `AuthMethod::Oauth2` (lettre supports it; the resolved secret must be an access token).
- `approval.rs`: opaque `ApprovalProof` (content hash + caller token); only checks hash equality (`ApprovalInvalid` otherwise).
- `outbox.rs` / `sqlite_outbox.rs`: `OutboxStore` trait + SQLite impl (WAL, synchronous=FULL, 0600 file, IMMEDIATE transactions),
  crash recovery on open, `resolve_uncertain`, append-style audit table. See `RECOVERY.md`.

## Commands run (all green at the end)
- `cargo fmt -p openmail-smtp`
- `cargo clippy -p openmail-smtp --all-targets -- -D warnings`
- `cargo test -p openmail-smtp` -> 14 unit + 13 integration tests pass.
  Integration tests use an in-process scripted SMTP/SMTPS server (`tests/support/fake_server.rs`, 127.0.0.1 only):
  success (implicit + STARTTLS), STARTTLS-required/no downgrade, implicit-TLS-vs-plaintext, untrusted cert, auth failure,
  recipient rejection, final 554, hang after DATA -> Uncertain, duplicate key (same process and after reopening SQLite),
  simulated crash mid-DATA (task aborted) -> Uncertain after reopen, operator resolution, key reuse with different content,
  approval mismatch, sender spoofing/alias.

## Failures hit and fixes
- lettre's `references()` replaces instead of appending -> pass the joined chain once (test asserts both ids).
- lettre keeps IDN domains in Unicode (would need SMTPUTF8) -> punycode via `idna` in the builder.
- lettre's `AsyncSmtpConnection::abort()` waits for QUIT's reply with no timeout; a silent server hung the first Uncertain test
  forever -> all aborts bounded by `abort_quick` (3 s).
- `Envelope::has_non_ascii_addresses` is crate-private -> reimplemented for local parts.

## Design decisions
- One connection per send (no pooling): simplest correct behaviour for idempotency; pooling can come later.
- Failure before DATA => `Rejected` (retryable). Any non-verdict failure after DATA is issued => `Uncertain`
  (deliberately conservative: includes a lost reply to the DATA command itself).
- A `Pending` row without the DATA marker older than 15 min (`PENDING_LEASE`) is treated as abandoned and retryable;
  a younger one reports "already in progress".
- Crate-local dependency versions live in `crates/openmail-smtp/Cargo.toml` (workspace deps untouched) to avoid merge conflicts.
- `NEEDS_CORE_CHANGE.md`: none needed. (Note: core has no `RecipientRejected` code; recipient refusals map to `InvalidInput`.)

## NOT done / limitations
- XOAUTH2 path is wired but has no automated test (fake server only speaks AUTH PLAIN); token refresh is the caller's job.
- `cargo deny` not run: no `deny.toml` in the repo. Dependency licence audit (webpki-roots CDLA/MPL, ring, rusqlite/SQLite) is pending.
- lettre `Credentials` holds the password as a plain `String` for the session duration (not zeroized).
- No tests against a real provider or a Docker server (only the in-process server); no SIZE-extension enforcement from EHLO.
- Message drafts (saving to the Drafts folder) belong to the IMAP side; this crate only builds/sends.
- Idempotency is per `(account, key)` in one SQLite file; two machines with separate files are not coordinated.
