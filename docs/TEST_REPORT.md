# Test report: E2E stdio vertical slice (Gate 3)

Date: 2026-11-19. Suite: `crates/openmail-cli/tests/e2e_stdio.rs` (helpers in `tests/support/`),
runner `scripts/e2e-stdio.sh` (sets `OPENMAIL_REQUIRE_DOCKER=1`; docker is mandatory, no silent skip).

## What is exercised (all real, nothing mocked)
- The built `openmail-mcp` binary: `--config <toml> --log debug serve --transport stdio`, env cleared except `PATH`,
  the credential env var(s) and `SSL_CERT_FILE`.
- Real `ImapBackend` + `EnvKeyringSecretSource` inside it.
- Real IMAP server: GreenMail 2.1.3 in docker, behind an in-test TLS-terminating proxy.
- TLS: a private CA is generated per run (rcgen); the proxy presents a `localhost` leaf signed by it; the binary
  trusts it only through `SSL_CERT_FILE`. No insecure option exists or is used.
- MCP client: raw newline-delimited JSON-RPC 2.0 over the child's stdin/stdout.

## Scenarios and assertions
1. `single_account_full_flow`: initialize (tools capability, serverInfo) -> tools/list (read tools present, no
   send/delete tools) -> `mail_list_accounts` (read_only default, port) -> `mail_test_connection` -> `mail_list_folders`
   (INBOX role) -> `mail_search_messages` (subject / unread+from / since; unfiltered search refused by design) ->
   `mail_get_message` on a seeded prompt-injection mail (returned verbatim as data with the untrusted `_notice`; mailbox
   unchanged afterwards, 3 messages) -> `mail_list_messages` pagination with cursor -> errors: unknown account,
   malformed `message_ref`, unknown folder (`FOLDER_NOT_FOUND`), unknown argument rejected -> stdin EOF.
2. `two_accounts_are_isolated_and_bad_credentials_fail_safely`: three accounts (alice, bob, and one with a wrong
   password): each sees only its own mail; a bob reference resolves; the bad account yields `AUTH_FAILED` /
   `imap_ok=false` while the others keep working.
3. `untrusted_server_certificate_is_refused_by_the_binary`: binary pointed at a different CA than the proxy's:
   `imap_ok=false`, `mail_list_folders` errors (fail closed).
Every scenario ends by closing stdin and requiring exit status 0 within 15 s, and asserts that no password
(client-side or server-side value) appears in any stdout line or in stderr at `--log debug`, and that no mail body
text appears in stderr.

## Results (actual)
- Final run against a clean snapshot of `integration` HEAD (`ff9d577`) plus only my paths: **3 passed, 0 failed**,
  repeated 3 times (9.3 s, 7.2 s, 10.6 s). `clippy -p openmail-cli --all-targets -D warnings`: clean. No leftover
  docker containers.
- Caveat: the shared `integration` worktree currently holds other agents' uncommitted wave-3 edits to
  `openmail-imap` / `openmail-mcp` / `openmail-smtp` / `openmail-security` (e.g. `crates/openmail-imap/src/html.rs`
  imports the private `ammonia::rcdom` and does not compile). I therefore ran the final verification from a
  `git archive HEAD` snapshot, not that dirty tree. I did not test their uncommitted changes.

## Findings
1. **FIXED (small, in `crates/openmail-cli/src/main.rs`): `--log debug` copied mail bodies to stderr.** `rmcp::service`
   logs complete `CallToolResult`s at debug, so a blanket debug filter wrote message text (including the untrusted
   body) into stderr. The new e2e audit caught it (red before, green after). Fix: `init_tracing` adds `rmcp=info`
   unless the filter already names `rmcp`. Default level (`warn`) was never affected. Trade-off: debugging rmcp
   internals needs an explicit `rmcp=debug`, which consciously re-enables the content dump.
2. **Observation (not fixed): tools without an input struct ignore unknown arguments.** `mail_list_accounts` with
   `{"surprise":1}` succeeds, whereas tools with inputs reject unknown fields (`deny_unknown_fields`). Harmless but
   inconsistent with the strict-schema statement in `input.rs`.
3. **Observation: unfiltered `mail_search_messages` returns `INVALID_INPUT`** (by design; use `mail_list_messages`).
   The tests assert this behaviour.
4. **Bookkeeping:** `Cargo.lock` gained entries for the new dev-dependencies (`async-imap`, `rcgen`, `serde_json`,
   `tokio-rustls` on `openmail-cli`); I left `Cargo.lock` uncommitted because it also contains other agents' pending
   changes. Cargo regenerates it automatically.

## Not covered
Streamable HTTP transport (not wired), STARTTLS through the binary, OAuth accounts, write tools (accounts are
read-only), attachment/HTML output through MCP, SIGTERM shutdown (only stdin-EOF shutdown was tested).
