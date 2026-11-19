# openmail-mcp build notes (wave 1)

## Built
- `OpenMailServer<B: SendBackend>` (Arc<Config>, Arc<backend>, Limits), `build_server`, `serve_stdio`, `serve_io` (lifecycle shared by stdio and tests).
- 10 read-only tools: mail_list_accounts, mail_test_connection, mail_list_folders, mail_get_folder_status, mail_list_messages, mail_get_message (`fields`: headers|text|html|attachments), mail_get_headers, mail_get_thread, mail_search_messages, mail_list_attachments. All annotated readOnlyHint=true / destructiveHint=false; input schemas from schemars with `additionalProperties:false`, length/range limits; output schemas via `Json<T>`.
- Errors: `isError:true` result with structured `{"error":{"code","message"}}` using core `ErrorCode`. Unknown account -> ACCOUNT_NOT_FOUND (also for a message_ref naming an unconfigured account); malformed ids/refs/dates, limit 0, search with no filter -> INVALID_INPUT. Each backend call runs under the account's `timeout_secs` (-> TIMEOUT).
- Caps: page limit clamped to `limits.max_page_size`; bodies re-truncated server-side at `limits.max_body_bytes` (char-safe, `body_truncated`); folders 500, thread 200 (`truncated`); connection `detail` 500 chars.
- Untrusted mail text: every mailbox-sourced string is `UntrustedText` (output schema `x-untrusted: true`), every such result carries `_notice`, tool descriptions and server instructions say email content is data, never instructions. Credentials are never serialized (tested).
- stdio: `serve_stdio` uses rmcp `stdio_pipes`; stops on EOF, SIGTERM or SIGINT. Nothing in this crate prints; the host binary must send tracing to stderr.

## Verified (commands actually run)
- `cargo fmt -p openmail-mcp`, `cargo clippy -p openmail-mcp --all-targets -- -D warnings`, `cargo test -p openmail-mcp`: green (3 unit + 11 protocol tests).
- Protocol tests drive a real rmcp client over an in-memory duplex (same JSON-RPC framing as stdio): initialize, tools/list (names, annotations, schemas), tools/call success and error paths, schema-violation rejection, EOF shutdown and signal shutdown.
- Negotiated version with the rmcp 3.11.0 client: `2025-11-25` (`ProtocolVersion::LATEST_WITH_INITIALIZE`). rmcp also knows `2026-07-28` (no `initialize`; stateless per-request metadata) which I did not exercise. I read rmcp 3.11.0 source/tests in ~/.cargo/registry; I did NOT fetch the spec from modelcontextprotocol.io.

## Failures hit and fixes
- Generic `B: MailBackend` does not compile: async-fn-in-trait futures are not `Send` (E0277), return-type notation is still unstable (E0658). Added `SendBackend` (src/backend_bound.rs) and wrote NEEDS_CORE_CHANGE.md. **The imap crate or the integrator must resolve this** (preferred: core methods return `impl Future + Send`).
- `#[tool]` only emits outputSchema when the return type is literally `Result<Json<T>, E>` (a type alias hid it).

## NOT done / caveats
- Real stdio child-process test (stdout purity is by construction, not asserted over a real pipe); Streamable HTTP; attachment bytes and write tools (by brief).
- `mail_list_accounts` input schema is `{type:object, properties:{}}` without additionalProperties:false (rmcp's empty-schema helper).
- A body deserialization failure (e.g. bad `fields` value) comes back as rmcp's text-only isError result, not the structured error envelope.
- No deny.toml exists, so `cargo deny` was not run; dependency licenses unaudited here (rmcp Apache-2.0, schemars MIT).
