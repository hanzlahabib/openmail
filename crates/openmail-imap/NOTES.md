# openmail-imap build notes

## What was built
`ImapBackend` implements `MailBackend` + `MailOrganizer` from `openmail-core`.
Modules: `conn` (TLS/STARTTLS open + LOGIN/XOAUTH2), `tls`, `pool` (bounded sessions),
`ops` (typed IMAP commands, COPYUID/LIST RETURN parsing), `paging` + `cursor`,
`search` (SearchQuery -> IMAP keys), `mime` (mail-parser + ammonia), `thread`, `utf7`,
`backend`. Extras beyond the core traits: `ImapBackend::thread()` (entries labelled
Anchor/Exact/Heuristic, `ThreadEntry` lives in this crate) and `fetch_attachment()`.

## Stack decision
async-imap 0.12 (`runtime-tokio`, default features off) + tokio + tokio-rustls 0.26 (ring
provider) + rustls-native-certs (fallback: webpki-roots) + mail-parser 1.0.1 (`full_encoding`,
MSRV 1.98 OK on 1.100) + ammonia 4.2.5. Verified, not assumed: async-imap compiles only with
tokio's `AsyncRead/AsyncWrite` under `runtime-tokio`, and every integration test drives it on a
tokio multi-thread runtime against a real server. Certificate + hostname verification is always
on; there is no insecure switch. Private CAs: `ImapBackend::with_extra_roots`.
STARTTLS refuses to continue in clear text if the server rejects the upgrade.

## Behaviour notes
- Sessions: lazy, per-account semaphore (`max_connections`), global semaphore
  (`max_global_connections`). Idle sessions keep their global permit and are evicted (with LOGOUT,
  permit held until it finishes) when another account needs a socket. Pooled sessions are NOOP-checked
  before reuse; a dead session during an op is replaced and the op retried once (not for MOVE).
  Pool wait timeout -> `LimitExceeded`; command timeout -> `Timeout` and the session is discarded.
- `with_session!` macro instead of an `AsyncFnMut` parameter: rustc could not prove futures from
  async closures over `&mut Session` are `Send` ("implementation of Send is not general enough").
  Transport is a concrete `TlsTransport` newtype for the same reason.
- Pagination: UID SEARCH then newest-first; cursor = folder + UIDVALIDITY + lowest UID returned.
  `has_attachment` has no IMAP key, so it is a client-side filter on BODYSTRUCTURE with a scan cap
  of 500 candidates per call (cursor continues past the cap).
- Non-ASCII search values use `SEARCH CHARSET UTF-8` with quoted strings (no literals); verified
  against GreenMail. Control characters in search values are rejected (command-injection guard).
- MOVE: `UID MOVE` when advertised, else `UID COPY` + `\Deleted` + `UID EXPUNGE <uid>` (needs UIDPLUS;
  otherwise `Unsupported` - plain EXPUNGE is never used). New reference comes from COPYUID.
- Write ops also check `read_only`/`permissions.organize` (defence in depth; policy lives in security).
- `get_message` probes RFC822.SIZE first; > 32 MiB -> `LimitExceeded`. (Partial `BODY[]<0.n>` is not
  parsed by async-imap against GreenMail, hence the two-step fetch.)
- Errors never include server bytes: I/O errors keep only `ErrorKind` (an early parse failure leaked
  message text into an error string; fixed).
- HTML: ammonia with img/picture/video/audio/iframe/object/embed/svg/form/link/style/script removed,
  only http/https/mailto links, `rel="noopener noreferrer nofollow"`. Nothing is ever fetched.
- Threading is single-folder (IMAP limitation); `get_thread` (trait) returns Anchor+Exact only.

## Tests / commands run
- `cargo fmt -p openmail-imap`, `cargo clippy -p openmail-imap --all-targets -- -D warnings`: clean.
- `cargo test -p openmail-imap`: 22 unit + 10 integration pass (GreenMail 2.1.3 in docker; an in-process
  TLS proxy in tests/greenmail/harness.rs terminates TLS/STARTTLS, counts sockets, kills connections,
  and can hide the MOVE capability to exercise the fallback). Covered: login, auth failure, STARTTLS,
  untrusted-cert rejection, folders/roles, fetch, search, flags, move (both paths, bystander `\Deleted`
  survives), UIDVALIDITY change (real recreate) for messages and cursors, disconnect/reconnect,
  per-account cap, 100 accounts under a global cap of 4 (proxy-observed peak <= 4, run 3x), pool timeout,
  threading exact/heuristic. Tests skip loudly without docker; `OPENMAIL_REQUIRE_DOCKER=1` makes that a failure.
- `cargo deny` (no deny.toml in repo; ran with a scratch config): licenses OK; advisories flag only
  *unmaintained* notices (`chrono` via async-imap, `pin-utils`), no vulnerabilities. Needs an owner decision
  for the Gate-6 audit. webpki-roots is CDLA-Permissive-2.0 (fallback roots only).

## NOT done / limits
- OAuth2 (XOAUTH2) code path is written but untested against any server.
- RFC 6154 `LIST ... RETURN (SPECIAL-USE)` path is untested (GreenMail has no SPECIAL-USE); roles from
  config `FolderMap` are tested. No name-based role guessing.
- No IDLE, no CONDSTORE/QRESYNC, no THREAD/SORT extensions, no ESEARCH (page search is O(matches) UIDs).
- Moving without COPYUID in the reply fails with `Internal` after the move happened (message is safe in
  the destination; caller must re-list).
- Folder hierarchy delimiters are reported as the server sends them ("." on GreenMail).
- Only tested against GreenMail (+ proxy); not Dovecot/Gmail/Outlook.
