# Needed change in openmail-core

**What:** declare the `MailBackend` (and `MailOrganizer`) methods as
`fn x(&self, ..) -> impl Future<Output = Result<T>> + Send;` instead of `async fn x(..)`.
Implementors can still write `async fn` as long as their future is `Send`.

**Why:** rmcp tool handlers must be `Send`. With `async fn` in the trait, the returned futures
are not `Send` for generic `B`, so a server generic over `MailBackend` does not compile
(`E0277: impl Future ... cannot be sent between threads safely`). Return-type notation
(`B: MailBackend<foo(..): Send>`) is still unstable on rustc 1.100 (E0658).

**Workaround in place:** `openmail_mcp::SendBackend` (src/backend_bound.rs) mirrors the read
contract with `Send` futures; the server is generic over it. After the core change, delete the
trait body and add `impl<T: MailBackend> SendBackend for T {}`-style forwarding (or make the
server use `MailBackend` directly). Until then `openmail-imap` must implement `SendBackend`
too, or the integrator applies this core change at merge time.
