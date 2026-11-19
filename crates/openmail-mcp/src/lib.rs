//! openmail-mcp: rmcp server exposing read/search/organize/draft/send mail tools over any `MailBackend`.
//! Mailbox text is untrusted: see [`untrusted`] and the per-tool descriptions.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
mod access;
mod backend;
mod error;
mod input;
mod limits;
mod outgoing;
mod output;
mod sanitize;
mod search;
mod server;
mod stdio;
mod tools_brief;
mod tools_draft;
mod tools_organize;
mod tools_read;
mod tools_send;
pub mod untrusted;

pub use access::{PrincipalResolver, RateLimits, stdio_principal};
pub use backend::FullBackend;
pub use error::ToolError;
pub use outgoing::{ApprovalRequester, BoxFuture, Outgoing, SmtpOutgoing};
pub use server::{OpenMailServer, build_server, build_server_with, build_server_with_resolver};
pub use stdio::{ServeError, serve_io, serve_stdio};
