//! openmail-mcp: rmcp server exposing read/search mail tools over any `MailBackend`.
//! Mailbox text is untrusted: see [`untrusted`] and the per-tool descriptions.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
mod access;
mod error;
mod input;
mod limits;
mod output;
mod sanitize;
mod search;
mod server;
mod stdio;
pub mod untrusted;

pub use access::{RateLimits, stdio_principal};
pub use error::ToolError;
pub use server::{OpenMailServer, build_server, build_server_with};
pub use stdio::{ServeError, serve_io, serve_stdio};
