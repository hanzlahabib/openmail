//! openmail-mcp: rmcp server exposing read/search mail tools over any `MailBackend`.
//! Mailbox text is untrusted: see [`untrusted`] and the per-tool descriptions.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
mod backend_bound;
mod error;
mod input;
mod limits;
mod output;
mod search;
mod server;
mod stdio;
pub mod untrusted;

pub use backend_bound::SendBackend;
pub use error::ToolError;
pub use server::{OpenMailServer, build_server};
pub use stdio::{ServeError, serve_io, serve_stdio};
