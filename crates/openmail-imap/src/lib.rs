//! openmail-imap — see docs/ARCHITECTURE.md for ownership and contracts.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod backend;
pub mod conn;
pub mod cursor;
pub mod error;
pub mod mime;
pub mod ops;
pub mod paging;
pub mod pool;
pub mod search;
pub mod thread;
pub mod tls;
pub mod utf7;

pub use backend::{AttachmentData, ImapBackend};
pub use thread::{ThreadEntry, ThreadRelation};
