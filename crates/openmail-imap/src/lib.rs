//! openmail-imap — see docs/ARCHITECTURE.md for ownership and contracts.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod attach;
pub mod backend;
pub mod conn;
pub mod cursor;
pub mod error;
pub mod html;
pub mod hygiene;
pub mod mime;
pub mod ops;
pub mod outgoing;
pub mod paging;
pub mod pool;
pub mod search;
pub mod thread;
pub mod tls;
pub mod utf7;

pub use backend::ImapBackend;
pub use openmail_core::model::AttachmentData;
pub use thread::{ThreadEntry, ThreadRelation};
