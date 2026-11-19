//! openmail-smtp — SMTP engine, message builder and idempotent outbox.
//!
//! This crate never decides *whether* a send is permitted; the caller supplies an
//! [`ApprovalProof`] bound to the exact content ([`SendRequest::content_hash`]).
//! What it does guarantee: TLS is never downgraded, the sender identity is
//! validated, and a message whose fate is unknown is never re-sent automatically
//! (see `RECOVERY.md`).
pub mod approval;
pub mod builder;
pub mod client;
pub mod outbox;
pub mod request;
pub mod sqlite_outbox;

pub use approval::{ApprovalProof, ContentHash};
pub use client::{SendOutcome, SmtpClient, SmtpOptions};
pub use outbox::{AuditEntry, OutboxRecord, OutboxState, OutboxStore, Outcome};
pub use request::{Attachment, SendRequest, SmtpLimits};
pub use sqlite_outbox::SqliteOutbox;
