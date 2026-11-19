//! openmail-smtp — SMTP engine, message builder and idempotent outbox.
//!
//! This crate never decides *whether* a send is permitted, but it refuses to send
//! without a sealed [`ApprovalProof`], obtainable only by running an
//! [`ApprovalConsumer`] against a descriptor derived from the actual request.
//! What it does guarantee: TLS is never downgraded, the sender identity is
//! validated, and a message whose fate is unknown is never re-sent automatically
//! (see `RECOVERY.md`).
pub mod approval;
pub mod builder;
pub mod client;
pub mod outbox;
pub mod request;
pub mod sqlite_outbox;

pub use approval::{ApprovalConsumer, ApprovalProof, ContentHash, SendRequestDescriptor};
pub use client::{SendOutcome, SmtpClient, SmtpOptions};
pub use outbox::{AuditEntry, OutboxRecord, OutboxState, OutboxStore, Outcome};
pub use request::{Attachment, SendRequest, SmtpLimits};
pub use sqlite_outbox::SqliteOutbox;
