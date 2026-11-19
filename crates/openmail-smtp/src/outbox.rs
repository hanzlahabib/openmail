//! Outbox contract: the durable record that makes sending idempotent.
//!
//! State machine (per `(account, idempotency_key)`):
//! `Pending -> Accepted | Rejected | Uncertain`. `Rejected` means the server
//! definitively did not take the message (or we failed before DATA began), so the
//! same key may be retried. `Accepted` and `Uncertain` are terminal for automatic
//! behaviour: only an operator's `resolve_uncertain` can move `Uncertain` on.
use std::time::Duration;

use openmail_core::Result;
use openmail_core::ids::AccountId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    Pending,
    Accepted,
    Rejected,
    Uncertain,
}

impl OutboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Uncertain => "uncertain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "uncertain" => Self::Uncertain,
            _ => return None,
        })
    }
}

/// Operator verdict for an `Uncertain` message after checking the real Sent folder
/// / recipient / server logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The message was in fact delivered; never re-send.
    Delivered,
    /// The message was not delivered; the same key may be sent again.
    NotDelivered,
}

#[derive(Debug, Clone)]
pub struct NewAttempt {
    pub account: AccountId,
    pub idempotency_key: String,
    /// Hex of `ContentHash`; a key reused with different content is refused.
    pub content_hash: String,
    pub message_id: String,
    pub recipients: u32,
    pub approval_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub account: AccountId,
    pub idempotency_key: String,
    pub content_hash: String,
    pub message_id: String,
    pub recipients: u32,
    pub state: OutboxState,
    /// The DATA command was (about to be) issued: anything unresolved is `Uncertain`.
    pub data_started: bool,
    pub attempts: u32,
    pub detail: Option<String>,
    pub updated_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// Caller owns the attempt and may talk to the server.
    Started(OutboxRecord),
    /// A record already decided what happens; the caller must not send.
    Existing(OutboxRecord),
}

/// One row per send attempt. Never contains subject, body or addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: String,
    pub account: AccountId,
    pub idempotency_key: String,
    pub message_id: String,
    pub recipients: u32,
    pub attempt: u32,
    pub outcome: String,
    pub approval_token: String,
    pub detail: Option<String>,
}

#[allow(async_fn_in_trait)] // internal contract; callers are generic over the store
pub trait OutboxStore: Send + Sync {
    /// Atomically claim or look up a key. See `OutboxState` for the rules; a key
    /// reused with a different content hash fails with `InvalidInput`.
    async fn begin(&self, attempt: NewAttempt, pending_lease: Duration) -> Result<Begin>;
    /// Durably record that DATA is about to start. Must complete before the DATA command is sent.
    async fn mark_data_started(&self, account: &AccountId, key: &str) -> Result<()>;
    /// Record the final state of an attempt (`Accepted`, `Rejected` or `Uncertain`).
    async fn finish(&self, account: &AccountId, key: &str, state: OutboxState, detail: Option<&str>) -> Result<()>;
    async fn get(&self, account: &AccountId, key: &str) -> Result<Option<OutboxRecord>>;
    /// Operator recovery: only valid while the record is `Uncertain`.
    async fn resolve_uncertain(&self, account: &AccountId, key: &str, outcome: Outcome, note: &str) -> Result<OutboxRecord>;
    /// Most recent first.
    async fn audit_entries(&self, account: &AccountId, limit: u32) -> Result<Vec<AuditEntry>>;
}
