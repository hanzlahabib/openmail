//! Output types of the write tools. Only server-generated values or sanitized mailbox text.
use schemars::JsonSchema;
use serde::Serialize;

use crate::untrusted::UntrustedText;

#[derive(Debug, Serialize, JsonSchema)]
pub struct OkOut {
    pub ok: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MovedOut {
    pub ok: bool,
    /// Reference of the message in its new folder; the old reference is no longer valid.
    pub message_ref: String,
    /// Destination folder name.
    pub folder: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DraftOut {
    pub ok: bool,
    /// Reference of the draft; pass it to mail_send_approved after the owner approves.
    pub message_ref: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AttachmentOut {
    pub message_ref: String,
    pub index: u32,
    /// Declared content type (data from the sender, not verified against the bytes).
    pub content_type: String,
    /// Sanitized basename: no path separators, no control characters.
    pub filename: UntrustedText,
    pub size: usize,
    /// Standard base64 of the attachment bytes. Never written to disk by the server.
    pub data_base64: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SendOut {
    pub sent: bool,
    /// True when the idempotency key was already accepted: nothing was sent this time.
    pub already_sent: bool,
    pub message_id: String,
    /// Whether a copy was stored in the Sent folder (best effort; a failure does not unsend).
    pub sent_copy_saved: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PrepareReplyOut {
    pub ok: bool,
    pub message_ref: String,
    /// Recipient addresses the reply was addressed to (derived from the source headers).
    pub to: Vec<UntrustedText>,
    pub subject: UntrustedText,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BulkMarkOut {
    /// True when nothing was changed because `dry_run` was set.
    pub dry_run: bool,
    /// Unread messages that matched (or refs supplied).
    pub matched: usize,
    pub marked_read: usize,
    pub failed: usize,
    /// True when more than 500 matched: call again to continue (marked mail no longer matches).
    pub truncated: bool,
}
