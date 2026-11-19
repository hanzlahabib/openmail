//! Provider-neutral message models. Everything sourced from a mailbox is UNTRUSTED
//! data; `Untrusted<T>` makes that visible in types so tool layers cannot hand
//! mail text to a model as if it were instructions.
use serde::{Deserialize, Serialize};

use crate::ids::{AccountId, MessageRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Untrusted<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub name: String,
    pub delimiter: Option<char>,
    /// RFC 6154 special-use role when the server reports one (inbox/sent/drafts/archive/trash/junk).
    pub role: Option<String>,
    pub selectable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderStatus {
    pub name: String,
    pub exists: u32,
    pub unseen: Option<u32>,
    pub uid_validity: u32,
    pub uid_next: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub reference: MessageRef,
    pub message_id: Option<String>,
    pub subject: Untrusted<String>,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    /// RFC 3339 UTC.
    pub date: Option<String>,
    pub flags: Flags,
    pub has_attachments: bool,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub index: u32,
    pub filename: Option<String>,
    pub content_type: String,
    pub size: u32,
    pub inline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageBody {
    pub text: Option<Untrusted<String>>,
    /// Sanitized HTML only (scripts, remote resources and event handlers stripped).
    pub html_sanitized: Option<Untrusted<String>>,
    /// True when the body was cut at `max_body_bytes`.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub summary: MessageSummary,
    pub cc: Vec<Address>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub body: MessageBody,
    pub attachments: Vec<AttachmentMeta>,
}

/// Structured filters; translated to IMAP SEARCH by the IMAP crate. Only what IMAP
/// can answer is exposed — there is no semantic search.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    pub folder: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub text: Option<String>,
    /// RFC 3339 dates (inclusive since, exclusive before).
    pub since: Option<String>,
    pub before: Option<String>,
    pub unread: Option<bool>,
    pub flagged: Option<bool>,
    pub has_attachment: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    pub cursor: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionReport {
    pub account: AccountId,
    pub imap_ok: bool,
    pub smtp_ok: Option<bool>,
    pub capabilities: Vec<String>,
    /// Sanitized, actionable diagnostic; never contains credentials.
    pub detail: Option<String>,
}

/// Input for creating or replacing a draft. Content only; sending is a separate approved action.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DraftInput {
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    /// When replying: the message being answered (threading headers are derived from it).
    pub in_reply_to: Option<crate::ids::MessageRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentData {
    pub meta: AttachmentMeta,
    pub bytes: Vec<u8>,
}
