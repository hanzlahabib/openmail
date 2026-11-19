//! Tool output types: deterministic field order, typed schemas, and explicit
//! `UntrustedText` for everything that originates in a mailbox.
use openmail_core::model::{self, Untrusted};
use schemars::JsonSchema;
use serde::Serialize;

use crate::untrusted::{UNTRUSTED_NOTICE, UntrustedText};

fn text(s: String) -> UntrustedText {
    UntrustedText(s)
}
fn untrusted(u: Untrusted<String>) -> UntrustedText {
    UntrustedText(u.0)
}

/// Marker field present on every result that includes mailbox text.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Notice(#[schemars(length(min = 1))] pub &'static str);

impl Notice {
    pub const fn untrusted() -> Self {
        Self(UNTRUSTED_NOTICE)
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PermissionsOut {
    pub organize: bool,
    pub drafts: bool,
    pub send: bool,
    pub delete: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AccountOut {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub read_only: bool,
    pub permissions: PermissionsOut,
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_configured: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AccountsOut {
    pub accounts: Vec<AccountOut>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ConnectionOut {
    pub account: String,
    pub imap_ok: bool,
    pub smtp_ok: Option<bool>,
    pub capabilities: Vec<String>,
    /// Sanitized diagnostic from the backend; never contains credentials.
    pub detail: Option<String>,
}

impl ConnectionOut {
    pub fn from_report(r: model::ConnectionReport, detail_cap: usize) -> Self {
        Self {
            account: r.account.to_string(),
            imap_ok: r.imap_ok,
            smtp_ok: r.smtp_ok,
            capabilities: r.capabilities,
            detail: r.detail.map(|d| crate::limits::truncate_utf8(d, detail_cap).0),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FolderOut {
    pub name: UntrustedText,
    pub delimiter: Option<String>,
    /// RFC 6154 special-use role (inbox, sent, drafts, archive, trash, junk) when known.
    pub role: Option<String>,
    pub selectable: bool,
}

impl From<model::Folder> for FolderOut {
    fn from(f: model::Folder) -> Self {
        Self { name: text(f.name), delimiter: f.delimiter.map(String::from), role: f.role, selectable: f.selectable }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FoldersOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub account: String,
    pub folders: Vec<FolderOut>,
    /// True when the folder list was cut at the server's result cap.
    pub truncated: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FolderStatusOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub account: String,
    pub name: UntrustedText,
    pub exists: u32,
    pub unseen: Option<u32>,
    pub uid_validity: u32,
    pub uid_next: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AddressOut {
    pub name: Option<UntrustedText>,
    pub email: UntrustedText,
}

impl From<model::Address> for AddressOut {
    fn from(a: model::Address) -> Self {
        Self { name: a.name.map(text), email: text(a.email) }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FlagsOut {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SummaryOut {
    /// Opaque reference to pass to the message tools.
    pub message_ref: String,
    pub message_id: Option<UntrustedText>,
    pub subject: UntrustedText,
    pub from: Vec<AddressOut>,
    pub to: Vec<AddressOut>,
    /// RFC 3339 UTC.
    pub date: Option<String>,
    pub flags: FlagsOut,
    pub has_attachments: bool,
    pub size: Option<u32>,
}

impl From<model::MessageSummary> for SummaryOut {
    fn from(m: model::MessageSummary) -> Self {
        let f = m.flags;
        Self {
            message_ref: m.reference.encode(),
            message_id: m.message_id.map(text),
            subject: untrusted(m.subject),
            from: m.from.into_iter().map(Into::into).collect(),
            to: m.to.into_iter().map(Into::into).collect(),
            date: m.date,
            flags: FlagsOut { seen: f.seen, flagged: f.flagged, answered: f.answered, draft: f.draft, deleted: f.deleted },
            has_attachments: m.has_attachments,
            size: m.size,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MessageListOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub account: String,
    pub messages: Vec<SummaryOut>,
    /// Pass back as `cursor` for the next page; null on the last page.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ThreadOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub messages: Vec<SummaryOut>,
    /// True when the thread was cut at the server's result cap.
    pub truncated: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct HeadersOut {
    #[serde(flatten)]
    pub summary: SummaryOut,
    pub cc: Vec<AddressOut>,
    pub in_reply_to: Option<UntrustedText>,
    pub references: Vec<UntrustedText>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AttachmentOut {
    pub index: u32,
    pub filename: Option<UntrustedText>,
    pub content_type: UntrustedText,
    pub size: u32,
    pub inline: bool,
}

impl From<model::AttachmentMeta> for AttachmentOut {
    fn from(a: model::AttachmentMeta) -> Self {
        Self { index: a.index, filename: a.filename.map(text), content_type: text(a.content_type), size: a.size, inline: a.inline }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MessageOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub message_ref: String,
    /// Present when "headers" was requested.
    pub headers: Option<HeadersOut>,
    /// Present when "text" was requested and the message has a text part.
    pub text: Option<UntrustedText>,
    /// Sanitized HTML; present when "html" was requested and the message has an HTML part.
    pub html_sanitized: Option<UntrustedText>,
    /// True when text or html was cut at the body-size cap.
    pub body_truncated: bool,
    /// Present when "attachments" was requested.
    pub attachments: Option<Vec<AttachmentOut>>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AttachmentsOut {
    #[serde(rename = "_notice")]
    pub notice: Notice,
    pub message_ref: String,
    pub attachments: Vec<AttachmentOut>,
}
