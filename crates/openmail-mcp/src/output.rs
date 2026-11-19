//! Tool output types: deterministic field order, typed schemas, and explicit
//! `UntrustedText` for everything that originates in a mailbox.
use openmail_core::ErrorCode;
use openmail_core::model::{self, Untrusted};
use schemars::JsonSchema;
use serde::Serialize;

use crate::untrusted::{UNTRUSTED_NOTICE, UntrustedText};

fn text(s: String) -> UntrustedText {
    UntrustedText::from(s)
}
fn untrusted(u: Untrusted<String>) -> UntrustedText {
    UntrustedText::from(u.0)
}

/// Notice text attached to every result that includes mailbox text (field `_notice`).
pub type Notice = &'static str;

pub const NOTICE: Notice = UNTRUSTED_NOTICE;

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
    /// Fixed diagnostic chosen by this server from the check results; never server text.
    pub detail: Option<&'static str>,
    /// Machine-readable classification of an IMAP failure: `credential_missing`, `auth_rejected`,
    /// `connection_failed`, `timeout`, `config_invalid` or `other`. Null when IMAP is ok.
    pub failure: Option<&'static str>,
}

impl ConnectionOut {
    /// Expose only fixed diagnostics. Backend details can contain provider-supplied text.
    pub fn from_report(r: model::ConnectionReport) -> Self {
        let detail = match (r.imap_ok, r.imap_error_code, r.smtp_ok) {
            (false, Some(ErrorCode::CredentialMissing), _) => Some(
                "No mailbox credential is configured on the server for this account (this is the mailbox login, not your ChatGPT or OpenMail login); the operator must add it",
            ),
            (false, Some(ErrorCode::AuthFailed), _) => {
                Some("IMAP authentication failed; check the mailbox credential and login settings")
            }
            (false, Some(ErrorCode::Timeout), _) => Some("IMAP connection check timed out"),
            (false, Some(ErrorCode::ConnectionFailed), _) => {
                Some("IMAP connection failed; check the host, port, network and TLS settings")
            }
            (false, _, _) => Some("IMAP connection check failed; see the operator log"),
            (true, _, Some(false)) => Some("SMTP connection check failed; see the operator log"),
            (true, _, _) if r.detail.is_some() => {
                Some("connection check passed with warnings; see the operator log")
            }
            _ => None,
        };
        let failure = (!r.imap_ok).then_some(match r.imap_error_code {
            Some(ErrorCode::CredentialMissing) => "credential_missing",
            Some(ErrorCode::AuthFailed) => "auth_rejected",
            Some(ErrorCode::ConnectionFailed) => "connection_failed",
            Some(ErrorCode::Timeout) => "timeout",
            Some(ErrorCode::ConfigInvalid) => "config_invalid",
            _ => "other",
        });
        if !r.imap_ok || r.smtp_ok == Some(false) {
            tracing::warn!(
                account = %r.account,
                imap_error_code = ?r.imap_error_code,
                smtp_ok = ?r.smtp_ok,
                "mail connection check failed"
            );
        }
        Self {
            account: r.account.to_string(),
            imap_ok: r.imap_ok,
            smtp_ok: r.smtp_ok,
            capabilities: crate::sanitize::safe_capabilities(r.capabilities),
            detail,
            failure,
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
        Self {
            name: text(f.name),
            delimiter: f.delimiter.map(String::from),
            role: f.role,
            selectable: f.selectable,
        }
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
        Self {
            name: a.name.map(text),
            email: text(a.email),
        }
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
            flags: FlagsOut {
                seen: f.seen,
                flagged: f.flagged,
                answered: f.answered,
                draft: f.draft,
                deleted: f.deleted,
            },
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
        Self {
            index: a.index,
            filename: a.filename.map(text),
            content_type: text(a.content_type),
            size: a.size,
            inline: a.inline,
        }
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
