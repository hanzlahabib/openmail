//! Input types of the organize/draft/send/attachment tools. Strict schemas (unknown fields are
//! errors) with explicit size bounds; deeper checks happen in the tool.
use openmail_core::model::Address;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::error::ToolError;
use crate::sanitize::strip_invisible;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FlagInput {
    /// Opaque message_ref from a list/search result.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// true (default) sets the flag, false clears it.
    pub flagged: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveInput {
    /// Opaque message_ref from a list/search result.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// Destination folder exactly as returned by mail_list_folders.
    #[schemars(length(min = 1, max = 512))]
    pub dest_folder: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentInput {
    /// Opaque message_ref from a list/search result.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// Attachment index from mail_list_attachments.
    pub index: u32,
}

/// One recipient. `name` is display text only; `email` must be a plain `local@domain`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressInput {
    #[schemars(length(min = 3, max = 320))]
    pub email: String,
    #[schemars(length(max = 200))]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateDraftInput {
    /// Account id as returned by mail_list_accounts.
    #[schemars(length(min = 1, max = 64))]
    pub account: String,
    #[schemars(length(max = 100))]
    pub to: Vec<AddressInput>,
    #[schemars(length(max = 100))]
    pub cc: Option<Vec<AddressInput>>,
    #[schemars(length(max = 100))]
    pub bcc: Option<Vec<AddressInput>>,
    #[schemars(length(max = 998))]
    pub subject: String,
    /// Plain-text body.
    #[schemars(length(max = 1048576))]
    pub text: Option<String>,
    /// HTML body (optional; plain text is preferred).
    #[schemars(length(max = 1048576))]
    pub html: Option<String>,
    /// message_ref of the message being answered; threading headers are derived from it.
    #[schemars(length(min = 1, max = 2048))]
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDraftInput {
    /// message_ref of the existing draft. The result carries the NEW reference.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    #[schemars(length(max = 100))]
    pub to: Vec<AddressInput>,
    #[schemars(length(max = 100))]
    pub cc: Option<Vec<AddressInput>>,
    #[schemars(length(max = 100))]
    pub bcc: Option<Vec<AddressInput>>,
    #[schemars(length(max = 998))]
    pub subject: String,
    #[schemars(length(max = 1048576))]
    pub text: Option<String>,
    #[schemars(length(max = 1048576))]
    pub html: Option<String>,
    #[schemars(length(min = 1, max = 2048))]
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareReplyInput {
    /// message_ref of the message to answer.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// Your reply text. It is the ONLY content taken from you; nothing is copied from the mail.
    #[schemars(length(max = 1048576))]
    pub text: String,
    /// Reply to everyone on the message (default false: sender / Reply-To only).
    pub reply_all: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendApprovedInput {
    /// message_ref of the draft to send.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// Approval id granted by the account owner out of band. Omit it to create a pending
    /// request the owner can approve.
    #[schemars(length(min = 1, max = 64))]
    pub approval_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardApprovedInput {
    /// message_ref of the message to forward.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    #[schemars(length(min = 1, max = 100))]
    pub to: Vec<AddressInput>,
    #[schemars(length(max = 100))]
    pub cc: Option<Vec<AddressInput>>,
    /// Your own note placed above the forwarded text.
    #[schemars(length(max = 1048576))]
    pub note: Option<String>,
    /// Approval id granted by the account owner out of band; omit to create a pending request.
    #[schemars(length(min = 1, max = 64))]
    pub approval_id: Option<String>,
}

impl AddressInput {
    /// Header-injection safe: the address must be a plain `local@domain` (no whitespace, control
    /// characters, quotes, angle brackets, commas) and the display name loses control/invisible chars.
    pub fn into_address(self) -> Result<Address, ToolError> {
        let email = self.email.trim().to_owned();
        let bad = |c: char| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '<' | '>' | ',' | ';' | '"' | '(' | ')' | '\\' | '[' | ']'
                )
        };
        let ok = email
            .split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && !d.is_empty() && !d.contains('@'))
            && !email.chars().any(bad);
        if !ok {
            return Err(ToolError::invalid(
                "recipient must be a plain address like name@example.com",
            ));
        }
        let name = self
            .name
            .map(|n| {
                strip_invisible(&n)
                    .replace(['\r', '\n'], " ")
                    .trim()
                    .to_owned()
            })
            .filter(|n| !n.is_empty());
        Ok(Address { name, email })
    }
}

pub fn addresses(list: Option<Vec<AddressInput>>) -> Result<Vec<Address>, ToolError> {
    list.unwrap_or_default()
        .into_iter()
        .map(AddressInput::into_address)
        .collect()
}
