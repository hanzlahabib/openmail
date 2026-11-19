//! Tool input types. `deny_unknown_fields` makes schemas strict
//! (`additionalProperties: false`) so a mistyped argument is an error, not ignored.
use schemars::JsonSchema;
use serde::Deserialize;

/// Upper bound for any free-text filter or identifier argument.
pub const MAX_ARG_CHARS: usize = 512;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountInput {
    /// Account id as returned by mail_list_accounts.
    #[schemars(length(min = 1, max = 64))]
    pub account: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FolderStatusInput {
    /// Account id as returned by mail_list_accounts.
    #[schemars(length(min = 1, max = 64))]
    pub account: String,
    /// Folder name exactly as returned by mail_list_folders.
    #[schemars(length(min = 1, max = 512))]
    pub folder: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListMessagesInput {
    /// Account id as returned by mail_list_accounts.
    #[schemars(length(min = 1, max = 64))]
    pub account: String,
    /// Folder name exactly as returned by mail_list_folders.
    #[schemars(length(min = 1, max = 512))]
    pub folder: String,
    /// Opaque cursor from a previous result's next_cursor.
    #[schemars(length(max = 2048))]
    pub cursor: Option<String>,
    /// Page size; defaults to 20 and is capped by the server's configured maximum.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<u32>,
}

/// Which parts of a message to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageField {
    Headers,
    Text,
    Html,
    Attachments,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetMessageInput {
    /// Opaque message_ref from a list/search result.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
    /// Parts to return; defaults to ["headers", "text"]. "html" is sanitized HTML.
    #[schemars(length(max = 4))]
    pub fields: Option<Vec<MessageField>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageRefInput {
    /// Opaque message_ref from a list/search result.
    #[schemars(length(min = 1, max = 2048))]
    pub message_ref: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchInput {
    /// Account id as returned by mail_list_accounts.
    #[schemars(length(min = 1, max = 64))]
    pub account: String,
    /// Restrict to one folder; defaults to the backend's default search scope.
    #[schemars(length(min = 1, max = 512))]
    pub folder: Option<String>,
    /// Sender contains this text.
    #[schemars(length(min = 1, max = 512))]
    pub from: Option<String>,
    /// Recipient contains this text.
    #[schemars(length(min = 1, max = 512))]
    pub to: Option<String>,
    /// Subject contains this text.
    #[schemars(length(min = 1, max = 512))]
    pub subject: Option<String>,
    /// Message text contains this (IMAP substring match, not semantic search).
    #[schemars(length(min = 1, max = 512))]
    pub text: Option<String>,
    /// Received on/after this RFC 3339 timestamp or YYYY-MM-DD date.
    #[schemars(length(min = 1, max = 64))]
    pub since: Option<String>,
    /// Received before this RFC 3339 timestamp or YYYY-MM-DD date.
    #[schemars(length(min = 1, max = 64))]
    pub before: Option<String>,
    /// Only unread (true) or only read (false) messages.
    pub unread: Option<bool>,
    /// Only flagged (true) or unflagged (false) messages.
    pub flagged: Option<bool>,
    /// Only messages with (true) or without (false) attachments.
    pub has_attachment: Option<bool>,
    /// Opaque cursor from a previous result's next_cursor.
    #[schemars(length(max = 2048))]
    pub cursor: Option<String>,
    /// Page size; defaults to 20 and is capped by the server's configured maximum.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<u32>,
}
