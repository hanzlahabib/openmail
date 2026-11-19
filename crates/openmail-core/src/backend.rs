//! Read/organize contract implemented by `openmail-imap` and consumed by the MCP
//! and briefing layers. Generic use (no `dyn`) keeps native async-fn-in-trait.
use std::future::Future;

use crate::Result;
use crate::ids::{AccountId, MessageRef};
use crate::model::*;

/// Futures are `Send` so servers (rmcp handlers, tokio::spawn) can be generic over the backend.
/// Implementors may still write `async fn` as long as the body is `Send`.
pub trait MailBackend: Send + Sync + 'static {
    fn test_connection(
        &self,
        account: &AccountId,
    ) -> impl Future<Output = Result<ConnectionReport>> + Send;
    fn list_folders(&self, account: &AccountId)
    -> impl Future<Output = Result<Vec<Folder>>> + Send;
    fn folder_status(
        &self,
        account: &AccountId,
        folder: &str,
    ) -> impl Future<Output = Result<FolderStatus>> + Send;
    fn list_messages(
        &self,
        account: &AccountId,
        folder: &str,
        page: PageRequest,
    ) -> impl Future<Output = Result<Page<MessageSummary>>> + Send;
    fn search(
        &self,
        account: &AccountId,
        query: &SearchQuery,
        page: PageRequest,
    ) -> impl Future<Output = Result<Page<MessageSummary>>> + Send;
    /// Fails with `StaleReference` when UIDVALIDITY no longer matches.
    fn get_message(
        &self,
        reference: &MessageRef,
        max_body_bytes: usize,
    ) -> impl Future<Output = Result<Message>> + Send;
    fn get_thread(
        &self,
        reference: &MessageRef,
    ) -> impl Future<Output = Result<Vec<MessageSummary>>> + Send;
}

/// Write-side operations; separate trait so read-only deployments can't call them.
pub trait MailOrganizer: Send + Sync + 'static {
    fn set_seen(
        &self,
        reference: &MessageRef,
        seen: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    fn set_flagged(
        &self,
        reference: &MessageRef,
        flagged: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    fn move_message(
        &self,
        reference: &MessageRef,
        dest_folder: &str,
    ) -> impl Future<Output = Result<MessageRef>> + Send;
}

/// Resolves a `CredentialRef` to a secret at the moment of use (never cached in
/// config structs). Implemented by `openmail-security`; tests use in-memory fakes.
pub trait SecretSource: Send + Sync {
    fn resolve(&self, reference: &crate::config::CredentialRef) -> Result<secrecy::SecretString>;
}

/// Draft management in the account's Drafts folder (IMAP APPEND/STORE/EXPUNGE).
/// Requires `permissions.drafts`; the caller (MCP layer) authorizes before calling.
pub trait MailDrafts: Send + Sync + 'static {
    fn create_draft(
        &self,
        account: &AccountId,
        draft: DraftInput,
    ) -> impl Future<Output = Result<MessageRef>> + Send;
    /// Replaces the draft; returns the new reference (IMAP drafts are replaced, not edited in place).
    fn update_draft(
        &self,
        reference: &MessageRef,
        draft: DraftInput,
    ) -> impl Future<Output = Result<MessageRef>> + Send;
    fn delete_draft(&self, reference: &MessageRef) -> impl Future<Output = Result<()>> + Send;
}

/// Attachment bytes on demand; never touches the local filesystem.
pub trait AttachmentSource: Send + Sync + 'static {
    /// Fails with `LimitExceeded` when the part is larger than `max_bytes`.
    fn get_attachment(
        &self,
        reference: &MessageRef,
        index: u32,
        max_bytes: usize,
    ) -> impl Future<Output = Result<AttachmentData>> + Send;
}

/// Stores a copy of a delivered message in the account's Sent folder (RFC 5322 bytes).
pub trait SentFolder: Send + Sync + 'static {
    fn append_sent(
        &self,
        account: &AccountId,
        rfc822: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send;
}
