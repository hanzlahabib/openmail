//! Read/organize contract implemented by `openmail-imap` and consumed by the MCP
//! and briefing layers. Generic use (no `dyn`) keeps native async-fn-in-trait.
use crate::Result;
use crate::ids::{AccountId, MessageRef};
use crate::model::*;

#[allow(async_fn_in_trait)] // internal contract; callers are generic over the backend
pub trait MailBackend: Send + Sync {
    async fn test_connection(&self, account: &AccountId) -> Result<ConnectionReport>;
    async fn list_folders(&self, account: &AccountId) -> Result<Vec<Folder>>;
    async fn folder_status(&self, account: &AccountId, folder: &str) -> Result<FolderStatus>;
    async fn list_messages(&self, account: &AccountId, folder: &str, page: PageRequest) -> Result<Page<MessageSummary>>;
    async fn search(&self, account: &AccountId, query: &SearchQuery, page: PageRequest) -> Result<Page<MessageSummary>>;
    /// Fails with `StaleReference` when UIDVALIDITY no longer matches.
    async fn get_message(&self, reference: &MessageRef, max_body_bytes: usize) -> Result<Message>;
    async fn get_thread(&self, reference: &MessageRef) -> Result<Vec<MessageSummary>>;
}

/// Write-side operations; separate trait so read-only deployments can't call them.
#[allow(async_fn_in_trait)]
pub trait MailOrganizer: Send + Sync {
    async fn set_seen(&self, reference: &MessageRef, seen: bool) -> Result<()>;
    async fn set_flagged(&self, reference: &MessageRef, flagged: bool) -> Result<()>;
    async fn move_message(&self, reference: &MessageRef, dest_folder: &str) -> Result<MessageRef>;
}
