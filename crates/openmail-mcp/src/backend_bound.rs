//! rmcp tool handlers must be `Send`, but `openmail_core::backend::MailBackend` uses plain
//! async-fn-in-trait whose futures are not guaranteed `Send` (and return-type notation,
//! the stable-Rust-free way to demand it, is still unstable on 1.100).
//!
//! This trait is the same read contract with `Send` futures spelled out. The server is
//! generic over it. See NEEDS_CORE_CHANGE.md: once core's `MailBackend` methods return
//! `impl Future<Output = ..> + Send`, replace the implementors with one blanket impl
//! `impl<T: MailBackend> SendBackend for T`.
use std::future::Future;

use openmail_core::Result;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{ConnectionReport, Folder, FolderStatus, Message, MessageSummary, Page, PageRequest, SearchQuery};

pub trait SendBackend: Send + Sync + 'static {
    fn test_connection(&self, account: &AccountId) -> impl Future<Output = Result<ConnectionReport>> + Send;
    fn list_folders(&self, account: &AccountId) -> impl Future<Output = Result<Vec<Folder>>> + Send;
    fn folder_status(&self, account: &AccountId, folder: &str) -> impl Future<Output = Result<FolderStatus>> + Send;
    fn list_messages(&self, account: &AccountId, folder: &str, page: PageRequest) -> impl Future<Output = Result<Page<MessageSummary>>> + Send;
    fn search(&self, account: &AccountId, query: &SearchQuery, page: PageRequest) -> impl Future<Output = Result<Page<MessageSummary>>> + Send;
    fn get_message(&self, reference: &MessageRef, max_body_bytes: usize) -> impl Future<Output = Result<Message>> + Send;
    fn get_thread(&self, reference: &MessageRef) -> impl Future<Output = Result<Vec<MessageSummary>>> + Send;
}
