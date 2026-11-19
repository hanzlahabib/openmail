//! Multi-mailbox aggregation for briefs.
//!
//! Fans out over accounts with bounded concurrency and a per-account timeout.
//! A failing or slow account never hides: it is reported with an explicit
//! [`AccountStatus`] while the healthy accounts still contribute messages.
use std::time::Duration;

use futures_util::future::join_all;
use openmail_core::ErrorCode;
use openmail_core::backend::MailBackend;
use openmail_core::ids::AccountId;
use openmail_core::model::{MessageSummary, PageRequest};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Page size per `list_messages` call; mid-sized to keep IMAP round trips low
/// without large single responses.
const PAGE_LIMIT: u32 = 100;

/// Supplies the last stored position per (account, folder) so a run resumes
/// where the previous one stopped, and receives the new position afterwards.
pub trait CursorStore: Send + Sync {
    fn load(&self, account: &AccountId, folder: &str) -> Option<String>;
}

/// A store that never has a cursor (always start from the newest page).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCursors;

impl CursorStore for NoCursors {
    fn load(&self, _account: &AccountId, _folder: &str) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct AggregateConfig {
    pub folder: String,
    /// Messages dated before `now - lookback` are dropped.
    pub lookback: Duration,
    pub now: OffsetDateTime,
    /// Upper bound on accounts fetched simultaneously.
    pub max_concurrency: usize,
    /// Deadline for one account's whole fetch (all pages).
    pub per_account_timeout: Duration,
    /// Stop paging an account once this many in-window messages were collected.
    pub max_messages_per_account: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
    Ok,
    Failed { code: ErrorCode, message: String },
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct AccountResult {
    pub account: AccountId,
    pub status: AccountStatus,
    pub messages: Vec<MessageSummary>,
    /// Cursor to persist for the next run; `None` when the account failed or is exhausted.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Aggregate {
    pub accounts: Vec<AccountResult>,
}

impl Aggregate {
    pub fn is_complete(&self) -> bool {
        self.accounts.iter().all(|a| a.status == AccountStatus::Ok)
    }

    pub fn failed_accounts(&self) -> impl Iterator<Item = &AccountResult> {
        self.accounts
            .iter()
            .filter(|a| a.status != AccountStatus::Ok)
    }
}

/// Fetch in-window messages from every account. Results keep the input order.
pub async fn aggregate<B: MailBackend, C: CursorStore>(
    backend: &B,
    cursors: &C,
    accounts: &[AccountId],
    cfg: &AggregateConfig,
) -> Aggregate {
    // A zero permit count would deadlock every account.
    let semaphore = Semaphore::new(cfg.max_concurrency.max(1));
    let work = accounts.iter().map(|account| {
        let semaphore = &semaphore;
        async move {
            let _permit = semaphore.acquire().await;
            fetch_account(backend, cursors, account, cfg).await
        }
    });
    Aggregate {
        accounts: join_all(work).await,
    }
}

async fn fetch_account<B: MailBackend, C: CursorStore>(
    backend: &B,
    cursors: &C,
    account: &AccountId,
    cfg: &AggregateConfig,
) -> AccountResult {
    let outcome = timeout(
        cfg.per_account_timeout,
        collect(backend, cursors, account, cfg),
    )
    .await;
    match outcome {
        Ok(Ok((messages, next_cursor))) => AccountResult {
            account: account.clone(),
            status: AccountStatus::Ok,
            messages,
            next_cursor,
        },
        Ok(Err(e)) => {
            tracing::warn!(account = %account, code = ?e.code(), "brief aggregation failed for account");
            let status = AccountStatus::Failed {
                code: e.code(),
                message: e.to_string(),
            };
            AccountResult {
                account: account.clone(),
                status,
                messages: Vec::new(),
                next_cursor: None,
            }
        }
        Err(_) => {
            tracing::warn!(account = %account, "brief aggregation timed out for account");
            AccountResult {
                account: account.clone(),
                status: AccountStatus::TimedOut,
                messages: Vec::new(),
                next_cursor: None,
            }
        }
    }
}

async fn collect<B: MailBackend, C: CursorStore>(
    backend: &B,
    cursors: &C,
    account: &AccountId,
    cfg: &AggregateConfig,
) -> openmail_core::Result<(Vec<MessageSummary>, Option<String>)> {
    let cutoff = cfg.now - cfg.lookback;
    let mut cursor = cursors.load(account, &cfg.folder);
    let mut out = Vec::new();
    loop {
        let page = backend
            .list_messages(
                account,
                &cfg.folder,
                PageRequest {
                    cursor: cursor.clone(),
                    limit: PAGE_LIMIT,
                },
            )
            .await?;
        out.extend(page.items.into_iter().filter(|m| in_window(m, cutoff)));
        cursor = page.next_cursor;
        if cursor.is_none() || out.len() >= cfg.max_messages_per_account {
            break;
        }
    }
    out.truncate(cfg.max_messages_per_account);
    Ok((out, cursor))
}

/// Messages with a missing or unparsable date are kept: dropping them would hide mail silently.
fn in_window(m: &MessageSummary, cutoff: OffsetDateTime) -> bool {
    match m
        .date
        .as_deref()
        .map(|d| OffsetDateTime::parse(d, &Rfc3339))
    {
        Some(Ok(date)) => date >= cutoff,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openmail_core::Error;
    use openmail_core::Result;
    use openmail_core::ids::MessageRef;
    use openmail_core::model::*;

    use super::*;

    struct Fake {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    fn summary(account: &AccountId, uid: u32, date: &str) -> MessageSummary {
        MessageSummary {
            reference: MessageRef {
                account: account.clone(),
                folder: "INBOX".into(),
                uid_validity: 1,
                uid,
            },
            message_id: None,
            subject: Untrusted("s".into()),
            from: vec![],
            to: vec![],
            date: Some(date.into()),
            flags: Flags::default(),
            has_attachments: false,
            size: None,
        }
    }

    impl MailBackend for Fake {
        async fn test_connection(&self, _: &AccountId) -> Result<ConnectionReport> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
        async fn list_folders(&self, _: &AccountId) -> Result<Vec<Folder>> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
        async fn folder_status(&self, _: &AccountId, _: &str) -> Result<FolderStatus> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
        async fn list_messages(
            &self,
            account: &AccountId,
            _: &str,
            page: PageRequest,
        ) -> Result<Page<MessageSummary>> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let result = match account.as_str() {
                "broken" => Err(Error::new(ErrorCode::AuthFailed, "bad login")),
                "slow" => {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok(Page {
                        items: vec![],
                        next_cursor: None,
                    })
                }
                "paged" if page.cursor.is_none() => Ok(Page {
                    items: vec![summary(account, 2, "2026-01-10T00:00:00Z")],
                    next_cursor: Some("c2".into()),
                }),
                "paged" => Ok(Page {
                    items: vec![summary(account, 1, "2026-01-09T00:00:00Z")],
                    next_cursor: None,
                }),
                _ => Ok(Page {
                    items: vec![
                        summary(account, 1, "2026-01-10T00:00:00Z"),
                        summary(account, 2, "2025-01-01T00:00:00Z"),
                    ],
                    next_cursor: None,
                }),
            };
            tokio::task::yield_now().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            result
        }
        async fn search(
            &self,
            _: &AccountId,
            _: &SearchQuery,
            _: PageRequest,
        ) -> Result<Page<MessageSummary>> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
        async fn get_message(&self, _: &MessageRef, _: usize) -> Result<Message> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
        async fn get_thread(&self, _: &MessageRef) -> Result<Vec<MessageSummary>> {
            Err(Error::new(ErrorCode::Unsupported, "n/a"))
        }
    }

    struct FixedCursor(&'static str);
    impl CursorStore for FixedCursor {
        fn load(&self, _: &AccountId, _: &str) -> Option<String> {
            Some(self.0.into())
        }
    }

    fn cfg() -> AggregateConfig {
        AggregateConfig {
            folder: "INBOX".into(),
            lookback: Duration::from_secs(7 * 24 * 3600),
            now: OffsetDateTime::parse("2026-01-12T00:00:00Z", &Rfc3339).unwrap(),
            max_concurrency: 2,
            per_account_timeout: Duration::from_secs(5),
            max_messages_per_account: 50,
        }
    }

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }
    fn fake() -> Fake {
        Fake {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn partial_failure_and_timeout_are_reported_not_hidden() {
        let backend = fake();
        let accounts = [id("good"), id("broken"), id("slow")];
        let agg = aggregate(&backend, &NoCursors, &accounts, &cfg()).await;

        assert!(!agg.is_complete());
        assert_eq!(
            agg.accounts
                .iter()
                .map(|a| a.account.as_str())
                .collect::<Vec<_>>(),
            ["good", "broken", "slow"]
        );
        // lookback drops the 2025 message
        assert_eq!(agg.accounts[0].status, AccountStatus::Ok);
        assert_eq!(agg.accounts[0].messages.len(), 1);
        assert_eq!(agg.accounts[0].messages[0].reference.uid, 1);
        assert!(matches!(
            agg.accounts[1].status,
            AccountStatus::Failed {
                code: ErrorCode::AuthFailed,
                ..
            }
        ));
        assert!(agg.accounts[1].messages.is_empty());
        assert_eq!(agg.accounts[2].status, AccountStatus::TimedOut);
        assert_eq!(agg.failed_accounts().count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrency_is_bounded() {
        let backend = fake();
        let accounts = [id("a"), id("b"), id("c"), id("d"), id("e")];
        let agg = aggregate(&backend, &NoCursors, &accounts, &cfg()).await;
        assert!(agg.is_complete());
        assert!(backend.peak.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test(start_paused = true)]
    async fn follows_pages_and_honours_stored_cursor() {
        let backend = fake();
        let accounts = [id("paged")];
        let agg = aggregate(&backend, &NoCursors, &accounts, &cfg()).await;
        assert_eq!(agg.accounts[0].messages.len(), 2);
        assert_eq!(agg.accounts[0].next_cursor, None);

        // Resuming from a stored cursor skips the first page.
        let agg = aggregate(&backend, &FixedCursor("c2"), &accounts, &cfg()).await;
        assert_eq!(agg.accounts[0].messages.len(), 1);
        assert_eq!(agg.accounts[0].messages[0].reference.uid, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn message_cap_stops_paging_and_keeps_cursor() {
        let backend = fake();
        let mut c = cfg();
        c.max_messages_per_account = 1;
        let agg = aggregate(&backend, &NoCursors, &[id("paged")], &c).await;
        assert_eq!(agg.accounts[0].messages.len(), 1);
        assert_eq!(agg.accounts[0].next_cursor.as_deref(), Some("c2"));
    }
}
