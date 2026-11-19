//! SQLite persistence: processed-message cursors, latest brief, run records.
//! Cursors are keyed by (account, folder, UIDVALIDITY): when the server resets
//! UIDVALIDITY the old cursor is simply never looked up again, so stale UIDs
//! cannot hide new mail.
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::model::{AccountRunStatus, Brief};
use crate::scheduler::{SchedulerError, SchedulerStore};

/// Ordered, append-only. Index + 1 is the schema version.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE cursors (
        account TEXT NOT NULL,
        folder TEXT NOT NULL,
        uid_validity INTEGER NOT NULL,
        last_uid INTEGER NOT NULL,
        PRIMARY KEY (account, folder, uid_validity)
    );
    CREATE TABLE briefs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        generated_at TEXT NOT NULL,
        body TEXT NOT NULL
    );
    CREATE TABLE runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT
    );
    CREATE INDEX runs_account ON runs (account, id);",
    // v2: scheduler state shared by every process using this database, and the digest audit.
    // The partial unique index makes "one digest per brief and account" atomic across processes.
    "CREATE TABLE scheduler_jobs (
        job_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        last_run TEXT
    );
    CREATE TABLE scheduler_leases (
        job_id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE digest_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        brief_id TEXT NOT NULL,
        account TEXT NOT NULL,
        recipient TEXT NOT NULL,
        created_at TEXT NOT NULL,
        state TEXT NOT NULL
    );
    CREATE UNIQUE INDEX digest_log_once ON digest_log (brief_id, account) WHERE state <> 'failed';
    CREATE INDEX digest_log_recent ON digest_log (account, created_at);",
];

/// How long a writer waits for another process holding the database before failing; several
/// processes (CLI, `serve`) share one file.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A finished attempt to process one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub account: AccountId,
    /// RFC 3339 UTC.
    pub started_at: String,
    pub finished_at: String,
    pub status: AccountRunStatus,
}

#[derive(Debug)]
pub struct BriefStore {
    conn: Connection,
}

fn db_err(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Internal, format!("brief store: {e}"))
}

/// Opens-time setup shared by every connection to the database: WAL, busy timeout, migrations.
fn migrate(conn: &mut Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(db_err)?;
    conn.busy_timeout(BUSY_TIMEOUT).map_err(db_err)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .map_err(db_err)?;
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )
        .map_err(db_err)?;
    let applied = usize::try_from(current).map_err(db_err)?;
    if applied > MIGRATIONS.len() {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "brief database was created by a newer OpenMail version",
        ));
    }
    for (idx, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
        // IMMEDIATE takes the write lock up front; the version is re-read under it because
        // another process may have applied this step since the check above.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)?;
        let version = i64::try_from(idx + 1).map_err(db_err)?;
        let done: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if done >= version {
            continue;
        }
        tx.execute_batch(sql).map_err(db_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [version],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
    }
    Ok(())
}

impl BriefStore {
    /// Opens (creating if needed) the database at `path` and applies migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(db_err)?;
        Self::init(conn)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        migrate(&mut conn)?;
        Ok(Self { conn })
    }

    pub fn schema_version(&self) -> Result<usize> {
        let v: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        usize::try_from(v).map_err(db_err)
    }

    /// Highest processed UID for this exact UIDVALIDITY, or `None` if nothing was processed.
    pub fn cursor(
        &self,
        account: &AccountId,
        folder: &str,
        uid_validity: u32,
    ) -> Result<Option<u32>> {
        self.conn
            .query_row(
                "SELECT last_uid FROM cursors WHERE account = ?1 AND folder = ?2 AND uid_validity = ?3",
                params![account.as_str(), folder, uid_validity],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)
    }

    /// Moves the cursor forward; a lower `last_uid` never moves it back.
    pub fn advance_cursor(
        &self,
        account: &AccountId,
        folder: &str,
        uid_validity: u32,
        last_uid: u32,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO cursors (account, folder, uid_validity, last_uid) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account, folder, uid_validity)
                 DO UPDATE SET last_uid = MAX(last_uid, excluded.last_uid)",
                params![account.as_str(), folder, uid_validity, last_uid],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Drops cursors for UIDVALIDITY values other than `current`; they can never match again.
    pub fn prune_stale_cursors(
        &self,
        account: &AccountId,
        folder: &str,
        current: u32,
    ) -> Result<usize> {
        self.conn
            .execute(
                "DELETE FROM cursors WHERE account = ?1 AND folder = ?2 AND uid_validity <> ?3",
                params![account.as_str(), folder, current],
            )
            .map_err(db_err)
    }

    pub fn save_brief(&self, brief: &Brief) -> Result<()> {
        let body = serde_json::to_string(brief).map_err(db_err)?;
        self.conn
            .execute(
                "INSERT INTO briefs (generated_at, body) VALUES (?1, ?2)",
                params![brief.generated_at, body],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// The most recently saved brief (by insertion order, not timestamp).
    pub fn latest_brief(&self) -> Result<Option<Brief>> {
        let body: Option<String> = self
            .conn
            .query_row(
                "SELECT body FROM briefs ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        body.map(|b| serde_json::from_str(&b).map_err(db_err))
            .transpose()
    }

    pub fn record_run(&self, run: &RunRecord) -> Result<()> {
        let (status, reason) = match &run.status {
            AccountRunStatus::Ok => ("ok", None),
            AccountRunStatus::Failed { reason } => ("failed", Some(reason.as_str())),
            AccountRunStatus::NotChecked => ("not_checked", None),
        };
        self.conn
            .execute(
                "INSERT INTO runs (account, started_at, finished_at, status, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![run.account.as_str(), run.started_at, run.finished_at, status, reason],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Newest-first run history for an account.
    pub fn recent_runs(&self, account: &AccountId, limit: u32) -> Result<Vec<RunRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT started_at, finished_at, status, reason FROM runs
                 WHERE account = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![account.as_str(), limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (started_at, finished_at, status, reason) = row.map_err(db_err)?;
            let status = match (status.as_str(), reason) {
                ("ok", _) => AccountRunStatus::Ok,
                ("not_checked", _) => AccountRunStatus::NotChecked,
                ("failed", reason) => AccountRunStatus::Failed {
                    reason: reason.unwrap_or_default(),
                },
                (other, _) => return Err(db_err(format!("unknown run status {other:?}"))),
            };
            out.push(RunRecord {
                account: account.clone(),
                started_at,
                finished_at,
                status,
            });
        }
        Ok(out)
    }
}

/// Result of asking to send a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestClaim {
    /// This caller owns the send; report the outcome with [`BriefStore::finish_digest`].
    Claimed(i64),
    /// A digest for this brief and account is already pending, sent or uncertain.
    AlreadySent,
    /// The account already received its quota of digests in the window.
    RateLimited,
}

impl BriefStore {
    /// Atomically reserves the right to email `brief_id` to `account`'s owner. At most
    /// `max_in_window` digests per account are allowed since `window_start` (RFC 3339 UTC);
    /// failed attempts do not count. The audit row is written before any network I/O.
    pub fn claim_digest(
        &mut self,
        brief_id: &str,
        account: &AccountId,
        recipient: &str,
        now: &str,
        window_start: &str,
        max_in_window: u32,
    ) -> Result<DigestClaim> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM digest_log WHERE brief_id = ?1 AND account = ?2 AND state <> 'failed')",
                params![brief_id, account.as_str()],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if exists {
            return Ok(DigestClaim::AlreadySent);
        }
        let recent: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM digest_log WHERE account = ?1 AND created_at >= ?2 AND state <> 'failed'",
                params![account.as_str(), window_start],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if recent >= max_in_window {
            return Ok(DigestClaim::RateLimited);
        }
        tx.execute(
            "INSERT INTO digest_log (brief_id, account, recipient, created_at, state) VALUES (?1, ?2, ?3, ?4, 'pending')",
            params![brief_id, account.as_str(), recipient, now],
        )
        .map_err(db_err)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(db_err)?;
        Ok(DigestClaim::Claimed(id))
    }

    /// `state` is one of `sent`, `failed` (safe to retry) or `uncertain` (never retried).
    pub fn finish_digest(&self, id: i64, state: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE digest_log SET state = ?2 WHERE id = ?1",
                params![id, state],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// `(recipient, state, created_at)` of digests for `account`, newest first.
    pub fn digest_history(
        &self,
        account: &AccountId,
        limit: u32,
    ) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT recipient, state, created_at FROM digest_log WHERE account = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![account.as_str(), limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(db_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)
    }
}

fn sched_err(e: impl std::fmt::Display) -> SchedulerError {
    SchedulerError::Store(format!("{e}"))
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn parse_ts(raw: &str) -> std::result::Result<DateTime<Utc>, SchedulerError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(sched_err)
}

/// Scheduler state in the shared SQLite file, so two processes (for example two `serve`
/// instances) take one lease per job and see each other's completed runs. Every call is a
/// short synchronous statement; the connection lock is never held across an await.
#[derive(Debug)]
pub struct SqliteSchedulerStore {
    conn: Mutex<Connection>,
}

impl SqliteSchedulerStore {
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path).map_err(db_err)?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::result::Result<MutexGuard<'_, Connection>, SchedulerError> {
        self.conn
            .lock()
            .map_err(|_| SchedulerError::Store("scheduler store lock poisoned".into()))
    }

    /// When this job was first registered. Persisted so a restart does not reset the
    /// baseline and silently drop fire times that passed while the process was down.
    pub fn job_created_at(
        &self,
        job_id: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<DateTime<Utc>, SchedulerError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO scheduler_jobs (job_id, created_at) VALUES (?1, ?2)",
            params![job_id, ts(now)],
        )
        .map_err(sched_err)?;
        let raw: String = conn
            .query_row(
                "SELECT created_at FROM scheduler_jobs WHERE job_id = ?1",
                [job_id],
                |r| r.get(0),
            )
            .map_err(sched_err)?;
        parse_ts(&raw)
    }
}

impl SchedulerStore for SqliteSchedulerStore {
    async fn last_run(
        &self,
        job_id: &str,
    ) -> std::result::Result<Option<DateTime<Utc>>, SchedulerError> {
        let conn = self.lock()?;
        let raw: Option<Option<String>> = conn
            .query_row(
                "SELECT last_run FROM scheduler_jobs WHERE job_id = ?1",
                [job_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(sched_err)?;
        raw.flatten().as_deref().map(parse_ts).transpose()
    }

    async fn record_run(
        &self,
        job_id: &str,
        scheduled_for: DateTime<Utc>,
    ) -> std::result::Result<(), SchedulerError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO scheduler_jobs (job_id, created_at, last_run) VALUES (?1, ?2, ?2)
             ON CONFLICT (job_id) DO UPDATE SET last_run = excluded.last_run",
            params![job_id, ts(scheduled_for)],
        )
        .map_err(sched_err)?;
        Ok(())
    }

    async fn try_acquire(
        &self,
        job_id: &str,
        owner: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> std::result::Result<bool, SchedulerError> {
        let ttl = chrono::Duration::from_std(ttl).map_err(sched_err)?;
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sched_err)?;
        let held: Option<(String, String)> = tx
            .query_row(
                "SELECT owner, expires_at FROM scheduler_leases WHERE job_id = ?1",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sched_err)?;
        if let Some((holder, expires)) = held
            && holder != owner
            && parse_ts(&expires)? > now
        {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO scheduler_leases (job_id, owner, expires_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (job_id) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at",
            params![job_id, owner, ts(now + ttl)],
        )
        .map_err(sched_err)?;
        tx.commit().map_err(sched_err)?;
        Ok(true)
    }

    async fn release(&self, job_id: &str, owner: &str) -> std::result::Result<(), SchedulerError> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM scheduler_leases WHERE job_id = ?1 AND owner = ?2",
            params![job_id, owner],
        )
        .map_err(sched_err)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use openmail_core::ids::MessageRef;
    use openmail_core::model::Untrusted;
    use tempfile::TempDir;

    use super::*;
    use crate::model::{ActionItem, BriefItem, Evidence, Provenance};

    fn acct(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn open() -> (TempDir, BriefStore) {
        let dir = TempDir::new().unwrap();
        let store = BriefStore::open(&dir.path().join("briefs.db")).unwrap();
        (dir, store)
    }

    fn brief(stamp: &str) -> Brief {
        let item = BriefItem {
            source: MessageRef {
                account: acct("work"),
                folder: "INBOX".into(),
                uid_validity: 3,
                uid: 11,
            },
            title: Untrusted("Contract".into()),
            evidence: vec![Evidence {
                reason: "from VIP rule".into(),
                excerpt: Some(Untrusted("sign by Friday".into())),
            }],
            provenance: Provenance::UserRule,
        };
        Brief {
            generated_at: stamp.into(),
            window_start: "2026-11-18T00:00:00Z".into(),
            window_end: "2026-11-19T00:00:00Z".into(),
            accounts: BTreeMap::from([
                (acct("work"), AccountRunStatus::Ok),
                (
                    acct("home"),
                    AccountRunStatus::Failed {
                        reason: "auth".into(),
                    },
                ),
                (acct("old"), AccountRunStatus::NotChecked),
            ]),
            highlights: vec![item.clone()],
            actions: vec![ActionItem {
                item,
                due: Some("2026-11-21T17:00:00Z".into()),
            }],
            follow_ups: vec![],
            ai_summary: None,
            notes: vec![],
        }
    }

    #[test]
    fn migrations_apply_once_and_reopen_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.db");
        assert_eq!(
            BriefStore::open(&path).unwrap().schema_version().unwrap(),
            MIGRATIONS.len()
        );
        assert_eq!(
            BriefStore::open(&path).unwrap().schema_version().unwrap(),
            MIGRATIONS.len()
        );
    }

    #[test]
    fn newer_database_is_refused() {
        let (dir, store) = open();
        store
            .conn
            .execute("INSERT INTO schema_migrations (version) VALUES (999)", [])
            .unwrap();
        drop(store);
        let err = BriefStore::open(&dir.path().join("briefs.db")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn cursor_is_monotonic_and_scoped_by_uidvalidity() {
        let (_dir, store) = open();
        let a = acct("work");
        assert_eq!(store.cursor(&a, "INBOX", 1).unwrap(), None);
        store.advance_cursor(&a, "INBOX", 1, 50).unwrap();
        store.advance_cursor(&a, "INBOX", 1, 20).unwrap();
        assert_eq!(store.cursor(&a, "INBOX", 1).unwrap(), Some(50));
        // UIDVALIDITY reset: old cursor must not apply.
        assert_eq!(store.cursor(&a, "INBOX", 2).unwrap(), None);
        assert_eq!(store.cursor(&a, "Sent", 1).unwrap(), None);
        assert_eq!(store.cursor(&acct("home"), "INBOX", 1).unwrap(), None);
        store.advance_cursor(&a, "INBOX", 2, 5).unwrap();
        assert_eq!(store.prune_stale_cursors(&a, "INBOX", 2).unwrap(), 1);
        assert_eq!(store.cursor(&a, "INBOX", 1).unwrap(), None);
        assert_eq!(store.cursor(&a, "INBOX", 2).unwrap(), Some(5));
    }

    #[test]
    fn latest_brief_roundtrips_and_persists_across_reopen() {
        let (dir, store) = open();
        assert_eq!(store.latest_brief().unwrap(), None);
        let first = brief("2026-11-19T06:00:00Z");
        let second = brief("2026-11-19T07:00:00Z");
        store.save_brief(&first).unwrap();
        store.save_brief(&second).unwrap();
        drop(store);
        let reopened = BriefStore::open(&dir.path().join("briefs.db")).unwrap();
        let latest = reopened.latest_brief().unwrap().unwrap();
        assert_eq!(latest, second);
        assert_eq!(latest.accounts[&acct("old")], AccountRunStatus::NotChecked);
    }

    #[test]
    fn runs_are_newest_first_and_keep_failure_reason() {
        let (_dir, store) = open();
        let a = acct("work");
        let mk = |n: u8, status| RunRecord {
            account: a.clone(),
            started_at: format!("2026-11-19T0{n}:00:00Z"),
            finished_at: format!("2026-11-19T0{n}:01:00Z"),
            status,
        };
        store.record_run(&mk(1, AccountRunStatus::Ok)).unwrap();
        store
            .record_run(&mk(
                2,
                AccountRunStatus::Failed {
                    reason: "timeout".into(),
                },
            ))
            .unwrap();
        store
            .record_run(&mk(3, AccountRunStatus::NotChecked))
            .unwrap();
        store
            .record_run(&RunRecord {
                account: acct("home"),
                ..mk(4, AccountRunStatus::Ok)
            })
            .unwrap();
        let runs = store.recent_runs(&a, 2).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].status, AccountRunStatus::NotChecked);
        assert_eq!(
            runs[1].status,
            AccountRunStatus::Failed {
                reason: "timeout".into()
            }
        );
        assert_eq!(store.recent_runs(&a, 10).unwrap().len(), 3);
    }
}
