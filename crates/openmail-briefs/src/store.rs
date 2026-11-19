//! SQLite persistence: processed-message cursors, latest brief, run records.
//! Cursors are keyed by (account, folder, UIDVALIDITY): when the server resets
//! UIDVALIDITY the old cursor is simply never looked up again, so stale UIDs
//! cannot hide new mail.
use std::path::Path;

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::{AccountRunStatus, Brief};

/// Ordered, append-only. Index + 1 is the schema version.
const MIGRATIONS: &[&str] = &["CREATE TABLE cursors (
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
    CREATE INDEX runs_account ON runs (account, id);"];

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

impl BriefStore {
    /// Opens (creating if needed) the database at `path` and applies migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(db_err)?;
        Self::init(conn)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
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
            let tx = conn.transaction().map_err(db_err)?;
            tx.execute_batch(sql).map_err(db_err)?;
            tx.execute(
                "INSERT INTO schema_migrations (version) VALUES (?1)",
                [i64::try_from(idx + 1).map_err(db_err)?],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
        }
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
