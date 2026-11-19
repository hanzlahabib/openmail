//! SQLite-backed `OutboxStore`. `synchronous=FULL` + WAL so a state the caller was
//! told is durable (notably `data_started`) survives power loss.
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::outbox::{AuditEntry, Begin, NewAttempt, Outcome, OutboxRecord, OutboxState, OutboxStore};

const SCHEMA_VERSION: i64 = 1;
/// Wait this long for a competing writer (another process on the same file) before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = "
CREATE TABLE outbox (
  account TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  content_hash TEXT NOT NULL, message_id TEXT NOT NULL, recipients INTEGER NOT NULL,
  state TEXT NOT NULL, data_started INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 1,
  detail TEXT, created_unix INTEGER NOT NULL, updated_unix INTEGER NOT NULL,
  PRIMARY KEY (account, idempotency_key)
) WITHOUT ROWID;
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, account TEXT NOT NULL,
  idempotency_key TEXT NOT NULL, message_id TEXT NOT NULL, recipients INTEGER NOT NULL,
  attempt INTEGER NOT NULL, outcome TEXT NOT NULL, approval_token TEXT NOT NULL, detail TEXT
);
CREATE INDEX audit_account_idx ON audit (account, id);
";

#[derive(Debug, Clone)]
pub struct SqliteOutbox {
    conn: Arc<Mutex<Connection>>,
}

fn internal(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Internal, format!("outbox storage error: {e}"))
}

fn now() -> (i64, String) {
    let t = OffsetDateTime::now_utc();
    (t.unix_timestamp(), t.format(&Rfc3339).unwrap_or_default())
}

impl SqliteOutbox {
    /// Opens (creating if needed) the database and converts any attempt that died
    /// after DATA began into `Uncertain`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(internal)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(internal)?;
        }
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(internal)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(BUSY_TIMEOUT).map_err(internal)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(internal)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(internal)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(internal)?;
        if version > SCHEMA_VERSION {
            return Err(Error::new(ErrorCode::ConfigInvalid, "outbox database was written by a newer version"));
        }
        if version == 0 {
            conn.execute_batch(SCHEMA).map_err(internal)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION).map_err(internal)?;
        }
        let store = Self { conn: Arc::new(Mutex::new(conn)) };
        store.recover_orphans()?;
        Ok(store)
    }

    fn recover_orphans(&self) -> Result<()> {
        let mut conn = self.conn.lock().map_err(|_| internal("poisoned lock"))?;
        let tx = conn.transaction().map_err(internal)?;
        let orphans: Vec<(String, String)> = {
            let mut st = tx.prepare("SELECT account, idempotency_key FROM outbox WHERE state='pending' AND data_started=1").map_err(internal)?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(internal)?.collect::<std::result::Result<_, _>>().map_err(internal)?
        };
        for (account, key) in &orphans {
            set_state(&tx, account, key, OutboxState::Uncertain, Some("process ended after DATA began"))?;
        }
        tx.commit().map_err(internal)?;
        if !orphans.is_empty() {
            tracing::warn!(count = orphans.len(), "recovered in-flight sends as Uncertain");
        }
        Ok(())
    }

    async fn run<T: Send + 'static>(&self, f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static) -> Result<T> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| internal("poisoned lock"))?;
            f(&mut guard)
        })
        .await
        .map_err(internal)?
    }
}

fn read_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, String, String, u32, String, bool, u32, Option<String>, i64)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get::<_, i64>(6)? != 0, r.get(7)?, r.get(8)?, r.get(9)?))
}

const SELECT: &str = "SELECT account, idempotency_key, content_hash, message_id, recipients, state, data_started, attempts, detail, updated_unix FROM outbox";

fn fetch(tx: &Transaction<'_>, account: &str, key: &str) -> Result<Option<OutboxRecord>> {
    let row = tx
        .query_row(&format!("{SELECT} WHERE account=?1 AND idempotency_key=?2"), params![account, key], read_record)
        .optional()
        .map_err(internal)?;
    row.map(|(a, k, h, m, n, s, d, at, det, up)| {
        Ok(OutboxRecord {
            account: AccountId::new(a)?,
            idempotency_key: k,
            content_hash: h,
            message_id: m,
            recipients: n,
            state: OutboxState::parse(&s).ok_or_else(|| internal("unknown state in database"))?,
            data_started: d,
            attempts: at,
            detail: det,
            updated_unix: up,
        })
    })
    .transpose()
}

fn set_state(tx: &Transaction<'_>, account: &str, key: &str, state: OutboxState, detail: Option<&str>) -> Result<()> {
    let (unix, ts) = now();
    tx.execute(
        "UPDATE outbox SET state=?3, detail=?4, updated_unix=?5 WHERE account=?1 AND idempotency_key=?2",
        params![account, key, state.as_str(), detail, unix],
    )
    .map_err(internal)?;
    // The audit row for the current attempt carries the latest outcome.
    tx.execute(
        "UPDATE audit SET outcome=?3, detail=?4, ts=?5 WHERE id=(SELECT MAX(id) FROM audit WHERE account=?1 AND idempotency_key=?2)",
        params![account, key, state.as_str(), detail, ts],
    )
    .map_err(internal)?;
    Ok(())
}

fn insert_audit(tx: &Transaction<'_>, a: &NewAttempt, attempt: u32, outcome: &str) -> Result<()> {
    let (_, ts) = now();
    tx.execute(
        "INSERT INTO audit (ts, account, idempotency_key, message_id, recipients, attempt, outcome, approval_token) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![ts, a.account.as_str(), a.idempotency_key, a.message_id, a.recipients, attempt, outcome, a.approval_token],
    )
    .map_err(internal)?;
    Ok(())
}

impl OutboxStore for SqliteOutbox {
    async fn begin(&self, attempt: NewAttempt, pending_lease: Duration) -> Result<Begin> {
        self.run(move |conn| {
            // IMMEDIATE: take the write lock up front so two processes cannot both claim a key.
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(internal)?;
            let account = attempt.account.as_str();
            let (unix, ts) = now();
            let out = match fetch(&tx, account, &attempt.idempotency_key)? {
                None => {
                    tx.execute(
                        "INSERT INTO outbox (account, idempotency_key, content_hash, message_id, recipients, state, created_unix, updated_unix) VALUES (?1,?2,?3,?4,?5,'pending',?6,?6)",
                        params![account, attempt.idempotency_key, attempt.content_hash, attempt.message_id, attempt.recipients, unix],
                    )
                    .map_err(internal)?;
                    insert_audit(&tx, &attempt, 1, "pending")?;
                    Begin::Started(fetch(&tx, account, &attempt.idempotency_key)?.ok_or_else(|| internal("row vanished"))?)
                }
                Some(rec) => {
                    if rec.content_hash != attempt.content_hash {
                        return Err(Error::new(ErrorCode::InvalidInput, "idempotency key was already used for different content"));
                    }
                    let lease_secs = i64::try_from(pending_lease.as_secs()).unwrap_or(i64::MAX);
                    let stale_pending = rec.state == OutboxState::Pending && !rec.data_started && unix.saturating_sub(rec.updated_unix) >= lease_secs;
                    if rec.state == OutboxState::Pending && rec.data_started {
                        set_state(&tx, account, &attempt.idempotency_key, OutboxState::Uncertain, Some("previous attempt ended after DATA began"))?;
                        Begin::Existing(fetch(&tx, account, &attempt.idempotency_key)?.ok_or_else(|| internal("row vanished"))?)
                    } else if rec.state == OutboxState::Rejected || stale_pending {
                        // Nothing reached the DATA phase: a retry cannot duplicate delivery.
                        let n = rec.attempts + 1;
                        tx.execute(
                            "UPDATE outbox SET state='pending', data_started=0, attempts=?3, detail=NULL, updated_unix=?4 WHERE account=?1 AND idempotency_key=?2",
                            params![account, attempt.idempotency_key, n, unix],
                        )
                        .map_err(internal)?;
                        tx.execute(
                            "INSERT INTO audit (ts, account, idempotency_key, message_id, recipients, attempt, outcome, approval_token) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7)",
                            params![ts, account, attempt.idempotency_key, rec.message_id, rec.recipients, n, attempt.approval_token],
                        )
                        .map_err(internal)?;
                        Begin::Started(fetch(&tx, account, &attempt.idempotency_key)?.ok_or_else(|| internal("row vanished"))?)
                    } else {
                        Begin::Existing(rec)
                    }
                }
            };
            tx.commit().map_err(internal)?;
            Ok(out)
        })
        .await
    }

    async fn mark_data_started(&self, account: &AccountId, key: &str) -> Result<()> {
        let (account, key) = (account.to_string(), key.to_owned());
        self.run(move |conn| {
            let (unix, _) = now();
            conn.execute(
                "UPDATE outbox SET data_started=1, updated_unix=?3 WHERE account=?1 AND idempotency_key=?2 AND state='pending'",
                params![account, key, unix],
            )
            .map_err(internal)?;
            Ok(())
        })
        .await
    }

    async fn finish(&self, account: &AccountId, key: &str, state: OutboxState, detail: Option<&str>) -> Result<()> {
        if state == OutboxState::Pending {
            return Err(Error::new(ErrorCode::Internal, "finish() requires a final state"));
        }
        let (account, key, detail) = (account.to_string(), key.to_owned(), detail.map(str::to_owned));
        self.run(move |conn| {
            let tx = conn.transaction().map_err(internal)?;
            set_state(&tx, &account, &key, state, detail.as_deref())?;
            tx.commit().map_err(internal)
        })
        .await
    }

    async fn get(&self, account: &AccountId, key: &str) -> Result<Option<OutboxRecord>> {
        let (account, key) = (account.to_string(), key.to_owned());
        self.run(move |conn| {
            let tx = conn.transaction().map_err(internal)?;
            fetch(&tx, &account, &key)
        })
        .await
    }

    async fn resolve_uncertain(&self, account: &AccountId, key: &str, outcome: Outcome, note: &str) -> Result<OutboxRecord> {
        let (account, key, note) = (account.to_string(), key.to_owned(), note.to_owned());
        self.run(move |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(internal)?;
            let rec = fetch(&tx, &account, &key)?.ok_or_else(|| Error::new(ErrorCode::InvalidInput, "unknown idempotency key"))?;
            if rec.state != OutboxState::Uncertain {
                return Err(Error::new(ErrorCode::InvalidInput, format!("only uncertain sends can be resolved (state is {})", rec.state.as_str())));
            }
            let (state, label) = match outcome {
                Outcome::Delivered => (OutboxState::Accepted, "operator_resolved_delivered"),
                Outcome::NotDelivered => (OutboxState::Rejected, "operator_resolved_not_delivered"),
            };
            let (unix, ts) = now();
            tx.execute(
                "UPDATE outbox SET state=?3, detail=?4, updated_unix=?5 WHERE account=?1 AND idempotency_key=?2",
                params![account, key, state.as_str(), format!("operator: {note}"), unix],
            )
            .map_err(internal)?;
            tx.execute(
                "INSERT INTO audit (ts, account, idempotency_key, message_id, recipients, attempt, outcome, approval_token, detail) VALUES (?1,?2,?3,?4,?5,?6,?7,'operator',?8)",
                params![ts, account, key, rec.message_id, rec.recipients, rec.attempts, label, note],
            )
            .map_err(internal)?;
            let out = fetch(&tx, &account, &key)?.ok_or_else(|| internal("row vanished"))?;
            tx.commit().map_err(internal)?;
            Ok(out)
        })
        .await
    }

    async fn audit_entries(&self, account: &AccountId, limit: u32) -> Result<Vec<AuditEntry>> {
        let account = account.to_string();
        self.run(move |conn| {
            let mut st = conn
                .prepare("SELECT ts, account, idempotency_key, message_id, recipients, attempt, outcome, approval_token, detail FROM audit WHERE account=?1 ORDER BY id DESC LIMIT ?2")
                .map_err(internal)?;
            let rows = st
                .query_map(params![account, limit], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?))
                })
                .map_err(internal)?;
            rows.map(|r| {
                let (ts, acc, key, mid, rc, at, out, tok, det) = r.map_err(internal)?;
                Ok(AuditEntry { timestamp: ts, account: AccountId::new(acc)?, idempotency_key: key, message_id: mid, recipients: rc, attempt: at, outcome: out, approval_token: tok, detail: det })
            })
            .collect()
        })
        .await
    }
}
