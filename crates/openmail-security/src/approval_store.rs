//! Persistence for approvals. Only a SHA-256 of the bearer id is stored, so a
//! leaked database cannot be replayed. Consumed rows are kept as tombstones so a
//! replay is detected even after restart.
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use openmail_core::{Error, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub id_hash: [u8; 32],
    pub binding: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeOutcome {
    Consumed,
    NotFound,
    AlreadyConsumed,
    Expired,
    Mismatch,
}

pub trait ApprovalStore: Send + Sync {
    fn insert(&self, record: &ApprovalRecord) -> Result<()>;
    /// Atomically validates and consumes. A binding mismatch does NOT consume.
    fn consume(&self, id_hash: &[u8; 32], binding: &[u8; 32], now: u64) -> Result<ConsumeOutcome>;
    /// Drops unconsumed rows that expired before `now`; they can never succeed again.
    fn purge_expired(&self, now: u64) -> Result<usize>;
}

fn internal(msg: &'static str) -> Error {
    Error::new(ErrorCode::Internal, msg)
}

#[derive(Debug)]
struct Entry {
    binding: [u8; 32],
    expires_at: u64,
    consumed: bool,
}

#[derive(Debug, Default)]
pub struct InMemoryApprovalStore {
    inner: Mutex<HashMap<[u8; 32], Entry>>,
}

impl ApprovalStore for InMemoryApprovalStore {
    fn insert(&self, r: &ApprovalRecord) -> Result<()> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        if m.contains_key(&r.id_hash) {
            return Err(internal("approval id collision"));
        }
        m.insert(
            r.id_hash,
            Entry {
                binding: r.binding,
                expires_at: r.expires_at,
                consumed: false,
            },
        );
        Ok(())
    }

    fn consume(&self, id_hash: &[u8; 32], binding: &[u8; 32], now: u64) -> Result<ConsumeOutcome> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        let Some(e) = m.get_mut(id_hash) else {
            return Ok(ConsumeOutcome::NotFound);
        };
        Ok(decide(
            e.consumed,
            e.expires_at,
            &e.binding,
            binding,
            now,
            || e.consumed = true,
        ))
    }

    fn purge_expired(&self, now: u64) -> Result<usize> {
        let mut m = self
            .inner
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        let before = m.len();
        m.retain(|_, e| e.consumed || e.expires_at > now);
        Ok(before - m.len())
    }
}

/// Shared decision logic so both stores behave identically.
fn decide(
    consumed: bool,
    expires_at: u64,
    stored: &[u8; 32],
    presented: &[u8; 32],
    now: u64,
    mark: impl FnOnce(),
) -> ConsumeOutcome {
    if consumed {
        return ConsumeOutcome::AlreadyConsumed;
    }
    if now >= expires_at {
        return ConsumeOutcome::Expired;
    }
    if !bool::from(stored.ct_eq(presented)) {
        return ConsumeOutcome::Mismatch;
    }
    mark();
    ConsumeOutcome::Consumed
}

#[derive(Debug)]
pub struct SqliteApprovalStore {
    conn: Mutex<Connection>,
}

/// Wait for the CLI (issuer) and server (verifier) processes to release the write lock.
const BUSY_TIMEOUT_MS: u64 = 5_000;

fn db(_: rusqlite::Error) -> Error {
    // Underlying sqlite text can include paths; keep it out of user-facing errors.
    internal("approval database error")
}

impl SqliteApprovalStore {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| internal("cannot create approval database"))?;
        }
        Self::from_connection(Connection::open(path).map_err(db)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory().map_err(db)?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS approvals (
                id_hash BLOB PRIMARY KEY CHECK (length(id_hash) = 32),
                binding BLOB NOT NULL CHECK (length(binding) = 32),
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;",
        )
        .map_err(db)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl ApprovalStore for SqliteApprovalStore {
    fn insert(&self, r: &ApprovalRecord) -> Result<()> {
        let exp = i64::try_from(r.expires_at).map_err(|_| internal("expiry out of range"))?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        conn.execute(
            "INSERT INTO approvals (id_hash, binding, expires_at) VALUES (?1, ?2, ?3)",
            params![&r.id_hash[..], &r.binding[..], exp],
        )
        .map_err(db)?;
        Ok(())
    }

    fn consume(&self, id_hash: &[u8; 32], binding: &[u8; 32], now: u64) -> Result<ConsumeOutcome> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        // IMMEDIATE takes the write lock up front so two processes cannot both consume.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let row: Option<(Vec<u8>, i64, bool)> = tx
            .query_row(
                "SELECT binding, expires_at, consumed FROM approvals WHERE id_hash = ?1",
                params![&id_hash[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)),
            )
            .optional()
            .map_err(db)?;
        let Some((stored, exp, consumed)) = row else {
            return Ok(ConsumeOutcome::NotFound);
        };
        let stored: [u8; 32] = stored
            .try_into()
            .map_err(|_| internal("corrupt approval row"))?;
        let exp = u64::try_from(exp).unwrap_or(0); // negative expiry = corrupt = already expired
        let mut mark = false;
        let outcome = decide(consumed, exp, &stored, binding, now, || mark = true);
        if mark {
            tx.execute(
                "UPDATE approvals SET consumed = 1 WHERE id_hash = ?1",
                params![&id_hash[..]],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(outcome)
    }

    fn purge_expired(&self, now: u64) -> Result<usize> {
        let now = i64::try_from(now).map_err(|_| internal("time out of range"))?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| internal("approval store poisoned"))?;
        conn.execute(
            "DELETE FROM approvals WHERE consumed = 0 AND expires_at <= ?1",
            params![now],
        )
        .map_err(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(n: u8, exp: u64) -> ApprovalRecord {
        ApprovalRecord {
            id_hash: [n; 32],
            binding: [n.wrapping_add(1); 32],
            expires_at: exp,
        }
    }

    fn exercise(s: &dyn ApprovalStore) {
        s.insert(&rec(1, 100)).unwrap();
        assert!(s.insert(&rec(1, 100)).is_err(), "duplicate id must fail");
        assert_eq!(
            s.consume(&[9; 32], &[2; 32], 50).unwrap(),
            ConsumeOutcome::NotFound
        );
        assert_eq!(
            s.consume(&[1; 32], &[7; 32], 50).unwrap(),
            ConsumeOutcome::Mismatch
        );
        assert_eq!(
            s.consume(&[1; 32], &[2; 32], 50).unwrap(),
            ConsumeOutcome::Consumed
        );
        assert_eq!(
            s.consume(&[1; 32], &[2; 32], 50).unwrap(),
            ConsumeOutcome::AlreadyConsumed
        );
        s.insert(&rec(2, 100)).unwrap();
        assert_eq!(
            s.consume(&[2; 32], &[3; 32], 100).unwrap(),
            ConsumeOutcome::Expired
        );
        s.insert(&rec(3, 10)).unwrap();
        assert_eq!(s.purge_expired(100).unwrap(), 2); // ids 2 and 3; consumed tombstone kept
        assert_eq!(
            s.consume(&[1; 32], &[2; 32], 50).unwrap(),
            ConsumeOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn in_memory_store_semantics() {
        exercise(&InMemoryApprovalStore::default());
    }

    #[test]
    fn sqlite_store_semantics() {
        exercise(&SqliteApprovalStore::open_in_memory().unwrap());
    }

    #[test]
    fn sqlite_consumption_persists_across_reopen_and_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.db");
        {
            let s = SqliteApprovalStore::open(&path).unwrap();
            s.insert(&rec(5, 1000)).unwrap();
            assert_eq!(
                s.consume(&[5; 32], &[6; 32], 1).unwrap(),
                ConsumeOutcome::Consumed
            );
        }
        let s = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            s.consume(&[5; 32], &[6; 32], 2).unwrap(),
            ConsumeOutcome::AlreadyConsumed
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn concurrent_consume_succeeds_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let seed = SqliteApprovalStore::open(&path).unwrap();
        seed.insert(&rec(8, 1000)).unwrap();
        let wins: usize = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    sc.spawn(|| {
                        let s = SqliteApprovalStore::open(&path).unwrap();
                        usize::from(
                            s.consume(&[8; 32], &[9; 32], 1).unwrap() == ConsumeOutcome::Consumed,
                        )
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(wins, 1);
    }
}
