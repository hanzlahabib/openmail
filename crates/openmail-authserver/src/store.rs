//! Registered clients and refresh tokens (hashed) in SQLite. Authorization codes and pending
//! authorizations are short-lived and live in memory only.
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, OptionalExtension, params};

use crate::Error;

/// Registered clients kept at most; dynamic registration is unauthenticated, so the table
/// must not grow without bound.
pub const MAX_CLIENTS: i64 = 200;

#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RefreshGrant {
    pub client_id: String,
    pub scope: String,
}

fn db(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let conn = Connection::open(path).map_err(db)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY, name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL,
                scope TEXT NOT NULL, expires_at INTEGER NOT NULL);",
        )
        .map_err(db)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn add_client(&self, c: &Client, now: i64) -> Result<(), Error> {
        let conn = self.lock();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))
            .map_err(db)?;
        if n >= MAX_CLIENTS {
            return Err(Error::TooManyClients);
        }
        conn.execute(
            "INSERT INTO clients (client_id, name, redirect_uris, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                c.client_id,
                c.name,
                serde_json::to_string(&c.redirect_uris).map_err(db)?,
                now
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    pub fn client(&self, id: &str) -> Result<Option<Client>, Error> {
        let row: Option<(String, String)> = self
            .lock()
            .query_row(
                "SELECT name, redirect_uris FROM clients WHERE client_id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(name, uris)| {
            Ok(Client {
                client_id: id.to_owned(),
                name,
                redirect_uris: serde_json::from_str(&uris).map_err(db)?,
            })
        })
        .transpose()
    }

    pub fn put_refresh(
        &self,
        hash: &str,
        client_id: &str,
        scope: &str,
        exp: i64,
    ) -> Result<(), Error> {
        self.lock()
            .execute(
                "INSERT INTO refresh_tokens (token_hash, client_id, scope, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![hash, client_id, scope, exp],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Atomically consume a refresh token (rotation): a second presentation finds nothing.
    pub fn take_refresh(&self, hash: &str, now: i64) -> Result<Option<RefreshGrant>, Error> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(db)?;
        let row: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT client_id, scope, expires_at FROM refresh_tokens WHERE token_hash = ?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        tx.execute("DELETE FROM refresh_tokens WHERE token_hash = ?1", [hash])
            .map_err(db)?;
        tx.execute("DELETE FROM refresh_tokens WHERE expires_at <= ?1", [now])
            .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(row
            .filter(|(_, _, exp)| *exp > now)
            .map(|(client_id, scope, _)| RefreshGrant { client_id, scope }))
    }
}
