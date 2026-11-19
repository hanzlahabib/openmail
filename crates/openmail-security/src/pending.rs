//! Pending send approvals: the queue a human works through out of band.
//!
//! An agent (via the SMTP/MCP side) can only [`PendingApprovals::request`] — which
//! records what it wants to send. Turning a request into a usable single-use
//! token is [`PendingApprovals::grant`], which needs a [`HumanConfirmation`] that
//! only the CLI/UI builds after a person has seen the exact message. The server
//! side holds an `ApprovalVerifier`, which has no route to any of this; the
//! workspace test `no_other_crate_mints_approvals` pins that boundary.
//!
//! The queue lives in the same SQLite file as the consumed-approval store so the
//! CLI (issuer) and the server (verifier) share one source of truth.
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use openmail_smtp::SendRequestDescriptor;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use subtle::ConstantTimeEq;

use crate::approval::{
    ApprovalGrantor, ApprovalId, ApprovalIssuer, GrantDecision, MAX_APPROVAL_TTL, SendIntent,
    Sha256Digest,
};
use crate::approval_store::SqliteApprovalStore;
use crate::clock::Clock;

/// Default lifetime of a minted token. Short on purpose: the human grants right
/// before the agent retries, and a forgotten token should die quickly.
pub const DEFAULT_TOKEN_TTL: Duration = MAX_APPROVAL_TTL;
/// How long an ungranted request waits for a human before it disappears.
const PENDING_REQUEST_TTL_SECS: u64 = 3_600;
/// Bytes of randomness in a short id: 32 bits is plenty for a human-typed
/// confirmation within a queue that expires in an hour; it is not a secret.
const PENDING_ID_BYTES: usize = 4;
/// Retries if a random short id collides with a live row.
const ID_RETRIES: usize = 8;
/// Wait for the CLI and server processes to release the SQLite write lock.
const BUSY_TIMEOUT_MS: u64 = 5_000;

fn db(_: rusqlite::Error) -> Error {
    // sqlite error text can contain filesystem paths.
    Error::new(ErrorCode::Internal, "approval database error")
}

fn invalid_input(msg: &'static str) -> Error {
    Error::new(ErrorCode::InvalidInput, msg)
}

/// Short, human-typeable handle of a pending request (not a bearer secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingId(String);

impl PendingId {
    pub fn parse(s: &str) -> Result<Self> {
        let ok = s.len() == PENDING_ID_BYTES * 2
            && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(invalid_input("unknown approval request id"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PendingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    Pending,
    Granted,
    Denied,
}

impl PendingStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    fn from_db(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "granted" => Ok(Self::Granted),
            "denied" => Ok(Self::Denied),
            _ => Err(Error::new(ErrorCode::Internal, "corrupt approval row")),
        }
    }
}

/// Everything a human needs to judge a request. Attachment filenames are not
/// part of the SMTP descriptor, so only their content hashes are shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: PendingId,
    pub principal: String,
    pub account: AccountId,
    pub recipients: Vec<String>,
    pub subject: String,
    /// Hex SHA-256 over body, html, cc/bcc roles, references and attachments.
    pub content_hash: String,
    pub attachment_sha256: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: PendingStatus,
}

/// Proof that a person confirmed one specific request. Fields are private and
/// the struct is not constructible outside this crate except through the two
/// constructors below, both of which are meant to be called only by the CLI/UI.
///
/// ```compile_fail
/// use openmail_security::pending::HumanConfirmation;
/// // Struct-literal forgery does not compile.
/// let _ = HumanConfirmation { target: todo!() };
/// ```
#[derive(Debug)]
pub struct HumanConfirmation {
    target: PendingId,
}

impl HumanConfirmation {
    /// The human typed the short id back; it must match the request being granted.
    pub fn typed_id(request: &PendingId, typed: &str) -> Result<Self> {
        if !bool::from(request.0.as_bytes().ct_eq(typed.trim().as_bytes())) {
            return Err(invalid_input("typed id does not match the request"));
        }
        Ok(Self {
            target: request.clone(),
        })
    }

    /// Skips the typing step (`--yes`). Dangerous: only for scripts a human wrote.
    pub fn assume_yes_dangerous(request: &PendingId) -> Self {
        Self {
            target: request.clone(),
        }
    }
}

/// Adapter so token minting reuses `ApprovalIssuer` (random id, TTL clamp, store insert).
struct Confirmed;

impl ApprovalGrantor for Confirmed {
    fn review(&self, _: &SendIntent) -> Result<GrantDecision> {
        Ok(GrantDecision::Approve)
    }
}

pub struct PendingApprovals<C> {
    conn: Mutex<Connection>,
    issuer: ApprovalIssuer<SqliteApprovalStore, C>,
    clock: C,
    token_ttl: Duration,
}

impl<C> std::fmt::Debug for PendingApprovals<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingApprovals").finish_non_exhaustive()
    }
}

impl<C: Clock + Clone> PendingApprovals<C> {
    /// Opens (creating, mode 0600) the shared approvals database at `path`.
    pub fn open(path: &Path, clock: C) -> Result<Self> {
        let store = Arc::new(SqliteApprovalStore::open(path)?); // creates the file privately
        let conn = Connection::open(path).map_err(db)?;
        Self::build(conn, store, clock)
    }

    fn build(conn: Connection, store: Arc<SqliteApprovalStore>, clock: C) -> Result<Self> {
        conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pending_approvals (
                id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                account TEXT NOT NULL,
                binding BLOB NOT NULL CHECK (length(binding) = 32),
                recipients TEXT NOT NULL,
                subject TEXT NOT NULL,
                content_hash BLOB NOT NULL CHECK (length(content_hash) = 32),
                attachments BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'granted', 'denied'))
            ) WITHOUT ROWID;
            CREATE UNIQUE INDEX IF NOT EXISTS pending_live_binding
                ON pending_approvals (principal, binding) WHERE status = 'pending';",
        )
        .map_err(db)?;
        Ok(Self {
            conn: Mutex::new(conn),
            issuer: ApprovalIssuer::new(store, clock.clone()),
            clock,
            token_ttl: DEFAULT_TOKEN_TTL,
        })
    }

    /// Token lifetime for future grants; clamped by the issuer to `MAX_APPROVAL_TTL`.
    #[must_use]
    pub fn with_token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = ttl;
        self
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "approval store poisoned"))
    }

    /// Records a request for a human to review. Identical live requests (same
    /// principal and descriptor) return the existing id rather than queueing twice.
    pub fn request(
        &self,
        principal: &str,
        account: &AccountId,
        descriptor: &SendRequestDescriptor,
    ) -> Result<PendingId> {
        if descriptor.account() != account {
            return Err(invalid_input("descriptor account mismatch"));
        }
        let intent = SendIntent::from_descriptor(principal, descriptor)?;
        let binding = intent.binding().0;
        let now = self.clock.unix_secs();
        let expires = now.saturating_add(PENDING_REQUEST_TTL_SECS);
        let (now_i, exp_i) = (to_i64(now)?, to_i64(expires)?);

        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM pending_approvals
                 WHERE principal = ?1 AND binding = ?2 AND status = 'pending' AND expires_at > ?3",
                params![principal, &binding[..], now_i],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(id) = existing {
            return PendingId::parse(&id);
        }
        // Expired twin would violate the live-binding unique index; it can never be granted.
        tx.execute(
            "DELETE FROM pending_approvals WHERE principal = ?1 AND binding = ?2 AND status = 'pending'",
            params![principal, &binding[..]],
        )
        .map_err(db)?;

        let recipients = intent.recipients().join("\n");
        let attachments: Vec<u8> = intent
            .attachment_sha256()
            .iter()
            .flat_map(|d| d.0)
            .collect();
        for _ in 0..ID_RETRIES {
            let mut raw = [0u8; PENDING_ID_BYTES];
            getrandom::fill(&mut raw)
                .map_err(|_| Error::new(ErrorCode::Internal, "secure random source unavailable"))?;
            let id = hex(&raw);
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO pending_approvals
                 (id, principal, account, binding, recipients, subject, content_hash,
                  attachments, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        id,
                        principal,
                        account.as_str(),
                        &binding[..],
                        recipients,
                        intent.subject(),
                        &intent.body_sha256().0[..],
                        attachments,
                        now_i,
                        exp_i
                    ],
                )
                .map_err(db)?;
            if inserted == 1 {
                tx.commit().map_err(db)?;
                return PendingId::parse(&id);
            }
        }
        Err(Error::new(
            ErrorCode::Internal,
            "could not allocate request id",
        ))
    }

    /// Live (unexpired, undecided) requests, oldest first.
    pub fn list_pending(&self) -> Result<Vec<PendingApproval>> {
        let now = to_i64(self.clock.unix_secs())?;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "{SELECT_ROW} WHERE status = 'pending' AND expires_at > ?1 ORDER BY created_at, id"
            ))
            .map_err(db)?;
        let rows = stmt
            .query_map(params![now], read_row)
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        rows.into_iter().map(Row::into_approval).collect()
    }

    /// Full descriptor of one request, whatever its status.
    pub fn get(&self, id: &PendingId) -> Result<Option<PendingApproval>> {
        let conn = self.lock()?;
        let row = fetch(&conn, id)?;
        row.map(Row::into_approval).transpose()
    }

    /// Mints the single-use token for a request. The token is bound to the
    /// principal, account and exact descriptor recorded at request time; the row is
    /// re-hashed first so a tampered database cannot widen what is approved.
    pub fn grant(&self, id: &PendingId, confirmation: &HumanConfirmation) -> Result<ApprovalId> {
        if confirmation.target != *id {
            return Err(invalid_input("confirmation is for a different request"));
        }
        let now = self.clock.unix_secs();
        let intent = {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db)?;
            let row =
                fetch(&tx, id)?.ok_or_else(|| invalid_input("unknown approval request id"))?;
            if PendingStatus::from_db(&row.status)? != PendingStatus::Pending
                || to_u64(row.expires_at) <= now
            {
                return Err(Error::new(
                    ErrorCode::ApprovalInvalid,
                    "request is not pending (expired, decided, or unknown)",
                ));
            }
            let stored_binding = row.binding;
            let intent = row.intent()?;
            if !bool::from(intent.binding().0.ct_eq(&stored_binding)) {
                return Err(Error::new(
                    ErrorCode::ApprovalInvalid,
                    "stored request failed its integrity check",
                ));
            }
            tx.execute(
                "UPDATE pending_approvals SET status = 'granted' WHERE id = ?1",
                params![id.as_str()],
            )
            .map_err(db)?;
            tx.commit().map_err(db)?;
            intent
        };
        match self.issuer.issue(&Confirmed, &intent, self.token_ttl) {
            Ok(token) => Ok(token),
            Err(e) => {
                // Nothing was minted; let the human retry.
                if let Ok(conn) = self.lock()
                    && let Err(revert) = conn.execute(
                        "UPDATE pending_approvals SET status = 'pending' WHERE id = ?1 AND status = 'granted'",
                        params![id.as_str()],
                    )
                {
                    tracing::error!(error = %revert, "could not revert failed grant");
                }
                Err(e)
            }
        }
    }

    /// Rejects a request. Returns false when it was not pending.
    pub fn deny(&self, id: &PendingId) -> Result<bool> {
        let conn = self.lock()?;
        let changed = conn
            .execute(
                "UPDATE pending_approvals SET status = ?2 WHERE id = ?1 AND status = 'pending'",
                params![id.as_str(), PendingStatus::Denied.as_str()],
            )
            .map_err(db)?;
        Ok(changed == 1)
    }
}

const SELECT_ROW: &str = "SELECT id, principal, account, binding, recipients, subject, \
     content_hash, attachments, created_at, expires_at, status FROM pending_approvals";

struct Row {
    id: String,
    principal: String,
    account: String,
    binding: [u8; 32],
    recipients: String,
    subject: String,
    content_hash: [u8; 32],
    attachments: Vec<u8>,
    created_at: i64,
    expires_at: i64,
    status: String,
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let fixed = |i: usize| -> rusqlite::Result<[u8; 32]> {
        let v: Vec<u8> = r.get(i)?;
        v.try_into().map_err(|_| {
            rusqlite::Error::InvalidColumnType(i, "hash".into(), rusqlite::types::Type::Blob)
        })
    };
    Ok(Row {
        id: r.get(0)?,
        principal: r.get(1)?,
        account: r.get(2)?,
        binding: fixed(3)?,
        recipients: r.get(4)?,
        subject: r.get(5)?,
        content_hash: fixed(6)?,
        attachments: r.get(7)?,
        created_at: r.get(8)?,
        expires_at: r.get(9)?,
        status: r.get(10)?,
    })
}

fn fetch(conn: &Connection, id: &PendingId) -> Result<Option<Row>> {
    conn.query_row(
        &format!("{SELECT_ROW} WHERE id = ?1"),
        params![id.as_str()],
        read_row,
    )
    .optional()
    .map_err(db)
}

impl Row {
    fn atts(&self) -> Result<Vec<Sha256Digest>> {
        let (chunks, rest) = self.attachments.as_chunks::<32>();
        if !rest.is_empty() {
            return Err(Error::new(ErrorCode::Internal, "corrupt approval row"));
        }
        Ok(chunks.iter().map(|c| Sha256Digest(*c)).collect())
    }

    fn intent(&self) -> Result<SendIntent> {
        let recipients: Vec<&str> = self.recipients.split('\n').collect();
        SendIntent::new(
            self.principal.clone(),
            AccountId::new(&self.account)?,
            &recipients,
            &self.subject,
            Sha256Digest(self.content_hash),
            &self.atts()?,
        )
    }

    fn into_approval(self) -> Result<PendingApproval> {
        Ok(PendingApproval {
            id: PendingId::parse(&self.id)?,
            account: AccountId::new(&self.account)?,
            recipients: self.recipients.split('\n').map(str::to_owned).collect(),
            content_hash: hex(&self.content_hash),
            attachment_sha256: self.atts()?.iter().map(|d| hex(&d.0)).collect(),
            created_at: to_u64(self.created_at),
            expires_at: to_u64(self.expires_at),
            status: PendingStatus::from_db(&self.status)?,
            principal: self.principal,
            subject: self.subject,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn to_i64(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::new(ErrorCode::Internal, "time out of range"))
}

/// Negative values only come from a corrupt row; 0 makes them read as expired.
fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}
