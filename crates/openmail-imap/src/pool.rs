//! Bounded session pool. Sessions are created lazily, capped per account
//! (`max_connections`) and globally (`Limits::max_global_connections`). Idle sessions
//! keep their global permit (they are real sockets) but are evicted on demand, so
//! 100 configured accounts never hold 100 sockets and one busy account cannot be
//! starved by idle ones elsewhere.
use std::collections::HashMap;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use openmail_core::backend::SecretSource;
use openmail_core::config::{AccountConfig, Limits};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;

use crate::conn::{self, ImapSession};
use crate::error::{ImapError, ImapResult};

/// Bound on the courtesy LOGOUT when evicting; a stuck server must not hold a permit.
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

struct Idle {
    session: ImapSession,
    _global: OwnedSemaphorePermit,
}

struct Slot {
    cfg: AccountConfig,
    permits: Arc<Semaphore>,
    idle: Mutex<Vec<Idle>>,
}

struct Inner {
    slots: HashMap<AccountId, Slot>,
    global: Arc<Semaphore>,
    global_cap: usize,
    /// Woken whenever a global permit or an idle session becomes available.
    available: Notify,
    secrets: Arc<dyn SecretSource>,
    tls: TlsConnector,
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("accounts", &self.inner.slots.len())
            .finish_non_exhaustive()
    }
}

/// A checked-out session. Returned to the idle list on drop unless discarded.
pub struct Lease {
    session: Option<ImapSession>,
    global: Option<OwnedSemaphorePermit>,
    _account: OwnedSemaphorePermit,
    inner: Arc<Inner>,
    account: AccountId,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl Lease {
    pub fn session(&mut self) -> &mut ImapSession {
        // Invariant: `session` is Some until `discard`/drop consume the lease.
        self.session
            .as_mut()
            .unwrap_or_else(|| unreachable!("lease used after discard"))
    }

    /// Drops the session (it is in an unknown state) instead of pooling it.
    fn discard(&mut self) {
        self.session = None;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let global = self.global.take();
        match (self.session.take(), global) {
            (Some(session), Some(permit)) => {
                if let Some(slot) = self.inner.slots.get(&self.account) {
                    slot.idle
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(Idle {
                            session,
                            _global: permit,
                        });
                }
            }
            (_, permit) => drop(permit),
        }
        self.inner.available.notify_waiters();
    }
}

pub enum Flow<T> {
    Done(Result<T>),
    Retry,
}

/// Pins an async block's output type to `ImapResult<T>` so `?` inside it converts errors.
pub fn typed<T>(
    fut: impl std::future::Future<Output = ImapResult<T>>,
) -> impl std::future::Future<Output = ImapResult<T>> {
    fut
}

/// Runs `$body` (an expression of type `ImapResult<T>` using `$s: &mut ImapSession`) on a
/// pooled session with the account timeout. With `$retry`, a dead session is replaced
/// once; pass `false` for non-idempotent operations. A macro rather than a closure
/// parameter because async closures over `&mut` sessions cannot be proven `Send`
/// (rustc higher-ranked limitation), which would make every backend call un-spawnable.
macro_rules! with_session {
    ($pool:expr, $id:expr, $retry:expr, |$s:ident| $body:expr) => {{
        let pool: &$crate::pool::Pool = &$pool;
        let id = $id;
        let attempts: usize = if $retry { 2 } else { 1 };
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let wait = match pool.account(id) {
                Ok(cfg) => cfg.timeout(),
                Err(e) => break Err(e),
            };
            let mut lease = match pool.lease(id).await {
                Ok(l) => l,
                Err(e) => break Err(e),
            };
            let outcome = ::tokio::time::timeout(
                wait,
                $crate::pool::typed(async {
                    let $s = lease.session();
                    $body
                }),
            )
            .await;
            match pool.settle(&mut lease, outcome, attempt, attempts) {
                $crate::pool::Flow::Done(r) => break r,
                $crate::pool::Flow::Retry => continue,
            }
        }
    }};
}
pub(crate) use with_session;

impl Pool {
    pub fn new(
        accounts: Vec<AccountConfig>,
        limits: &Limits,
        secrets: Arc<dyn SecretSource>,
        tls: TlsConnector,
    ) -> Self {
        let slots = accounts
            .into_iter()
            .map(|cfg| {
                let id = cfg.id.clone();
                let permits = Arc::new(Semaphore::new(usize::from(cfg.max_connections)));
                (
                    id,
                    Slot {
                        cfg,
                        permits,
                        idle: Mutex::new(Vec::new()),
                    },
                )
            })
            .collect();
        let global_cap = usize::from(limits.max_global_connections.max(1));
        let global = Arc::new(Semaphore::new(global_cap));
        Self {
            inner: Arc::new(Inner {
                slots,
                global,
                global_cap,
                available: Notify::new(),
                secrets,
                tls,
            }),
        }
    }

    pub fn account(&self, id: &AccountId) -> Result<&AccountConfig> {
        self.inner.slots.get(id).map(|s| &s.cfg).ok_or_else(|| {
            Error::new(
                ErrorCode::AccountNotFound,
                format!("unknown account '{id}'"),
            )
        })
    }

    /// Number of sockets currently held (leased + idle); used by tests and diagnostics.
    pub fn open_sessions(&self) -> usize {
        self.inner
            .global_cap
            .saturating_sub(self.inner.global.available_permits())
    }

    fn limit_error(what: &str) -> ImapError {
        ImapError::core(
            ErrorCode::LimitExceeded,
            format!("timed out waiting for a free {what} connection slot"),
        )
    }

    /// Closes one idle session politely. The socket's global permit is held until the
    /// LOGOUT round trip finishes, so the global cap bounds real server-side sockets
    /// rather than just our bookkeeping.
    fn evict_one_idle(&self) -> bool {
        let Some(idle) = self
            .inner
            .slots
            .values()
            .find_map(|s| s.idle.lock().unwrap_or_else(PoisonError::into_inner).pop())
        else {
            return false;
        };
        let inner = self.inner.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return true; // no runtime to run LOGOUT on: plain drop closes the socket
        };
        handle.spawn(async move {
            let Idle {
                mut session,
                _global,
            } = idle;
            let _ = timeout(LOGOUT_TIMEOUT, session.logout()).await;
            drop(session);
            drop(_global);
            inner.available.notify_waiters();
        });
        true
    }

    async fn acquire_global(&self, deadline: Instant) -> ImapResult<OwnedSemaphorePermit> {
        loop {
            let mut wake = pin!(self.inner.available.notified());
            wake.as_mut().enable();
            if let Ok(p) = self.inner.global.clone().try_acquire_owned() {
                return Ok(p);
            }
            if self.evict_one_idle() {
                continue;
            }
            if timeout(deadline.saturating_duration_since(Instant::now()), wake)
                .await
                .is_err()
            {
                return Err(Self::limit_error("global"));
            }
        }
    }

    async fn acquire(&self, id: &AccountId) -> ImapResult<Lease> {
        let slot = self.inner.slots.get(id).ok_or_else(|| {
            ImapError::core(
                ErrorCode::AccountNotFound,
                format!("unknown account '{id}'"),
            )
        })?;
        let wait = slot.cfg.timeout();
        let deadline = Instant::now() + wait;
        let account_permit = timeout(wait, slot.permits.clone().acquire_owned())
            .await
            .map_err(|_| Self::limit_error("per-account"))?
            .map_err(|_| ImapError::core(ErrorCode::Internal, "connection pool closed"))?;

        // Prefer a pooled session, verifying it is still alive.
        loop {
            let idle = slot
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            let Some(Idle {
                mut session,
                _global,
            }) = idle
            else {
                break;
            };
            if timeout(wait, session.noop()).await.is_ok_and(|r| r.is_ok()) {
                return Ok(Lease {
                    session: Some(session),
                    global: Some(_global),
                    _account: account_permit,
                    inner: self.inner.clone(),
                    account: id.clone(),
                });
            }
            tracing::debug!(account = %id, "discarding dead pooled IMAP session");
        }

        let global = self.acquire_global(deadline).await?;
        let secrets = self.inner.secrets.clone();
        let cred = slot.cfg.credential.clone();
        let secret = tokio::task::spawn_blocking(move || secrets.resolve(&cred))
            .await
            .map_err(|_| ImapError::core(ErrorCode::Internal, "secret resolution task failed"))??;
        let session = timeout(wait, conn::open(&slot.cfg, &secret, &self.inner.tls))
            .await
            .map_err(|_| ImapError::Timeout)??;
        tracing::debug!(account = %id, "opened IMAP session");
        Ok(Lease {
            session: Some(session),
            global: Some(global),
            _account: account_permit,
            inner: self.inner.clone(),
            account: id.clone(),
        })
    }

    /// Checks out a session (pooled or freshly connected). Hold it only briefly.
    pub async fn lease(&self, id: &AccountId) -> Result<Lease> {
        self.acquire(id).await.map_err(Error::from)
    }

    /// Decides what a finished attempt means for the lease and the caller. A dead
    /// session is discarded; with attempts left the caller retries on a fresh
    /// connection. Timeouts are never retried (the operation may still be running).
    pub fn settle<T>(
        &self,
        lease: &mut Lease,
        outcome: Result<ImapResult<T>, tokio::time::error::Elapsed>,
        attempt: usize,
        attempts: usize,
    ) -> Flow<T> {
        match outcome {
            Ok(Ok(v)) => Flow::Done(Ok(v)),
            Ok(Err(e)) if !e.is_connection_level() => Flow::Done(Err(e.into())),
            Ok(Err(e)) => {
                lease.discard();
                tracing::debug!(account = %lease.account, attempt, "IMAP session failed, discarded");
                if attempt < attempts {
                    Flow::Retry
                } else {
                    Flow::Done(Err(e.into()))
                }
            }
            Err(_) => {
                lease.discard();
                Flow::Done(Err(ImapError::Timeout.into()))
            }
        }
    }

    /// Closes every idle session (shutdown / config reload).
    pub fn close_idle(&self) {
        while self.evict_one_idle() {}
        self.inner.available.notify_waiters();
    }
}
