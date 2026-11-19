//! Bounded session pool. Sessions are created lazily, capped per account
//! (`max_connections`) and globally (`Limits::max_global_connections`). Idle sessions
//! keep their global permit (they are real sockets) but are evicted on demand, so
//! 100 configured accounts never hold 100 sockets and one busy account cannot be
//! starved by idle ones elsewhere.
use std::collections::HashMap;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};

use openmail_core::backend::SecretSource;
use openmail_core::config::{AccountConfig, Limits};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;

use crate::conn::{self, ImapSession};
use crate::error::{ImapError, ImapResult};

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
    fn session(&mut self) -> &mut ImapSession {
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

    fn evict_one_idle(&self) -> bool {
        self.inner.slots.values().any(|s| {
            s.idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
                .is_some()
        })
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

    /// Runs `op` on a pooled session with the account timeout. When `retry` is set and
    /// the session turns out to be dead (server restart, dropped TCP), the operation is
    /// re-run once on a fresh connection; pass `false` for non-idempotent operations.
    pub async fn run<T>(
        &self,
        id: &AccountId,
        retry: bool,
        mut op: impl AsyncFnMut(&mut ImapSession) -> ImapResult<T>,
    ) -> Result<T> {
        let wait = self.account(id)?.timeout();
        let attempts = if retry { 2 } else { 1 };
        let mut last = ImapError::core(ErrorCode::Internal, "no attempt made");
        for attempt in 0..attempts {
            let mut lease = self.acquire(id).await.map_err(Error::from)?;
            let outcome = timeout(wait, op(lease.session())).await;
            match outcome {
                Ok(Ok(v)) => return Ok(v),
                Ok(Err(e)) if !e.is_connection_level() => return Err(e.into()),
                Ok(Err(e)) => {
                    lease.discard();
                    tracing::debug!(account = %id, attempt, "IMAP session failed, discarded");
                    last = e;
                }
                Err(_) => {
                    lease.discard();
                    return Err(ImapError::Timeout.into());
                }
            }
        }
        Err(last.into())
    }

    /// Closes every idle session (shutdown / config reload).
    pub fn close_idle(&self) {
        while self.evict_one_idle() {}
        self.inner.available.notify_waiters();
    }
}
