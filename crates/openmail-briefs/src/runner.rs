//! Runs briefs on a schedule: a [`JobHandler`] that generates (and optionally emails) a
//! brief, and the loop that ticks the scheduler. The lease and last-run state live in SQLite
//! ([`crate::store::SqliteSchedulerStore`]), so two processes never run the same fire time.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use openmail_core::ErrorCode;
use openmail_core::backend::MailBackend;

use crate::config::{BriefsConfig, parse_lookback};
use crate::delivery::{DigestSender, EmailDigestAdapter};
use crate::engine::{BriefAccount, BriefEngine, GenerateRequest};
use crate::present::deliverable;
use crate::scheduler::{
    Backoff, Clock, CompiledJob, JobHandler, RunFailure, Scheduler, SchedulerError,
};
use crate::store::SqliteSchedulerStore;

/// How often the loop asks the scheduler what is due. Cron has minute resolution.
const TICK: Duration = Duration::from_secs(30);
/// Longest a run (all accounts, retries included) may hold the lease before another process
/// may take over; generous so a slow account never lets two runs overlap.
const LEASE_TTL: Duration = Duration::from_secs(20 * 60);

/// Wall clock for the scheduler.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSchedulerClock;

impl Clock for SystemSchedulerClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// What one schedule does when it fires.
#[derive(Debug, Clone)]
pub struct JobPlan {
    pub accounts: Vec<BriefAccount>,
    pub lookback: Duration,
    pub digest: bool,
}

#[derive(Debug)]
pub struct BriefJobHandler<B: MailBackend, D: DigestSender> {
    engine: Arc<BriefEngine<B>>,
    plans: HashMap<String, JobPlan>,
    /// Digest adapter plus the one address it may mail (the owner of the digest account).
    digest: Option<(EmailDigestAdapter<D>, String)>,
}

impl<B: MailBackend, D: DigestSender> BriefJobHandler<B, D> {
    pub fn new(
        engine: Arc<BriefEngine<B>>,
        plans: HashMap<String, JobPlan>,
        digest: Option<(D, String)>,
    ) -> Self {
        Self {
            engine,
            plans,
            digest: digest.map(|(sender, to)| (EmailDigestAdapter::new(sender), to)),
        }
    }
}

impl<B: MailBackend, D: DigestSender + Send + Sync> JobHandler for BriefJobHandler<B, D> {
    async fn run(&self, job_id: &str, scheduled_for: DateTime<Utc>) -> Result<(), RunFailure> {
        let Some(plan) = self.plans.get(job_id) else {
            return Err(RunFailure {
                message: format!("no plan for job `{job_id}`"),
                retryable: false,
            });
        };
        let failure = |e: openmail_core::Error| RunFailure {
            retryable: !matches!(
                e.code(),
                ErrorCode::AccessDenied | ErrorCode::ConfigInvalid | ErrorCode::InvalidInput
            ),
            message: e.to_string(),
        };
        let brief = self
            .engine
            .generate(&GenerateRequest {
                accounts: plan.accounts.clone(),
                lookback: plan.lookback,
                include_processed: false,
            })
            .await
            .map_err(failure)?;
        if plan.digest {
            let Some((adapter, to)) = &self.digest else {
                return Err(RunFailure {
                    message: "schedule wants a digest but none is configured".into(),
                    retryable: false,
                });
            };
            // Keyed by job and fire time: a restart that re-runs this fire cannot mail twice.
            let id = format!("{job_id}@{}", scheduled_for.to_rfc3339());
            adapter
                .deliver(&deliverable(&brief, &id), to)
                .await
                .map_err(failure)?;
        }
        Ok(())
    }
}

/// Jobs for every schedule in `config`, with their persisted creation baselines.
pub fn compile_jobs(
    config: &BriefsConfig,
    store: &SqliteSchedulerStore,
) -> Result<Vec<CompiledJob>, SchedulerError> {
    let now = Utc::now();
    config
        .schedule
        .iter()
        .map(|s| CompiledJob::compile(s.job_spec(store.job_created_at(&s.id, now)?)))
        .collect()
}

/// Plans keyed by schedule id; `all` is used when a schedule names no accounts.
pub fn plans(
    config: &BriefsConfig,
    all: &[BriefAccount],
) -> Result<HashMap<String, JobPlan>, openmail_core::Error> {
    let default_lookback = config.lookback()?;
    config
        .schedule
        .iter()
        .map(|s| {
            let accounts: Vec<BriefAccount> = if s.accounts.is_empty() {
                all.to_vec()
            } else {
                all.iter()
                    .filter(|a| s.accounts.contains(&a.id))
                    .cloned()
                    .collect()
            };
            let lookback = match &s.lookback {
                Some(l) => parse_lookback(l)?,
                None => default_lookback,
            };
            Ok((
                s.id.clone(),
                JobPlan {
                    accounts,
                    lookback,
                    digest: s.digest,
                },
            ))
        })
        .collect()
}

/// Tick forever (until the task is aborted at shutdown). Errors are logged and the loop
/// continues: a database hiccup must not end scheduling for the life of the process.
pub async fn run_forever<C, S, H>(scheduler: Scheduler<C, S, H>, jobs: Vec<CompiledJob>)
where
    C: Clock,
    S: crate::scheduler::SchedulerStore,
    H: JobHandler,
{
    loop {
        match scheduler.tick(&jobs).await {
            Ok(outcomes) => {
                for (job, outcome) in outcomes {
                    tracing::debug!(job, ?outcome, "brief schedule tick");
                }
            }
            Err(e) => tracing::error!(error = %e, "brief scheduler tick failed"),
        }
        tokio::time::sleep(TICK).await;
    }
}

/// A scheduler wired to the shared SQLite state. `owner` must be unique per process.
pub fn scheduler<H: JobHandler>(
    store: SqliteSchedulerStore,
    handler: H,
    owner: String,
) -> Scheduler<SystemSchedulerClock, SqliteSchedulerStore, H> {
    Scheduler::new(
        SystemSchedulerClock,
        store,
        handler,
        owner,
        LEASE_TTL,
        Backoff::default(),
    )
}
