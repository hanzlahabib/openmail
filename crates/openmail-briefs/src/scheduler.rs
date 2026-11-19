//! Opt-in brief scheduler.
//!
//! Jobs are disabled unless explicitly enabled. Fire times come from a cron
//! expression evaluated in an IANA timezone (DST handled by `croner` +
//! `chrono-tz`). A [`SchedulerStore`] persists the last completed run and a
//! lease so that two processes never run the same job concurrently; missed
//! runs are recovered on the next tick; failures retry with exponential
//! backoff. Time is injected through [`Clock`].

use std::future::Future;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc, Weekday};
use chrono_tz::Tz;
use croner::Cron;

/// Upper bound on fire times examined per tick, so a per-minute cron after a
/// long downtime cannot make one tick unbounded.
const MAX_CATCHUP_FIRES: usize = 10_000;

/// Errors from compiling jobs or from the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("unknown IANA timezone: {0}")]
    InvalidTimezone(String),
    #[error("invalid schedule: {0}")]
    InvalidSchedule(String),
    #[error("scheduler store failure: {0}")]
    Store(String),
}

/// How often a job fires (local wall-clock time in the job's timezone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    Daily {
        hour: u8,
        minute: u8,
    },
    Weekly {
        day: Weekday,
        hour: u8,
        minute: u8,
    },
    /// Standard 5-field cron expression.
    Cron(String),
}

impl Schedule {
    fn to_cron_expr(&self) -> Result<String, SchedulerError> {
        let check = |hour: u8, minute: u8| {
            if hour > 23 || minute > 59 {
                Err(SchedulerError::InvalidSchedule(format!(
                    "time {hour:02}:{minute:02} out of range"
                )))
            } else {
                Ok(())
            }
        };
        match self {
            Self::Daily { hour, minute } => {
                check(*hour, *minute)?;
                Ok(format!("{minute} {hour} * * *"))
            }
            Self::Weekly { day, hour, minute } => {
                check(*hour, *minute)?;
                Ok(format!(
                    "{minute} {hour} * * {}",
                    day.num_days_from_sunday()
                ))
            }
            Self::Cron(expr) => Ok(expr.clone()),
        }
    }
}

/// What to do with fire times that passed while the scheduler was not running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissedPolicy {
    /// Run once for the most recent missed fire time (coalesce).
    RunLatest,
    /// Run only if the latest fire time is within `grace`; otherwise record it as skipped.
    SkipOlderThan(Duration),
}

/// Declarative job definition.
#[derive(Debug, Clone)]
pub struct JobSpec {
    pub id: String,
    pub schedule: Schedule,
    /// IANA name, e.g. `Europe/Berlin`.
    pub timezone: String,
    /// Opt-in: a job never runs unless this is `true`.
    pub enabled: bool,
    /// Fire times at or before this instant are never considered missed.
    pub created_at: DateTime<Utc>,
    pub missed: MissedPolicy,
}

/// A validated job (parsed cron + timezone).
#[derive(Debug, Clone)]
pub struct CompiledJob {
    spec: JobSpec,
    cron: Cron,
    tz: Tz,
}

impl CompiledJob {
    pub fn compile(spec: JobSpec) -> Result<Self, SchedulerError> {
        let tz = Tz::from_str(&spec.timezone)
            .map_err(|_| SchedulerError::InvalidTimezone(spec.timezone.clone()))?;
        let expr = spec.schedule.to_cron_expr()?;
        let cron =
            Cron::from_str(&expr).map_err(|e| SchedulerError::InvalidSchedule(e.to_string()))?;
        Ok(Self { spec, cron, tz })
    }

    pub fn spec(&self) -> &JobSpec {
        &self.spec
    }

    /// First fire time strictly after `after`, or `None` if the cron never fires again.
    pub fn next_fire_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let local = after.with_timezone(&self.tz);
        self.cron
            .find_next_occurrence(&local, false)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    /// All fire times in `(since, until]`, capped at [`MAX_CATCHUP_FIRES`].
    fn fires_between(&self, since: DateTime<Utc>, until: DateTime<Utc>) -> Vec<DateTime<Utc>> {
        let mut out = Vec::new();
        let mut cursor = since;
        while out.len() < MAX_CATCHUP_FIRES {
            match self.next_fire_after(cursor) {
                Some(t) if t <= until => {
                    out.push(t);
                    cursor = t;
                }
                _ => break,
            }
        }
        out
    }
}

/// Injected time source (wall clock in production, fake in tests).
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

/// Persistence contract for scheduler state.
pub trait SchedulerStore: Send + Sync {
    /// Scheduled fire time of the last completed (or deliberately skipped) run.
    fn last_run(
        &self,
        job_id: &str,
    ) -> impl Future<Output = Result<Option<DateTime<Utc>>, SchedulerError>> + Send;
    fn record_run(
        &self,
        job_id: &str,
        scheduled_for: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), SchedulerError>> + Send;
    /// Atomically take the job's lease for `owner` unless another owner holds an unexpired one.
    /// Re-acquiring as the same owner succeeds. Returns whether the lease is now held.
    fn try_acquire(
        &self,
        job_id: &str,
        owner: &str,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> impl Future<Output = Result<bool, SchedulerError>> + Send;
    fn release(
        &self,
        job_id: &str,
        owner: &str,
    ) -> impl Future<Output = Result<(), SchedulerError>> + Send;
}

/// Failure reported by a [`JobHandler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFailure {
    pub message: String,
    pub retryable: bool,
}

/// Executes a job for one scheduled fire time.
pub trait JobHandler: Send + Sync {
    fn run(
        &self,
        job_id: &str,
        scheduled_for: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), RunFailure>> + Send;
}

/// Exponential backoff: `initial * 2^(attempt-1)`, capped at `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    /// Total attempts including the first.
    pub max_attempts: u32,
}

impl Backoff {
    fn delay_after(&self, failed_attempt: u32) -> Duration {
        let factor = 1u32
            .checked_shl(failed_attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(30),
            max: Duration::from_secs(15 * 60),
            max_attempts: 4,
        }
    }
}

/// Result of processing one job during a tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Disabled,
    NotDue,
    /// Another owner holds the lease.
    LeaseHeld,
    Completed {
        scheduled_for: DateTime<Utc>,
        attempts: u32,
    },
    /// Missed run dropped by [`MissedPolicy::SkipOlderThan`].
    Skipped {
        scheduled_for: DateTime<Utc>,
    },
    /// Retries exhausted (or non-retryable); not recorded, so the next tick tries again.
    Failed {
        scheduled_for: DateTime<Utc>,
        attempts: u32,
        message: String,
    },
}

#[derive(Debug)]
pub struct Scheduler<C, S, H> {
    clock: C,
    store: S,
    handler: H,
    owner: String,
    lease_ttl: Duration,
    backoff: Backoff,
}

impl<C: Clock, S: SchedulerStore, H: JobHandler> Scheduler<C, S, H> {
    /// `owner` must be unique per process. `lease_ttl` must exceed the longest
    /// expected run including retries, or a second process may take over mid-run.
    pub fn new(
        clock: C,
        store: S,
        handler: H,
        owner: impl Into<String>,
        lease_ttl: Duration,
        backoff: Backoff,
    ) -> Self {
        Self {
            clock,
            store,
            handler,
            owner: owner.into(),
            lease_ttl,
            backoff,
        }
    }

    /// Process every job once. Call periodically (e.g. every minute).
    pub async fn tick(
        &self,
        jobs: &[CompiledJob],
    ) -> Result<Vec<(String, RunOutcome)>, SchedulerError> {
        let mut outcomes = Vec::with_capacity(jobs.len());
        for job in jobs {
            let outcome = self.tick_job(job).await?;
            outcomes.push((job.spec.id.clone(), outcome));
        }
        Ok(outcomes)
    }

    async fn tick_job(&self, job: &CompiledJob) -> Result<RunOutcome, SchedulerError> {
        let id = job.spec.id.as_str();
        if !job.spec.enabled {
            return Ok(RunOutcome::Disabled);
        }
        if !self
            .store
            .try_acquire(id, &self.owner, self.clock.now(), self.lease_ttl)
            .await?
        {
            return Ok(RunOutcome::LeaseHeld);
        }
        let outcome = self.run_locked(job).await;
        // Release even on error; a failed release must not mask the original result.
        if let Err(e) = self.store.release(id, &self.owner).await {
            tracing::warn!(job = id, error = %e, "failed to release scheduler lease");
        }
        outcome
    }

    async fn run_locked(&self, job: &CompiledJob) -> Result<RunOutcome, SchedulerError> {
        let id = job.spec.id.as_str();
        let now = self.clock.now();
        // Read after acquiring the lease so a run finished by another owner is seen.
        let baseline = self
            .store
            .last_run(id)
            .await?
            .unwrap_or(job.spec.created_at);
        let Some(&latest) = job.fires_between(baseline, now).last() else {
            return Ok(RunOutcome::NotDue);
        };
        if let MissedPolicy::SkipOlderThan(grace) = job.spec.missed {
            let age = (now - latest).to_std().unwrap_or_default();
            if age > grace {
                self.store.record_run(id, latest).await?;
                return Ok(RunOutcome::Skipped {
                    scheduled_for: latest,
                });
            }
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.handler.run(id, latest).await {
                Ok(()) => {
                    self.store.record_run(id, latest).await?;
                    return Ok(RunOutcome::Completed {
                        scheduled_for: latest,
                        attempts,
                    });
                }
                Err(f) if f.retryable && attempts < self.backoff.max_attempts => {
                    tracing::warn!(job = id, attempts, error = %f.message, "brief run failed; retrying");
                    self.clock.sleep(self.backoff.delay_after(attempts)).await;
                }
                Err(f) => {
                    return Ok(RunOutcome::Failed {
                        scheduled_for: latest,
                        attempts,
                        message: f.message,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // tests may expect(); production code may not
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use chrono::TimeZone;

    use super::*;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0)
            .single()
            .expect("valid test time")
    }

    #[derive(Debug, Clone)]
    struct FakeClock {
        now: Arc<Mutex<DateTime<Utc>>>,
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl FakeClock {
        fn at(t: DateTime<Utc>) -> Self {
            Self {
                now: Arc::new(Mutex::new(t)),
                sleeps: Arc::default(),
            }
        }
        fn set(&self, t: DateTime<Utc>) {
            *self.now.lock().expect("lock") = t;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            *self.now.lock().expect("lock")
        }
        async fn sleep(&self, d: Duration) {
            self.sleeps.lock().expect("lock").push(d);
            let mut n = self.now.lock().expect("lock");
            *n += chrono::Duration::from_std(d).expect("duration");
        }
    }

    /// (owner, expiry)
    type Lease = (String, DateTime<Utc>);

    #[derive(Debug, Clone, Default)]
    struct MemStore {
        last: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
        leases: Arc<Mutex<HashMap<String, Lease>>>,
    }

    impl SchedulerStore for MemStore {
        async fn last_run(&self, job: &str) -> Result<Option<DateTime<Utc>>, SchedulerError> {
            Ok(self.last.lock().expect("lock").get(job).copied())
        }
        async fn record_run(&self, job: &str, at: DateTime<Utc>) -> Result<(), SchedulerError> {
            self.last.lock().expect("lock").insert(job.to_owned(), at);
            Ok(())
        }
        async fn try_acquire(
            &self,
            job: &str,
            owner: &str,
            now: DateTime<Utc>,
            ttl: Duration,
        ) -> Result<bool, SchedulerError> {
            let mut leases = self.leases.lock().expect("lock");
            if let Some((o, exp)) = leases.get(job)
                && o != owner
                && *exp > now
            {
                return Ok(false);
            }
            let exp = now + chrono::Duration::from_std(ttl).expect("ttl");
            leases.insert(job.to_owned(), (owner.to_owned(), exp));
            Ok(true)
        }
        async fn release(&self, job: &str, owner: &str) -> Result<(), SchedulerError> {
            let mut leases = self.leases.lock().expect("lock");
            if leases.get(job).is_some_and(|(o, _)| o == owner) {
                leases.remove(job);
            }
            Ok(())
        }
    }

    /// Fails the first `fail_times` calls; yields so concurrent tickers interleave.
    #[derive(Debug, Clone, Default)]
    struct CountingHandler {
        calls: Arc<AtomicU32>,
        fail_times: u32,
        retryable: bool,
    }

    impl JobHandler for CountingHandler {
        async fn run(&self, _job: &str, _at: DateTime<Utc>) -> Result<(), RunFailure> {
            tokio::task::yield_now().await;
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                Err(RunFailure {
                    message: "boom".into(),
                    retryable: self.retryable,
                })
            } else {
                Ok(())
            }
        }
    }

    fn daily(tz: &str, hour: u8, minute: u8, created: DateTime<Utc>) -> CompiledJob {
        CompiledJob::compile(JobSpec {
            id: "daily".into(),
            schedule: Schedule::Daily { hour, minute },
            timezone: tz.into(),
            enabled: true,
            created_at: created,
            missed: MissedPolicy::RunLatest,
        })
        .expect("compile")
    }

    fn scheduler(
        clock: &FakeClock,
        store: &MemStore,
        handler: &CountingHandler,
        owner: &str,
    ) -> Scheduler<FakeClock, MemStore, CountingHandler> {
        let backoff = Backoff {
            initial: Duration::from_secs(10),
            max: Duration::from_secs(60),
            max_attempts: 4,
        };
        Scheduler::new(
            clock.clone(),
            store.clone(),
            handler.clone(),
            owner,
            Duration::from_secs(300),
            backoff,
        )
    }

    #[test]
    fn rejects_bad_timezone_and_schedule() {
        let mut spec = JobSpec {
            id: "x".into(),
            schedule: Schedule::Daily { hour: 8, minute: 0 },
            timezone: "Mars/Olympus".into(),
            enabled: true,
            created_at: utc(2026, 1, 1, 0, 0),
            missed: MissedPolicy::RunLatest,
        };
        assert!(matches!(
            CompiledJob::compile(spec.clone()),
            Err(SchedulerError::InvalidTimezone(_))
        ));
        spec.timezone = "UTC".into();
        spec.schedule = Schedule::Daily {
            hour: 24,
            minute: 0,
        };
        assert!(matches!(
            CompiledJob::compile(spec.clone()),
            Err(SchedulerError::InvalidSchedule(_))
        ));
        spec.schedule = Schedule::Cron("not a cron".into());
        assert!(matches!(
            CompiledJob::compile(spec),
            Err(SchedulerError::InvalidSchedule(_))
        ));
    }

    #[test]
    fn weekly_fires_on_requested_weekday() {
        let job = CompiledJob::compile(JobSpec {
            id: "w".into(),
            schedule: Schedule::Weekly {
                day: Weekday::Mon,
                hour: 9,
                minute: 0,
            },
            timezone: "UTC".into(),
            enabled: true,
            created_at: utc(2026, 1, 1, 0, 0),
            missed: MissedPolicy::RunLatest,
        })
        .expect("compile");
        // 2026-03-04 is a Wednesday -> next Monday is 2026-03-09.
        assert_eq!(
            job.next_fire_after(utc(2026, 3, 4, 12, 0)),
            Some(utc(2026, 3, 9, 9, 0))
        );
    }

    #[test]
    fn dst_spring_forward_fires_once_and_keeps_local_time() {
        // New York 2026-03-08: 02:00 -> 03:00 (EST UTC-5 -> EDT UTC-4). 08:00 local daily.
        let job = daily("America/New_York", 8, 0, utc(2026, 3, 1, 0, 0));
        let before = job.next_fire_after(utc(2026, 3, 7, 14, 0)).expect("fire");
        let after = job.next_fire_after(before).expect("fire");
        assert_eq!(before, utc(2026, 3, 8, 12, 0)); // 08:00 EDT
        assert_eq!(after, utc(2026, 3, 9, 12, 0));
        // Day before the change was 08:00 EST = 13:00 UTC.
        assert_eq!(
            job.next_fire_after(utc(2026, 3, 6, 14, 0)),
            Some(utc(2026, 3, 7, 13, 0))
        );
        // A nonexistent local time (02:30) must still yield exactly one fire that day.
        let gap = daily("America/New_York", 2, 30, utc(2026, 3, 1, 0, 0));
        let fires = gap.fires_between(utc(2026, 3, 7, 12, 0), utc(2026, 3, 9, 12, 0));
        let on_day = fires
            .iter()
            .filter(|t| {
                t.date_naive() == chrono::NaiveDate::from_ymd_opt(2026, 3, 8).expect("date")
            })
            .count();
        assert_eq!(on_day, 1, "fires: {fires:?}");
    }

    #[test]
    fn dst_fall_back_fires_once_for_repeated_hour() {
        // New York 2026-11-01: 02:00 EDT -> 01:00 EST; 01:30 local occurs twice.
        let job = daily("America/New_York", 1, 30, utc(2026, 10, 25, 0, 0));
        let fires = job.fires_between(utc(2026, 10, 31, 12, 0), utc(2026, 11, 2, 12, 0));
        let nov1 = fires
            .iter()
            .filter(|t| {
                t.date_naive() == chrono::NaiveDate::from_ymd_opt(2026, 11, 1).expect("date")
            })
            .count();
        assert_eq!(nov1, 1, "fires: {fires:?}");
    }

    #[tokio::test]
    async fn runs_when_due_then_not_again() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 7, 59));
        let (store, handler) = (MemStore::default(), CountingHandler::default());
        let s = scheduler(&clock, &store, &handler, "a");
        assert_eq!(
            s.tick(std::slice::from_ref(&job)).await.expect("tick")[0].1,
            RunOutcome::NotDue
        );
        clock.set(utc(2026, 5, 1, 8, 0));
        let out = s.tick(std::slice::from_ref(&job)).await.expect("tick");
        assert_eq!(
            out[0].1,
            RunOutcome::Completed {
                scheduled_for: utc(2026, 5, 1, 8, 0),
                attempts: 1
            }
        );
        assert_eq!(
            s.tick(std::slice::from_ref(&job)).await.expect("tick")[0].1,
            RunOutcome::NotDue
        );
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disabled_job_never_runs() {
        let mut spec = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0)).spec().clone();
        spec.enabled = false;
        let job = CompiledJob::compile(spec).expect("compile");
        let clock = FakeClock::at(utc(2026, 5, 3, 9, 0));
        let (store, handler) = (MemStore::default(), CountingHandler::default());
        let out = scheduler(&clock, &store, &handler, "a")
            .tick(&[job])
            .await
            .expect("tick");
        assert_eq!(out[0].1, RunOutcome::Disabled);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missed_runs_after_downtime_coalesce_to_latest() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 8, 0));
        let (store, handler) = (MemStore::default(), CountingHandler::default());
        let s = scheduler(&clock, &store, &handler, "a");
        s.tick(std::slice::from_ref(&job)).await.expect("tick");
        // Down for three days; restart at 10:00 on May 4.
        clock.set(utc(2026, 5, 4, 10, 0));
        let out = s.tick(std::slice::from_ref(&job)).await.expect("tick");
        assert_eq!(
            out[0].1,
            RunOutcome::Completed {
                scheduled_for: utc(2026, 5, 4, 8, 0),
                attempts: 1
            }
        );
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            2,
            "one run, not one per missed day"
        );
    }

    #[tokio::test]
    async fn skip_policy_drops_stale_missed_run() {
        let mut spec = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0)).spec().clone();
        spec.missed = MissedPolicy::SkipOlderThan(Duration::from_secs(3600));
        let job = CompiledJob::compile(spec).expect("compile");
        let clock = FakeClock::at(utc(2026, 5, 1, 20, 0));
        let (store, handler) = (MemStore::default(), CountingHandler::default());
        let s = scheduler(&clock, &store, &handler, "a");
        let out = s.tick(std::slice::from_ref(&job)).await.expect("tick");
        assert_eq!(
            out[0].1,
            RunOutcome::Skipped {
                scheduled_for: utc(2026, 5, 1, 8, 0)
            }
        );
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        assert_eq!(s.tick(&[job]).await.expect("tick")[0].1, RunOutcome::NotDue);
    }

    #[tokio::test]
    async fn double_start_runs_job_once() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 8, 5));
        let (store, handler) = (MemStore::default(), CountingHandler::default());
        let (a, b) = (
            scheduler(&clock, &store, &handler, "a"),
            scheduler(&clock, &store, &handler, "b"),
        );
        let jobs = [job];
        let (ra, rb) = tokio::join!(a.tick(&jobs), b.tick(&jobs));
        let outcomes = [ra.expect("a")[0].1.clone(), rb.expect("b")[0].1.clone()];
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            1,
            "outcomes: {outcomes:?}"
        );
        assert!(
            outcomes.contains(&RunOutcome::LeaseHeld),
            "outcomes: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, RunOutcome::Completed { .. }))
        );
    }

    #[tokio::test]
    async fn expired_lease_can_be_taken_over() {
        let store = MemStore::default();
        let t0 = utc(2026, 5, 1, 8, 0);
        assert!(
            store
                .try_acquire("j", "dead", t0, Duration::from_secs(60))
                .await
                .expect("acq")
        );
        assert!(
            !store
                .try_acquire(
                    "j",
                    "live",
                    t0 + chrono::Duration::seconds(30),
                    Duration::from_secs(60)
                )
                .await
                .expect("acq")
        );
        assert!(
            store
                .try_acquire(
                    "j",
                    "live",
                    t0 + chrono::Duration::seconds(61),
                    Duration::from_secs(60)
                )
                .await
                .expect("acq")
        );
    }

    #[tokio::test]
    async fn retries_with_exponential_backoff_then_succeeds() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 8, 0));
        let (store, handler) = (
            MemStore::default(),
            CountingHandler {
                fail_times: 2,
                retryable: true,
                ..Default::default()
            },
        );
        let out = scheduler(&clock, &store, &handler, "a")
            .tick(&[job])
            .await
            .expect("tick");
        assert_eq!(
            out[0].1,
            RunOutcome::Completed {
                scheduled_for: utc(2026, 5, 1, 8, 0),
                attempts: 3
            }
        );
        assert_eq!(
            *clock.sleeps.lock().expect("lock"),
            vec![Duration::from_secs(10), Duration::from_secs(20)]
        );
    }

    #[tokio::test]
    async fn exhausted_retries_fail_unrecorded_and_retry_next_tick() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 8, 0));
        let (store, handler) = (
            MemStore::default(),
            CountingHandler {
                fail_times: 4,
                retryable: true,
                ..Default::default()
            },
        );
        let s = scheduler(&clock, &store, &handler, "a");
        let out = s.tick(std::slice::from_ref(&job)).await.expect("tick");
        assert!(
            matches!(out[0].1, RunOutcome::Failed { attempts: 4, .. }),
            "{:?}",
            out[0].1
        );
        assert_eq!(store.last_run("daily").await.expect("last"), None);
        let out = s.tick(&[job]).await.expect("tick");
        assert!(
            matches!(out[0].1, RunOutcome::Completed { attempts: 1, .. }),
            "{:?}",
            out[0].1
        );
    }

    #[tokio::test]
    async fn non_retryable_failure_stops_immediately() {
        let job = daily("UTC", 8, 0, utc(2026, 5, 1, 0, 0));
        let clock = FakeClock::at(utc(2026, 5, 1, 8, 0));
        let (store, handler) = (
            MemStore::default(),
            CountingHandler {
                fail_times: 9,
                retryable: false,
                ..Default::default()
            },
        );
        let out = scheduler(&clock, &store, &handler, "a")
            .tick(&[job])
            .await
            .expect("tick");
        assert!(matches!(out[0].1, RunOutcome::Failed { attempts: 1, .. }));
        assert!(clock.sleeps.lock().expect("lock").is_empty());
    }

    #[test]
    fn backoff_is_capped() {
        let b = Backoff {
            initial: Duration::from_secs(10),
            max: Duration::from_secs(60),
            max_attempts: 9,
        };
        assert_eq!(b.delay_after(1), Duration::from_secs(10));
        assert_eq!(b.delay_after(3), Duration::from_secs(40));
        assert_eq!(b.delay_after(4), Duration::from_secs(60));
        assert_eq!(b.delay_after(40), Duration::from_secs(60));
    }
}
