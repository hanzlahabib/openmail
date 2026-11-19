//! The SQLite scheduler state across real OS processes: one lease per job, a completed fire is
//! never repeated, and a process that dies holding the lease is recovered after the TTL.
//! The test binary re-executes itself as the "second process" (`CHILD_ENV` selects the role).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use chrono::{DateTime, Utc};
use openmail_briefs::runner::SystemSchedulerClock;
use openmail_briefs::scheduler::{
    Backoff, CompiledJob, JobHandler, JobSpec, MissedPolicy, RunFailure, RunOutcome, Schedule,
    Scheduler, SchedulerStore,
};
use openmail_briefs::store::SqliteSchedulerStore;

const CHILD_ENV: &str = "OPENMAIL_BRIEFS_TEST_CHILD";
const DB_ENV: &str = "OPENMAIL_BRIEFS_TEST_DB";
const LOG_ENV: &str = "OPENMAIL_BRIEFS_TEST_LOG";
const JOB: &str = "morning";

/// Appends one line per execution to a shared file, then lingers so overlapping ticks collide.
struct FileHandler {
    log: PathBuf,
    who: &'static str,
    work: Duration,
}

impl JobHandler for FileHandler {
    async fn run(&self, job_id: &str, scheduled_for: DateTime<Utc>) -> Result<(), RunFailure> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        writeln!(f, "{} {job_id} {}", self.who, scheduled_for.to_rfc3339()).unwrap();
        tokio::time::sleep(self.work).await;
        Ok(())
    }
}

fn job(store: &SqliteSchedulerStore) -> CompiledJob {
    // Registered two minutes ago with a daily fire time one minute ago: exactly one fire is due
    // now and the next is a day away, so a test that crosses a minute boundary cannot see a
    // second one.
    let created = Utc::now() - chrono::Duration::minutes(2);
    let fire = Utc::now() - chrono::Duration::minutes(1);
    let created = store.job_created_at(JOB, created).unwrap();
    CompiledJob::compile(JobSpec {
        id: JOB.into(),
        schedule: Schedule::Daily {
            hour: u8::try_from(chrono::Timelike::hour(&fire)).unwrap(),
            minute: u8::try_from(chrono::Timelike::minute(&fire)).unwrap(),
        },
        timezone: "UTC".into(),
        enabled: true,
        created_at: created,
        missed: MissedPolicy::SkipOlderThan(Duration::from_secs(3600)),
    })
    .unwrap()
}

fn scheduler<H: JobHandler>(
    db: &Path,
    handler: H,
    owner: &str,
    ttl: Duration,
) -> (
    Scheduler<SystemSchedulerClock, SqliteSchedulerStore, H>,
    CompiledJob,
) {
    let job = job(&SqliteSchedulerStore::open(db).unwrap());
    let s = Scheduler::new(
        SystemSchedulerClock,
        SqliteSchedulerStore::open(db).unwrap(),
        handler,
        owner,
        ttl,
        Backoff::default(),
    );
    (s, job)
}

/// Child role: tick once as its own process and report the outcome on stdout.
#[test]
#[allow(clippy::print_stdout)] // the parent process reads this line
fn child_process_tick() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let db = PathBuf::from(std::env::var(DB_ENV).unwrap());
    let log = PathBuf::from(std::env::var(LOG_ENV).unwrap());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (s, job) = scheduler(
        &db,
        FileHandler {
            log,
            who: "child",
            work: Duration::from_millis(100),
        },
        &format!("child-{}", std::process::id()),
        Duration::from_secs(60),
    );
    let out = rt.block_on(s.tick(std::slice::from_ref(&job))).unwrap();
    println!("CHILD-OUTCOME {:?}", out[0].1);
}

fn run_child(db: &Path, log: &Path) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_process_tick",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env(DB_ENV, db)
        .env(LOG_ENV, log)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.split_once("CHILD-OUTCOME ").map(|(_, o)| o.to_owned()))
        .expect("child reported an outcome")
}

fn executions(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_processes_run_one_fire_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (db, log) = (dir.path().join("briefs.db"), dir.path().join("runs.log"));
    let (parent, job) = scheduler(
        &db,
        FileHandler {
            log: log.clone(),
            who: "parent",
            // Long enough that a slow-starting child process (cold macOS runners) still finds the lease held.
            work: Duration::from_secs(8),
        },
        "parent",
        Duration::from_secs(60),
    );
    let running = tokio::spawn(async move { parent.tick(std::slice::from_ref(&job)).await });
    // Let the parent take the lease and start its (slow) run.
    for _ in 0..50 {
        if !executions(&log).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(executions(&log).len(), 1, "parent never started");

    let child_outcome = tokio::task::spawn_blocking({
        let (db, log) = (db.clone(), log.clone());
        move || run_child(&db, &log)
    })
    .await
    .unwrap();
    assert!(
        child_outcome.contains("LeaseHeld"),
        "child must not run: {child_outcome}"
    );

    let parent_out = running.await.unwrap().unwrap();
    assert!(
        matches!(parent_out[0].1, RunOutcome::Completed { .. }),
        "{parent_out:?}"
    );

    // After completion the same fire is done: a later process finds nothing due.
    let later = tokio::task::spawn_blocking({
        let (db, log) = (db.clone(), log.clone());
        move || run_child(&db, &log)
    })
    .await
    .unwrap();
    assert!(later.contains("NotDue"), "completed fire repeated: {later}");
    assert_eq!(executions(&log).len(), 1, "{:?}", executions(&log));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_that_dies_holding_the_lease_is_recovered_after_the_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let (db, log) = (dir.path().join("briefs.db"), dir.path().join("runs.log"));
    let store = SqliteSchedulerStore::open(&db).unwrap();
    // "Process A" takes the lease, then dies: no release, no completed-run record.
    assert!(
        store
            .try_acquire(JOB, "dead-process", Utc::now(), Duration::from_secs(2))
            .await
            .unwrap()
    );
    assert_eq!(store.last_run(JOB).await.unwrap(), None);

    let (b, job) = scheduler(
        &db,
        FileHandler {
            log: log.clone(),
            who: "b",
            work: Duration::ZERO,
        },
        "survivor",
        Duration::from_secs(60),
    );
    let jobs = std::slice::from_ref(&job);
    let blocked = b.tick(jobs).await.unwrap();
    assert_eq!(blocked[0].1, RunOutcome::LeaseHeld);
    assert!(executions(&log).is_empty());

    tokio::time::sleep(Duration::from_millis(2300)).await;
    let recovered = b.tick(jobs).await.unwrap();
    assert!(
        matches!(recovered[0].1, RunOutcome::Completed { .. }),
        "{recovered:?}"
    );
    assert_eq!(executions(&log).len(), 1);
    assert!(store.last_run(JOB).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn job_baseline_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("briefs.db");
    let first = SqliteSchedulerStore::open(&db)
        .unwrap()
        .job_created_at("j", Utc::now() - chrono::Duration::hours(5))
        .unwrap();
    // A restart presents a later "now"; the persisted creation time must win.
    let after = SqliteSchedulerStore::open(&db)
        .unwrap()
        .job_created_at("j", Utc::now())
        .unwrap();
    assert_eq!(first, after);
}
