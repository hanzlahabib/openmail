//! `brief now` and `brief schedule list`, plus the wiring `serve` reuses to give the MCP
//! server a brief engine and to run the opt-in scheduler.
//!
//! Optional settings live in `briefs.toml` next to the main config (see
//! `openmail_briefs::config`); state (processed-mail cursors, stored briefs, scheduler
//! leases, digest audit) lives in `briefs.db` and `briefs-outbox.db` in the state directory
//! (`$OPENMAIL_STATE_DIR`, else `$XDG_STATE_HOME/openmail-mcp`, else
//! `~/.local/state/openmail-mcp`), the directory `approvals.db` uses.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use openmail_briefs::ai::HttpSummarizer;
use openmail_briefs::classify::Classifier;
use openmail_briefs::config::{BriefsConfig, parse_lookback};
use openmail_briefs::delivery::{DigestSender, EmailDigestAdapter, render_markdown};
use openmail_briefs::digest::{NoDigest, SmtpDigestSender};
use openmail_briefs::engine::{
    AiStage, BriefAccount, BriefEngine, EngineSettings, GenerateRequest, SharedStore,
};
use openmail_briefs::present::deliverable;
use openmail_briefs::runner::{BriefJobHandler, compile_jobs, plans, run_forever, scheduler};
use openmail_briefs::scheduler::SchedulerStore;
use openmail_briefs::store::{BriefStore, SqliteSchedulerStore};
use openmail_core::config::{AccountConfig, Config};
use openmail_imap::ImapBackend;
use openmail_security::EnvKeyringSecretSource;
use openmail_smtp::{SmtpClient, SmtpOptions, SqliteOutbox};
use secrecy::SecretString;

use crate::cli::{BriefAction, BriefArgs, BriefFormat, BriefNowArgs, ScheduleAction};

const STATE_APP_DIR: &str = "openmail-mcp";
const BRIEFS_DB: &str = "briefs.db";
const OUTBOX_DB: &str = "briefs-outbox.db";

/// Where briefs read their optional settings and keep their state.
#[derive(Debug, Clone)]
pub struct BriefsPaths {
    /// The main config file; `briefs.toml` sits beside it.
    pub config: PathBuf,
    /// `None` when neither `$OPENMAIL_STATE_DIR`, an absolute `$XDG_STATE_HOME` nor `$HOME` is
    /// available. There is deliberately no relative fallback: a server started from an
    /// arbitrary working directory must not scatter a database there.
    pub state_dir: Option<PathBuf>,
}

impl BriefsPaths {
    pub fn from_process(config: PathBuf) -> Self {
        Self {
            config,
            state_dir: state_dir(),
        }
    }

    fn state_dir(&self) -> Result<&Path> {
        self.state_dir.as_deref().ok_or_else(|| {
            anyhow!(
                "cannot locate a state directory; set OPENMAIL_STATE_DIR (or HOME / XDG_STATE_HOME)"
            )
        })
    }
}

pub fn run(args: BriefArgs) -> Result<()> {
    let paths = BriefsPaths::from_process(args.config.clone());
    let config = load_config(&args.config)?;
    ensure_accounts(&config)?;
    let briefs = BriefsConfig::load(&BriefsConfig::path_next_to(&args.config))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?;
    match args.action {
        BriefAction::Now(now) => runtime.block_on(brief_now(&config, &briefs, &paths, &now)),
        BriefAction::Schedule {
            action: ScheduleAction::List,
        } => runtime.block_on(schedule_list(&briefs, &paths)),
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let config = Config::from_toml(&text)?;
    config.validate()?;
    Ok(config)
}

/// A brief over zero accounts is meaningless; say so rather than emit an empty one.
fn ensure_accounts(config: &Config) -> Result<()> {
    if config.accounts.is_empty() {
        bail!("no accounts configured; add one to the config before generating briefs");
    }
    Ok(())
}

/// Directory shared with `approvals.db`. Same precedence as the approvals command.
pub fn state_dir() -> Option<PathBuf> {
    state_dir_from(
        std::env::var_os("OPENMAIL_STATE_DIR").map(PathBuf::from),
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn state_dir_from(
    explicit: Option<PathBuf>,
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(dir) = explicit.filter(|p| !p.as_os_str().is_empty()) {
        return Some(dir);
    }
    // XDG: relative XDG_STATE_HOME values must be ignored.
    xdg.filter(|p| p.is_absolute())
        .or_else(|| {
            home.filter(|h| h.is_absolute())
                .map(|h| h.join(".local/state"))
        })
        .map(|base| base.join(STATE_APP_DIR))
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating state directory {}", dir.display()))
}

fn brief_accounts(config: &Config, wanted: &[String]) -> Result<Vec<BriefAccount>> {
    let to_brief = |a: &AccountConfig| BriefAccount {
        id: a.id.clone(),
        email: a.email.clone(),
        sent_folder: a.folders.sent.clone(),
    };
    if wanted.is_empty() {
        return Ok(config.accounts.iter().map(to_brief).collect());
    }
    wanted
        .iter()
        .map(|w| {
            config
                .accounts
                .iter()
                .find(|a| a.id.as_str() == w)
                .map(to_brief)
                .ok_or_else(|| anyhow!("unknown account `{w}`"))
        })
        .collect()
}

/// Everything `brief now` and `serve` share: engine, store handle and the state directory.
pub struct Wiring {
    pub engine: Arc<BriefEngine<ImapBackend>>,
    pub store: SharedStore,
    pub db_path: PathBuf,
}

/// Open the store and assemble the engine over `backend`.
pub fn wire(briefs: &BriefsConfig, backend: Arc<ImapBackend>, state_dir: &Path) -> Result<Wiring> {
    ensure_private_dir(state_dir)?;
    let db_path = state_dir.join(BRIEFS_DB);
    let store: SharedStore = Arc::new(Mutex::new(
        BriefStore::open(&db_path)
            .map_err(|e| anyhow!("{e}"))
            .with_context(|| format!("opening briefs database {}", db_path.display()))?,
    ));
    let classifier = Classifier::with_user_rules(briefs.rules.clone())
        .map_err(|e| anyhow!("briefs.rules: {e}"))?;
    let mut engine = BriefEngine::new(
        backend,
        Arc::clone(&store),
        EngineSettings::from_config(briefs),
        classifier,
    );
    if let Some(ai) = &briefs.ai {
        let key = std::env::var(&ai.api_key_env)
            .with_context(|| format!("[briefs.ai] needs the API key in ${}", ai.api_key_env))?;
        let summarizer = HttpSummarizer::new(
            ai.policy.clone(),
            &ai.endpoint,
            ai.model.clone(),
            SecretString::from(key),
        )
        .map_err(|e| anyhow!("[briefs.ai]: {e}"))?;
        engine = engine.with_ai(AiStage::new(summarizer, ai.policy.clone()));
    }
    Ok(Wiring {
        engine: Arc::new(engine),
        store,
        db_path,
    })
}

type OwnerSender = SmtpDigestSender<EnvKeyringSecretSource>;

/// The digest sender for `[briefs.digest]`, bound to that account's own address.
fn digest_sender(
    config: &Config,
    briefs: &BriefsConfig,
    store: &SharedStore,
    state_dir: &Path,
) -> Result<Option<(OwnerSender, String)>> {
    let Some(digest) = &briefs.digest else {
        return Ok(None);
    };
    let account = config
        .accounts
        .iter()
        .find(|a| a.id == digest.account)
        .ok_or_else(|| anyhow!("[briefs.digest] names unknown account `{}`", digest.account))?
        .clone();
    let outbox_path = state_dir.join(OUTBOX_DB);
    let outbox = SqliteOutbox::open(&outbox_path)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("opening {}", outbox_path.display()))?;
    let client = SmtpClient::new(
        outbox,
        EnvKeyringSecretSource::new(),
        SmtpOptions::default(),
    );
    let to = account.email.clone();
    let sender = SmtpDigestSender::new(client, account, Arc::clone(store))
        .map_err(|e| anyhow!("[briefs.digest]: {e}"))?;
    Ok(Some((sender, to)))
}

fn imap_backend(config: &Config) -> Result<Arc<ImapBackend>> {
    let secrets = Arc::new(EnvKeyringSecretSource::new());
    Ok(Arc::new(ImapBackend::new(
        config.accounts.clone(),
        config.limits.clone(),
        secrets,
    )?))
}

async fn brief_now(
    config: &Config,
    briefs: &BriefsConfig,
    paths: &BriefsPaths,
    args: &BriefNowArgs,
) -> Result<()> {
    let accounts = brief_accounts(config, &args.accounts)?;
    let lookback = match &args.lookback {
        Some(l) => parse_lookback(l),
        None => briefs.lookback(),
    }
    .map_err(|e| anyhow!("{e}"))?;
    let wiring = wire(briefs, imap_backend(config)?, paths.state_dir()?)?;
    // Built before generating so a digest misconfiguration fails before any mail is read.
    let digest = if args.email {
        Some(
            digest_sender(config, briefs, &wiring.store, paths.state_dir()?)?
                .ok_or_else(|| anyhow!("--email needs a [briefs.digest] account in briefs.toml"))?,
        )
    } else {
        None
    };

    let brief = wiring
        .engine
        .generate(&GenerateRequest {
            accounts,
            lookback,
            include_processed: args.include_processed,
        })
        .await
        .map_err(|e| anyhow!("{e}"))?;

    let id = format!("now@{}", brief.generated_at);
    let shown = deliverable(&brief, &id);
    let text = match args.format {
        BriefFormat::Md => render_markdown(&shown),
        BriefFormat::Json => serde_json::to_string_pretty(&brief)? + "\n",
    };
    std::io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .context("writing the brief")?;
    // Said on stderr so a piped `--format json` stays machine-readable.
    for (account, status) in &brief.accounts {
        if let openmail_briefs::model::AccountRunStatus::Failed { reason } = status {
            eprintln!("warning: account `{account}` could not be checked ({reason})");
        }
    }
    if let Some((sender, to)) = digest {
        let outcome = EmailDigestAdapter::new(sender)
            .deliver(&shown, &to)
            .await
            .map_err(|e| anyhow!("digest delivery failed: {e}"))?;
        eprintln!("digest to the owner of the digest account: {outcome:?}");
    }
    Ok(())
}

async fn schedule_list(briefs: &BriefsConfig, paths: &BriefsPaths) -> Result<()> {
    let mut out = String::new();
    if briefs.schedule.is_empty() {
        out.push_str("no schedules configured (add [[briefs.schedule]] to briefs.toml)\n");
    }
    let store = if briefs.schedule.is_empty() {
        None
    } else {
        let dir = paths.state_dir()?;
        ensure_private_dir(dir)?;
        Some(SqliteSchedulerStore::open(&dir.join(BRIEFS_DB)).map_err(|e| anyhow!("{e}"))?)
    };
    if let Some(store) = &store {
        let jobs = compile_jobs(briefs, store).map_err(|e| anyhow!("{e}"))?;
        for job in &jobs {
            let spec = job.spec();
            let next = job.next_fire_after(Utc::now());
            let last = store.last_run(&spec.id).await.map_err(|e| anyhow!("{e}"))?;
            let cfg = briefs.schedule.iter().find(|s| s.id == spec.id);
            let accounts = cfg.filter(|c| !c.accounts.is_empty()).map_or_else(
                || "all".to_owned(),
                |c| {
                    c.accounts
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                },
            );
            out.push_str(&format!(
                "{id}\t{state}\tcron `{cron}` {tz}\taccounts: {accounts}\tdigest: {digest}\tnext: {next}\tlast run: {last}\n",
                id = spec.id,
                state = if spec.enabled { "enabled" } else { "disabled" },
                cron = cfg.map_or("", |c| c.cron.as_str()),
                tz = spec.timezone,
                digest = cfg.is_some_and(|c| c.digest),
                next = next.map_or_else(|| "never".to_owned(), |t| t.to_rfc3339()),
                last = last.map_or_else(|| "never".to_owned(), |t| t.to_rfc3339()),
            ));
        }
    }
    std::io::stdout()
        .lock()
        .write_all(out.as_bytes())
        .context("writing the schedule list")
}

/// Give a server the brief tools and, when the owner enabled schedules, run them on this
/// process's runtime. Returns the scheduler task (abort it at shutdown).
///
/// A briefs database that cannot be opened degrades to "briefs unavailable" rather than
/// stopping the mail tools; a broken `briefs.toml` or digest setup is an error, because
/// silently skipping a schedule the owner asked for would hide the failure.
pub fn attach(
    server: openmail_mcp::OpenMailServer<ImapBackend>,
    config: &Config,
    paths: &BriefsPaths,
) -> Result<(
    openmail_mcp::OpenMailServer<ImapBackend>,
    Option<tokio::task::JoinHandle<()>>,
)> {
    let briefs = BriefsConfig::load(&BriefsConfig::path_next_to(&paths.config))?;
    let wiring = match paths
        .state_dir()
        .and_then(|dir| wire(&briefs, server.backend(), dir))
    {
        Ok(w) => w,
        Err(e) if !briefs.has_enabled_schedules() => {
            tracing::warn!(error = %format!("{e:#}"), "brief tools disabled: could not set up briefs");
            return Ok((server, None));
        }
        Err(e) => return Err(e),
    };
    let task = if briefs.has_enabled_schedules() {
        Some(spawn_scheduler(
            config,
            &briefs,
            &wiring,
            paths.state_dir()?,
        )?)
    } else {
        None
    };
    Ok((server.with_briefs(Arc::clone(&wiring.engine)), task))
}

fn spawn_scheduler(
    config: &Config,
    briefs: &BriefsConfig,
    wiring: &Wiring,
    state_dir: &Path,
) -> Result<tokio::task::JoinHandle<()>> {
    match digest_sender(config, briefs, &wiring.store, state_dir)? {
        Some(sender) => start(config, briefs, wiring, Some(sender)),
        None => start::<NoDigest>(config, briefs, wiring, None),
    }
}

fn start<D: DigestSender + Send + Sync + 'static>(
    config: &Config,
    briefs: &BriefsConfig,
    wiring: &Wiring,
    digest: Option<(D, String)>,
) -> Result<tokio::task::JoinHandle<()>> {
    let all = brief_accounts(config, &[])?;
    let plans: HashMap<_, _> = plans(briefs, &all).map_err(|e| anyhow!("{e}"))?;
    let store = SqliteSchedulerStore::open(&wiring.db_path).map_err(|e| anyhow!("{e}"))?;
    let jobs = compile_jobs(briefs, &store).map_err(|e| anyhow!("{e}"))?;
    let handler = BriefJobHandler::new(Arc::clone(&wiring.engine), plans, digest);
    // Unique per process so two `serve` instances compete for the lease instead of sharing it.
    let owner = format!(
        "pid{}-{}",
        std::process::id(),
        Utc::now().timestamp_micros()
    );
    tracing::info!(jobs = jobs.len(), "brief scheduler started");
    Ok(tokio::spawn(run_forever(
        scheduler(store, handler, owner),
        jobs,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_has_no_accounts() -> Result<()> {
        let config = Config::from_toml("version = 1\n")?;
        let text = match ensure_accounts(&config) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        };
        assert!(text.contains("no accounts"));
        Ok(())
    }

    #[test]
    fn missing_file_is_reported() {
        let text = match load_config(std::path::Path::new("/nonexistent/c.toml")) {
            Ok(_) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        assert!(text.contains("reading config"));
    }

    #[test]
    fn state_dir_precedence_matches_approvals() {
        assert_eq!(
            state_dir_from(Some("/s".into()), Some("/x".into()), Some("/h".into())),
            Some(PathBuf::from("/s"))
        );
        assert_eq!(
            state_dir_from(None, Some("/x".into()), Some("/h".into())),
            Some(PathBuf::from("/x/openmail-mcp"))
        );
        assert_eq!(
            state_dir_from(None, Some("rel".into()), Some("/h".into())),
            Some(PathBuf::from("/h/.local/state/openmail-mcp"))
        );
        // No usable base: no directory, never a relative one.
        assert_eq!(state_dir_from(None, Some("rel".into()), None), None);
        assert_eq!(state_dir_from(None, None, Some("home".into())), None);
    }

    const CFG: &str = r#"
version = 1
[[account]]
id = "a"
display_name = "A"
email = "a@example.com"
auth = "password"
credential = { kind = "env", var = "X" }
imap = { host = "i.example.com", port = 993, tls = "implicit" }
"#;

    #[test]
    fn unknown_account_flag_is_rejected_and_defaults_cover_every_account() -> Result<()> {
        let config = Config::from_toml(CFG)?;
        assert_eq!(brief_accounts(&config, &[])?.len(), 1);
        assert!(brief_accounts(&config, &["nope".into()]).is_err());
        assert_eq!(
            brief_accounts(&config, &["a".into()])?[0].email,
            "a@example.com"
        );
        Ok(())
    }
}
