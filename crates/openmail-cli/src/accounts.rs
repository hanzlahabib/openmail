//! `accounts list` and `accounts test`. Rendering is pure; the connectivity test
//! is generic over `MailBackend` so it runs against fakes in tests.

use std::fmt::Write as _;
use std::sync::Arc;

use crate::cli::{AccountsAction, AccountsArgs};
use anyhow::Context as _;
use openmail_core::backend::MailBackend;
use openmail_core::config::{AccountConfig, Config, CredentialRef};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use tokio::task::{JoinSet, LocalSet};

/// Accounts tested at once. Kept below the default global IMAP cap (8) so `accounts test`
/// on a large config never opens more sessions than the server layer would.
pub const TEST_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTest {
    pub account: AccountId,
    pub outcome: TestOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    Passed {
        capabilities: usize,
        smtp_ok: Option<bool>,
        detail: Option<String>,
    },
    Failed {
        imap_ok: bool,
        detail: String,
    },
}

impl AccountTest {
    pub fn passed(&self) -> bool {
        matches!(
            self.outcome,
            TestOutcome::Passed {
                smtp_ok: None | Some(true),
                ..
            }
        )
    }
}

fn credential_label(c: &CredentialRef) -> String {
    // Names a location, never a secret value.
    match c {
        CredentialRef::Env { var } => format!("env:{var}"),
        CredentialRef::Keyring { service, user } => format!("keyring:{service}/{user}"),
    }
}

fn mode_label(a: &AccountConfig) -> String {
    if a.read_only {
        return "read-only".to_owned();
    }
    let p = &a.permissions;
    let granted: Vec<&str> = [
        ("organize", p.organize),
        ("drafts", p.drafts),
        ("send", p.send),
        ("delete", p.delete),
    ]
    .into_iter()
    .filter_map(|(n, on)| on.then_some(n))
    .collect();
    if granted.is_empty() {
        "read-write (no grants)".to_owned()
    } else {
        granted.join("+")
    }
}

/// One line per account; never includes credential values.
pub fn render_list(cfg: &Config) -> String {
    if cfg.accounts.is_empty() {
        return "No accounts configured. Run `openmail-mcp init` to add one.\n".to_owned();
    }
    let mut out = String::new();
    for a in &cfg.accounts {
        let smtp = a
            .smtp
            .as_ref()
            .map_or_else(|| "-".to_owned(), |s| format!("{}:{}", s.host, s.port));
        let _ = writeln!(
            out,
            "{:<16} {:<28} imap={}:{} smtp={} mode={} cred={}",
            a.id,
            a.email,
            a.imap.host,
            a.imap.port,
            smtp,
            mode_label(a),
            credential_label(&a.credential),
        );
    }
    out
}

pub fn render_tests(results: &[AccountTest]) -> String {
    let mut out = String::new();
    for r in results {
        match &r.outcome {
            TestOutcome::Passed {
                capabilities,
                smtp_ok,
                detail,
            } => {
                let smtp = match smtp_ok {
                    Some(true) => " smtp=ok",
                    Some(false) => " smtp=FAILED",
                    None => "",
                };
                let _ = write!(
                    out,
                    "{:<16} {} imap=ok{smtp} capabilities={capabilities}",
                    r.account,
                    if r.passed() { "OK  " } else { "FAIL" }
                );
                if let Some(d) = detail {
                    let _ = write!(out, " ({d})");
                }
                out.push('\n');
            }
            TestOutcome::Failed { imap_ok, detail } => {
                let _ = writeln!(
                    out,
                    "{:<16} FAIL imap={} {detail}",
                    r.account,
                    if *imap_ok { "ok" } else { "FAILED" }
                );
            }
        }
    }
    out
}

fn select<'a>(cfg: &'a Config, only: Option<&AccountId>) -> Result<Vec<&'a AccountConfig>> {
    match only {
        Some(id) => Ok(vec![cfg.account(id)?]),
        None => Ok(cfg.accounts.iter().collect()),
    }
}

/// Runs `test_connection` for the selected accounts with at most `TEST_CONCURRENCY` in
/// flight. Results keep config order. Fails only for an unknown account filter.
pub async fn test_accounts<B>(
    backend: Arc<B>,
    cfg: &Config,
    only: Option<&AccountId>,
) -> Result<Vec<AccountTest>>
where
    B: MailBackend + 'static,
{
    let ids: Vec<AccountId> = select(cfg, only)?
        .into_iter()
        .map(|a| a.id.clone())
        .collect();
    // `MailBackend` futures are not `Send` (contract uses plain async fn in trait), so tasks
    // run on a LocalSet instead of being spawned onto the multi-thread scheduler.
    LocalSet::new().run_until(run_bounded(backend, ids)).await
}

async fn run_bounded<B>(backend: Arc<B>, ids: Vec<AccountId>) -> Result<Vec<AccountTest>>
where
    B: MailBackend + 'static,
{
    let mut results: Vec<Option<AccountTest>> = vec![None; ids.len()];
    let mut pending = ids.into_iter().enumerate();
    let mut set: JoinSet<(usize, AccountTest)> = JoinSet::new();
    loop {
        while set.len() < TEST_CONCURRENCY {
            let Some((i, id)) = pending.next() else { break };
            let backend = Arc::clone(&backend);
            set.spawn_local(async move {
                let outcome = match backend.test_connection(&id).await {
                    Ok(rep) if rep.imap_ok => TestOutcome::Passed {
                        capabilities: rep.capabilities.len(),
                        smtp_ok: rep.smtp_ok,
                        detail: rep.detail,
                    },
                    Ok(rep) => TestOutcome::Failed {
                        imap_ok: false,
                        detail: rep.detail.unwrap_or_else(|| "connection failed".to_owned()),
                    },
                    Err(e) => TestOutcome::Failed {
                        imap_ok: false,
                        detail: e.to_string(),
                    },
                };
                (
                    i,
                    AccountTest {
                        account: id,
                        outcome,
                    },
                )
            });
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        let (i, test) = joined.map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("account test task failed: {e}"),
            )
        })?;
        results[i] = Some(test);
    }
    Ok(results.into_iter().flatten().collect())
}

/// `accounts list|test` entry point. `test` opens a real IMAP (and SMTP, when configured)
/// session per account and exits non-zero if any account failed.
pub fn run(args: AccountsArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let cfg = Config::from_toml(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    match args.action {
        AccountsAction::List => {
            // CLI output channel, not library logging.
            #[allow(clippy::print_stdout)]
            {
                print!("{}", render_list(&cfg));
            }
            Ok(())
        }
        AccountsAction::Test { account } => {
            let only = account
                .as_deref()
                .map(AccountId::new)
                .transpose()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting async runtime")?;
            let secrets = Arc::new(openmail_security::EnvKeyringSecretSource::new());
            let backend = Arc::new(openmail_imap::ImapBackend::new(
                cfg.accounts.clone(),
                cfg.limits.clone(),
                secrets,
            )?);
            let results = runtime
                .block_on(test_accounts(backend, &cfg, only.as_ref()))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            #[allow(clippy::print_stdout)]
            {
                print!("{}", render_tests(&results));
            }
            if results.iter().all(AccountTest::passed) {
                Ok(())
            } else {
                anyhow::bail!("one or more accounts failed the connection test")
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap is the idiom in tests
mod tests {
    use super::*;
    use openmail_core::model::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SECRET: &str = "s3cret-canary-value";

    fn cfg(n: usize) -> Config {
        let mut t = String::from("version = 1\n");
        for i in 0..n {
            t.push_str(&format!(
                "[[account]]\nid = \"a{i}\"\ndisplay_name = \"A\"\nemail = \"a{i}@example.com\"\nauth = \"password\"\n\
                 credential = {{ kind = \"env\", var = \"OPENMAIL_A{i}_PASSWORD\" }}\n\
                 imap = {{ host = \"imap.example.com\", port = 993, tls = \"implicit\" }}\n"
            ));
        }
        Config::from_toml(&t).unwrap()
    }

    #[derive(Default)]
    struct Fake {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    impl MailBackend for Fake {
        async fn test_connection(&self, account: &AccountId) -> Result<ConnectionReport> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            match account.as_str() {
                "a1" => Err(Error::new(ErrorCode::AuthFailed, "login rejected")),
                "a2" => Ok(ConnectionReport {
                    account: account.clone(),
                    imap_ok: true,
                    smtp_ok: Some(false),
                    capabilities: vec!["IDLE".into()],
                    detail: None,
                }),
                _ => Ok(ConnectionReport {
                    account: account.clone(),
                    imap_ok: true,
                    smtp_ok: None,
                    capabilities: vec!["IDLE".into(), "UIDPLUS".into()],
                    detail: None,
                }),
            }
        }
        async fn list_folders(&self, _: &AccountId) -> Result<Vec<Folder>> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
        async fn folder_status(&self, _: &AccountId, _: &str) -> Result<FolderStatus> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
        async fn list_messages(
            &self,
            _: &AccountId,
            _: &str,
            _: PageRequest,
        ) -> Result<Page<MessageSummary>> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
        async fn search(
            &self,
            _: &AccountId,
            _: &SearchQuery,
            _: PageRequest,
        ) -> Result<Page<MessageSummary>> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
        async fn get_message(
            &self,
            _: &openmail_core::ids::MessageRef,
            _: usize,
        ) -> Result<Message> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
        async fn get_thread(
            &self,
            _: &openmail_core::ids::MessageRef,
        ) -> Result<Vec<MessageSummary>> {
            Err(Error::new(ErrorCode::Unsupported, "x"))
        }
    }

    #[test]
    fn list_shows_accounts_and_credential_location_only() {
        let out = render_list(&cfg(2));
        assert!(out.contains("a0@example.com") && out.contains("imap.example.com:993"));
        assert!(out.contains("read-only") && out.contains("env:OPENMAIL_A1_PASSWORD"));
        assert!(!out.contains(SECRET));
        assert!(render_list(&cfg(0)).contains("No accounts configured"));
    }

    #[tokio::test]
    async fn results_keep_order_and_classify_outcomes() {
        let res = test_accounts(Arc::new(Fake::default()), &cfg(3), None)
            .await
            .unwrap();
        let ids: Vec<&str> = res.iter().map(|r| r.account.as_str()).collect();
        assert_eq!(ids, ["a0", "a1", "a2"]);
        assert!(res[0].passed());
        assert!(!res[1].passed());
        assert!(!res[2].passed(), "smtp failure must fail the account");
        let out = render_tests(&res);
        assert!(
            out.contains("AuthFailed")
                && out.contains("smtp=FAILED")
                && out.contains("capabilities=2")
        );
        assert!(!out.contains(SECRET));
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let fake = Arc::new(Fake::default());
        let res = test_accounts(Arc::clone(&fake), &cfg(12), None)
            .await
            .unwrap();
        assert_eq!(res.len(), 12);
        let peak = fake.peak.load(Ordering::SeqCst);
        assert!(peak > 1 && peak <= TEST_CONCURRENCY, "peak was {peak}");
    }

    #[tokio::test]
    async fn unknown_account_filter_is_an_error() {
        let id = AccountId::new("nope").unwrap();
        let err = test_accounts(Arc::new(Fake::default()), &cfg(1), Some(&id))
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AccountNotFound);
    }
}
