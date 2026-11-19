//! `doctor`: diagnoses config, credentials and network reachability without ever
//! printing a secret value. Every check is data (`Check`) so rendering and the
//! decision logic are unit-testable with fakes.
// TODO(T12): remove once main.rs dispatches into this module.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cli::DoctorArgs;
use openmail_core::backend::SecretSource;
use openmail_core::config::{Config, CredentialRef, ServerEndpoint};
use openmail_core::{Error, ErrorCode};
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;

/// Endpoints probed at once. Small: doctor is a diagnostic, not a load test, and many
/// accounts often share one provider that may rate-limit parallel connects.
pub const PROBE_CONCURRENCY: usize = 6;
/// Per-probe ceiling when the account's own `timeout_secs` is not known yet (DNS+TCP only).
pub const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Group/other access bits that make a config file readable by other local users.
const GROUP_OTHER_BITS: u32 = 0o077;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub message: String,
    /// What the user should do next; present for Warn/Fail.
    pub hint: Option<String>,
}

impl Check {
    fn ok(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Ok,
            message: message.into(),
            hint: None,
        }
    }
    fn warn(name: impl Into<String>, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
    fn fail(name: impl Into<String>, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
}

pub fn has_failures(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.status == Status::Fail)
}

pub fn render(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let tag = match c.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        };
        let _ = writeln!(out, "[{tag}] {}: {}", c.name, c.message);
        if let Some(h) = &c.hint {
            let _ = writeln!(out, "       -> {h}");
        }
    }
    let (w, f) = (
        checks.iter().filter(|c| c.status == Status::Warn).count(),
        checks.iter().filter(|c| c.status == Status::Fail).count(),
    );
    let _ = writeln!(
        out,
        "{} checks, {w} warning(s), {f} failure(s)",
        checks.len()
    );
    out
}

// ---- config file ---------------------------------------------------------

/// What was observed about the config file; separate from reading so tests need no disk.
#[derive(Debug)]
pub struct ConfigFile {
    pub path: String,
    /// Unix permission bits, `None` on platforms without them.
    pub mode: Option<u32>,
    pub text: Result<String, io::ErrorKind>,
}

pub fn read_config_file(path: &Path) -> ConfigFile {
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let mode = None;
    ConfigFile {
        path: path.display().to_string(),
        mode,
        text: std::fs::read_to_string(path).map_err(|e| e.kind()),
    }
}

/// Returns the parsed config (when valid) plus the checks about it.
pub fn check_config(file: &ConfigFile) -> (Option<Config>, Vec<Check>) {
    let mut checks = Vec::new();
    let text = match &file.text {
        Ok(t) => t,
        Err(io::ErrorKind::NotFound) => {
            checks.push(Check::fail(
                "config",
                format!("no config file at {}", file.path),
                "run `openmail-mcp init` or pass --config <path>",
            ));
            return (None, checks);
        }
        Err(kind) => {
            checks.push(Check::fail(
                "config",
                format!("cannot read {} ({kind})", file.path),
                "check the path and file permissions",
            ));
            return (None, checks);
        }
    };
    checks.push(Check::ok("config", format!("found {}", file.path)));
    if let Some(mode) = file.mode {
        if mode & GROUP_OTHER_BITS != 0 {
            checks.push(Check::warn(
                "config permissions",
                format!("mode {mode:03o} is readable by other users"),
                format!("run `chmod 600 {}`", file.path),
            ));
        } else {
            checks.push(Check::ok("config permissions", format!("mode {mode:03o}")));
        }
    }
    match Config::from_toml(text) {
        Ok(cfg) => {
            checks.push(Check::ok(
                "config valid",
                format!("{} account(s)", cfg.accounts.len()),
            ));
            (Some(cfg), checks)
        }
        Err(e) => {
            checks.push(Check::fail(
                "config valid",
                e.to_string(),
                "fix the reported key; unknown keys and inline secrets are rejected",
            ));
            (None, checks)
        }
    }
}

// ---- credentials ---------------------------------------------------------

/// Verifies each account's credential resolves. The value is dropped immediately and
/// never formatted; only the reference location and an error code are reported.
pub fn check_credentials<S: SecretSource>(cfg: &Config, secrets: &S) -> Vec<Check> {
    cfg.accounts
        .iter()
        .map(|a| {
            let name = format!("credential [{}]", a.id);
            match (secrets.resolve(&a.credential), &a.credential) {
                (Ok(_), CredentialRef::Env { var }) => {
                    Check::ok(name, format!("env var {var} is set"))
                }
                (Ok(_), CredentialRef::Keyring { service, user }) => {
                    Check::ok(name, format!("keyring entry {service}/{user} readable"))
                }
                (Err(e), CredentialRef::Env { var }) => Check::fail(
                    name,
                    format!("env var {var} unavailable ({:?})", e.code()),
                    format!("export {var} in the environment that launches openmail-mcp"),
                ),
                (Err(e), CredentialRef::Keyring { service, user }) => Check::fail(
                    name,
                    format!(
                        "keyring entry {service}/{user} unavailable ({:?})",
                        e.code()
                    ),
                    "check the OS keyring service is running and the entry exists",
                ),
            }
        })
        .collect()
}

// ---- reachability --------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Reachable { addrs: usize, millis: u128 },
    DnsFailed,
    ConnectFailed,
    TimedOut,
}

/// DNS + TCP reachability. Abstracted so tests never touch the network.
pub trait Prober: Send + Sync {
    fn probe(
        &self,
        endpoint: &ServerEndpoint,
        timeout: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send;
}

/// TODO(owner: T10 follow-up): add a TLS handshake probe once a shared rustls
/// dependency is approved; today only DNS and TCP are verified.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetProber;

impl Prober for NetProber {
    async fn probe(&self, endpoint: &ServerEndpoint, timeout: Duration) -> ProbeOutcome {
        let started = Instant::now();
        let target = (endpoint.host.as_str(), endpoint.port);
        let attempt = async {
            let addrs: Vec<SocketAddr> = match lookup_host(target).await {
                Ok(it) => it.collect(),
                Err(_) => return ProbeOutcome::DnsFailed,
            };
            let Some(first) = addrs.first() else {
                return ProbeOutcome::DnsFailed;
            };
            match TcpStream::connect(first).await {
                Ok(_) => ProbeOutcome::Reachable {
                    addrs: addrs.len(),
                    millis: started.elapsed().as_millis(),
                },
                Err(_) => ProbeOutcome::ConnectFailed,
            }
        };
        tokio::time::timeout(timeout, attempt)
            .await
            .unwrap_or(ProbeOutcome::TimedOut)
    }
}

fn probe_check(label: &str, ep: &ServerEndpoint, outcome: &ProbeOutcome) -> Check {
    let name = format!("network {label}");
    let at = format!("{}:{}", ep.host, ep.port);
    match outcome {
        ProbeOutcome::Reachable { addrs, millis } => Check::ok(
            name,
            format!("{at} reachable ({addrs} address(es), {millis} ms)"),
        ),
        ProbeOutcome::DnsFailed => Check::fail(
            name,
            format!("cannot resolve {}", ep.host),
            "check the host name spelling and your DNS/network",
        ),
        ProbeOutcome::ConnectFailed => Check::fail(
            name,
            format!("TCP connect to {at} refused or blocked"),
            "check the port and any firewall/VPN",
        ),
        ProbeOutcome::TimedOut => Check::fail(
            name,
            format!("{at} timed out"),
            "check firewall rules; raise timeout_secs for slow links",
        ),
    }
}

/// Probes every account's IMAP (and SMTP) endpoint, at most `PROBE_CONCURRENCY` at a time.
/// Output order follows the config regardless of completion order.
pub async fn check_reachability<P>(cfg: &Config, prober: Arc<P>) -> Vec<Check>
where
    P: Prober + 'static,
{
    struct Job {
        label: String,
        endpoint: ServerEndpoint,
        timeout: Duration,
    }
    let jobs: Vec<Job> = cfg
        .accounts
        .iter()
        .flat_map(|a| {
            let timeout = a.timeout().min(MAX_PROBE_TIMEOUT);
            let imap = Job {
                label: format!("[{}] imap", a.id),
                endpoint: a.imap.clone(),
                timeout,
            };
            let smtp = a.smtp.clone().map(|endpoint| Job {
                label: format!("[{}] smtp", a.id),
                endpoint,
                timeout,
            });
            std::iter::once(imap).chain(smtp)
        })
        .collect();

    let mut results: Vec<Option<Check>> = vec![None; jobs.len()];
    let mut queue = jobs.into_iter().enumerate();
    let mut set: JoinSet<(usize, Check)> = JoinSet::new();
    loop {
        while set.len() < PROBE_CONCURRENCY {
            let Some((i, job)) = queue.next() else { break };
            let prober = Arc::clone(&prober);
            set.spawn(async move {
                let outcome = prober.probe(&job.endpoint, job.timeout).await;
                (i, probe_check(&job.label, &job.endpoint, &outcome))
            });
        }
        match set.join_next().await {
            None => break,
            Some(Ok((i, check))) => results[i] = Some(check),
            // A panicked probe leaves its slot empty; it is reported as a failed check below.
            Some(Err(_)) => {}
        }
    }
    results
        .into_iter()
        .map(|c| {
            c.unwrap_or_else(|| {
                Check::fail(
                    "network",
                    "a probe task failed unexpectedly",
                    "re-run doctor; report a bug if it persists",
                )
            })
        })
        .collect()
}

/// Full doctor run. Reachability is skipped when the config did not validate.
pub async fn run_checks<S, P>(file: &ConfigFile, secrets: &S, prober: Arc<P>) -> Vec<Check>
where
    S: SecretSource,
    P: Prober + 'static,
{
    let (cfg, mut checks) = check_config(file);
    if let Some(cfg) = cfg {
        checks.extend(check_credentials(&cfg, secrets));
        checks.extend(check_reachability(&cfg, prober).await);
    }
    checks
}

/// Resolves env credentials only. Keyring lookups need `openmail-security`, which is not
/// a dependency of this crate yet, so they report `Unsupported` and doctor shows a failure
/// with that code rather than claiming the keyring is fine.
#[derive(Debug, Clone, Copy)]
pub struct EnvSecrets;

impl SecretSource for EnvSecrets {
    fn resolve(&self, reference: &CredentialRef) -> openmail_core::Result<secrecy::SecretString> {
        match reference {
            CredentialRef::Env { var } => std::env::var(var)
                .ok()
                .filter(|v| !v.is_empty())
                .map(secrecy::SecretString::from)
                .ok_or_else(|| Error::new(ErrorCode::AuthFailed, "variable not set")),
            CredentialRef::Keyring { .. } => Err(Error::new(
                ErrorCode::Unsupported,
                "keyring access not wired into the CLI yet",
            )),
        }
    }
}

/// `doctor` entry point: prints the report, fails (non-zero exit) when any check failed.
pub fn run(args: DoctorArgs) -> anyhow::Result<()> {
    let file = read_config_file(&args.config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let checks = runtime.block_on(run_checks(&file, &EnvSecrets, Arc::new(NetProber)));
    // CLI output channel, not library logging.
    #[allow(clippy::print_stdout)]
    {
        print!("{}", render(&checks));
    }
    if has_failures(&checks) {
        anyhow::bail!("doctor found problems");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap is the idiom in tests
mod tests {
    use super::*;
    use openmail_core::Result;
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SECRET: &str = "canary-hunter2-secret";
    const CFG: &str = r#"
version = 1
[[account]]
id = "a"
display_name = "A"
email = "a@example.com"
auth = "password"
credential = { kind = "env", var = "OPENMAIL_A_PASSWORD" }
imap = { host = "imap.example.com", port = 993, tls = "implicit" }
smtp = { host = "smtp.example.com", port = 465, tls = "implicit" }
[[account]]
id = "b"
display_name = "B"
email = "b@example.com"
auth = "password"
credential = { kind = "keyring", service = "openmail", user = "b" }
imap = { host = "imap.bad.example", port = 993, tls = "implicit" }
"#;

    fn file(text: &str, mode: Option<u32>) -> ConfigFile {
        ConfigFile {
            path: "/cfg/openmail.toml".into(),
            mode,
            text: Ok(text.to_owned()),
        }
    }

    struct Secrets;
    impl SecretSource for Secrets {
        fn resolve(&self, r: &CredentialRef) -> Result<SecretString> {
            match r {
                CredentialRef::Env { .. } => Ok(SecretString::from(SECRET)),
                CredentialRef::Keyring { .. } => Err(Error::new(
                    ErrorCode::AuthFailed,
                    format!("backend said {SECRET}"),
                )),
            }
        }
    }

    #[derive(Default)]
    struct FakeProber {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }
    impl Prober for FakeProber {
        async fn probe(&self, ep: &ServerEndpoint, _: Duration) -> ProbeOutcome {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if ep.host.contains("bad") {
                ProbeOutcome::DnsFailed
            } else {
                ProbeOutcome::Reachable {
                    addrs: 1,
                    millis: 3,
                }
            }
        }
    }

    #[test]
    fn missing_config_is_actionable() {
        let f = ConfigFile {
            path: "/x.toml".into(),
            mode: None,
            text: Err(io::ErrorKind::NotFound),
        };
        let (cfg, checks) = check_config(&f);
        assert!(cfg.is_none() && has_failures(&checks));
        assert!(checks[0].hint.as_deref().unwrap().contains("init"));
    }

    #[test]
    fn loose_permissions_warn_and_strict_pass() {
        let (_, loose) = check_config(&file(CFG, Some(0o644)));
        assert!(
            loose
                .iter()
                .any(|c| c.status == Status::Warn
                    && c.hint.as_deref().unwrap().contains("chmod 600"))
        );
        let (cfg, strict) = check_config(&file(CFG, Some(0o600)));
        assert!(cfg.is_some() && strict.iter().all(|c| c.status == Status::Ok));
    }

    #[test]
    fn invalid_config_fails_and_skips_network() {
        let bad = CFG.replace(
            "auth = \"password\"",
            "auth = \"password\"\npassword = \"x\"",
        );
        let (cfg, checks) = check_config(&file(&bad, Some(0o600)));
        assert!(cfg.is_none() && has_failures(&checks));
    }

    #[tokio::test]
    async fn full_run_reports_each_dimension_and_never_leaks_secret() {
        let f = file(CFG, Some(0o600));
        let checks = run_checks(&f, &Secrets, Arc::new(FakeProber::default())).await;
        let out = render(&checks);
        assert!(out.contains("env var OPENMAIL_A_PASSWORD is set"));
        assert!(out.contains("keyring entry openmail/b unavailable"));
        assert!(
            out.contains("imap.example.com:993 reachable")
                && out.contains("smtp.example.com:465 reachable")
        );
        assert!(out.contains("cannot resolve imap.bad.example"));
        assert!(has_failures(&checks));
        assert!(
            !out.contains(SECRET),
            "secret leaked into doctor output:\n{out}"
        );
        assert!(!format!("{checks:?}").contains(SECRET));
    }

    #[tokio::test]
    async fn probes_are_bounded_and_ordered() {
        let mut text = String::from("version = 1\n");
        for i in 0..20 {
            text.push_str(&format!(
                "[[account]]\nid = \"x{i}\"\ndisplay_name = \"X\"\nemail = \"x{i}@example.com\"\nauth = \"password\"\n\
                 credential = {{ kind = \"env\", var = \"V{i}\" }}\nimap = {{ host = \"h{i}.example.com\", port = 993, tls = \"implicit\" }}\n"
            ));
        }
        let cfg = Config::from_toml(&text).unwrap();
        let prober = Arc::new(FakeProber::default());
        let checks = check_reachability(&cfg, Arc::clone(&prober)).await;
        assert_eq!(checks.len(), 20);
        assert!(
            checks
                .iter()
                .enumerate()
                .all(|(i, c)| c.message.contains(&format!("h{i}.example.com")))
        );
        let peak = prober.peak.load(Ordering::SeqCst);
        assert!(peak > 1 && peak <= PROBE_CONCURRENCY, "peak was {peak}");
    }

    #[tokio::test]
    async fn net_prober_reports_refused_port() {
        // Port 1 on loopback is closed everywhere we run; no external network involved.
        let ep = ServerEndpoint {
            host: "127.0.0.1".into(),
            port: 1,
            tls: openmail_core::config::TlsMode::Implicit,
        };
        let out = NetProber.probe(&ep, Duration::from_secs(2)).await;
        assert!(
            matches!(out, ProbeOutcome::ConnectFailed | ProbeOutcome::TimedOut),
            "{out:?}"
        );
    }
}
