//! `serve` glue: validates the requested transport and hands off to the
//! server crates through [`ServeBackend`]. Kept thin on purpose; the policy
//! decision in this module is refusing an unprotected http listener.

use std::net::SocketAddr;
use std::path::PathBuf;

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use openmail_core::config::Config;
use openmail_imap::ImapBackend;
use openmail_mcp::{build_server, serve_stdio};
use openmail_security::EnvKeyringSecretSource;

use crate::cli::{ServeArgs, Transport};

/// Env vars carrying the http transport's TLS and auth material. Paths only:
/// secrets are never accepted on the command line.
pub const ENV_TLS_CERT: &str = "OPENMAIL_HTTP_TLS_CERT";
pub const ENV_TLS_KEY: &str = "OPENMAIL_HTTP_TLS_KEY";
pub const ENV_AUTH_TOKEN_FILE: &str = "OPENMAIL_HTTP_AUTH_TOKEN_FILE";

/// TLS and auth inputs for the http transport, resolved from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpSecurity {
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub auth_token_file: Option<PathBuf>,
}

impl HttpSecurity {
    pub fn from_env() -> Self {
        let get = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self {
            tls_cert: get(ENV_TLS_CERT),
            tls_key: get(ENV_TLS_KEY),
            auth_token_file: get(ENV_AUTH_TOKEN_FILE),
        }
    }
}

/// Seam toward `openmail-mcp` (stdio) and `openmail-remote` (http). The real
/// adapters are wired once those crates expose their serve entry points.
pub trait ServeBackend {
    fn serve_stdio(&self, config: &Config) -> Result<()>;
    fn serve_http(&self, config: &Config, bind: SocketAddr, security: &HttpSecurity) -> Result<()>;
}

/// Refuse an http listener that lacks TLS or authentication. Exposing mail
/// over plaintext or unauthenticated HTTP is never acceptable, so there is no
/// override flag.
pub fn check_http_prerequisites(bind: &str, security: &HttpSecurity) -> Result<SocketAddr> {
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid --bind address `{bind}` (expected host:port)"))?;
    if security.tls_cert.is_none() || security.tls_key.is_none() {
        bail!("refusing --transport http without TLS: set {ENV_TLS_CERT} and {ENV_TLS_KEY}");
    }
    if security.auth_token_file.is_none() {
        bail!("refusing --transport http without authentication: set {ENV_AUTH_TOKEN_FILE}");
    }
    Ok(addr)
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C only on non-unix). Backends race
/// their serve loop against this so in-flight work can drain before exit.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the serve backends once openmail-mcp/remote are linked"
    )
)]
pub async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        let mut int = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received, shutting down"),
            _ = int.recv() => tracing::info!("SIGINT received, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("installing Ctrl-C handler")?;
        tracing::info!("Ctrl-C received, shutting down");
    }
    Ok(())
}

pub fn run(args: ServeArgs) -> Result<()> {
    run_with(args, &HttpSecurity::from_env(), &LiveBackend)
}

fn run_with(args: ServeArgs, security: &HttpSecurity, backend: &dyn ServeBackend) -> Result<()> {
    // Refuse before touching the config so a bad invocation fails fast.
    let http_addr = match args.transport {
        Transport::Stdio => None,
        Transport::Http => Some(check_http_prerequisites(&args.bind, security)?),
    };
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading config {}", args.config.display()))?;
    let config = Config::from_toml(&text)?;
    config.validate()?;
    match http_addr {
        None => backend.serve_stdio(&config),
        Some(addr) => backend.serve_http(&config, addr, security),
    }
}

/// Production wiring: real IMAP backend + OS/env secrets behind the MCP server.
struct LiveBackend;

impl ServeBackend for LiveBackend {
    fn serve_stdio(&self, config: &Config) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting async runtime")?;
        let secrets = Arc::new(EnvKeyringSecretSource::new());
        let backend = ImapBackend::new(config.accounts.clone(), config.limits.clone(), secrets)?;
        let server = build_server(Arc::new(config.clone()), backend);
        // stdout is the JSON-RPC channel; the library never prints to it.
        runtime
            .block_on(serve_stdio(server))
            .context("serving MCP over stdio")
    }

    fn serve_http(&self, _: &Config, _: SocketAddr, _: &HttpSecurity) -> Result<()> {
        // The hardened edge exists in openmail-remote but is not yet bridged to the MCP
        // service. Refusing is safer than serving without that bridge.
        bail!(
            "http transport is not wired yet: openmail-remote is not connected to the MCP service"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn full() -> HttpSecurity {
        HttpSecurity {
            tls_cert: Some("/c.pem".into()),
            tls_key: Some("/k.pem".into()),
            auth_token_file: Some("/t".into()),
        }
    }

    /// Error text of a result that must have failed.
    fn err_text<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => "unexpected success".to_owned(),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn http_without_tls_is_refused() {
        let sec = HttpSecurity {
            tls_cert: None,
            ..full()
        };
        assert!(err_text(check_http_prerequisites("127.0.0.1:8765", &sec)).contains("without TLS"));
        let sec = HttpSecurity {
            tls_key: None,
            ..full()
        };
        assert!(err_text(check_http_prerequisites("127.0.0.1:8765", &sec)).contains("without TLS"));
    }

    #[test]
    fn http_without_auth_is_refused() {
        let sec = HttpSecurity {
            auth_token_file: None,
            ..full()
        };
        assert!(
            err_text(check_http_prerequisites("127.0.0.1:8765", &sec)).contains("authentication")
        );
    }

    #[test]
    fn http_with_tls_and_auth_parses_bind() -> Result<()> {
        let addr = check_http_prerequisites("127.0.0.1:9000", &full())?;
        assert_eq!(addr.port(), 9000);
        assert!(err_text(check_http_prerequisites("nonsense", &full())).contains("invalid --bind"));
        Ok(())
    }

    struct Recorder(RefCell<Vec<&'static str>>);
    impl ServeBackend for Recorder {
        fn serve_stdio(&self, _: &Config) -> Result<()> {
            self.0.borrow_mut().push("stdio");
            Ok(())
        }
        fn serve_http(&self, _: &Config, _: SocketAddr, _: &HttpSecurity) -> Result<()> {
            self.0.borrow_mut().push("http");
            Ok(())
        }
    }

    fn args(transport: Transport, config: &str) -> ServeArgs {
        ServeArgs {
            config: config.into(),
            transport,
            bind: "127.0.0.1:8765".into(),
        }
    }

    #[test]
    fn refusal_happens_before_backend_is_called() {
        let rec = Recorder(RefCell::new(vec![]));
        let r = run_with(
            args(Transport::Http, "/nonexistent"),
            &HttpSecurity::default(),
            &rec,
        );
        assert!(err_text(r).contains("refusing"));
        assert!(rec.0.borrow().is_empty());
    }

    #[test]
    fn missing_config_is_reported() {
        let rec = Recorder(RefCell::new(vec![]));
        let r = run_with(
            args(Transport::Stdio, "/nonexistent/c.toml"),
            &HttpSecurity::default(),
            &rec,
        );
        assert!(err_text(r).contains("reading config"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_future_resolves_on_sigterm() -> Result<()> {
        let handle = tokio::spawn(shutdown_signal());
        // Let the task install its handlers before the signal is raised.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()?;
        assert!(status.success());
        tokio::time::timeout(std::time::Duration::from_secs(5), handle).await???;
        Ok(())
    }
}
