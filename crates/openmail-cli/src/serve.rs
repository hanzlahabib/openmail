//! `serve` glue: validates the requested transport and hands off to the
//! server crates through [`ServeBackend`]. Kept thin on purpose; the policy
//! decision in this module is refusing an unprotected http listener.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::http::{HeaderValue, header};
use axum::routing::get;
use openmail_core::config::Config;
use openmail_core::ids::AccountId;
use openmail_imap::ImapBackend;
use openmail_mcp::{RateLimits, build_server, build_server_with_resolver, serve_stdio};
use openmail_observe::metrics::Metrics;
use openmail_observe::observer::Observer;
use openmail_remote::auth::{
    AuthState, Authenticator, HttpsJwksFetcher, JwtConfig, JwtValidator, ProtectedResourceMetadata,
    StaticBearer,
};
use openmail_remote::http::{HttpConfig, RESOURCE_METADATA_PATH, Readiness, serve_tls};
use openmail_remote::mcp::{HttpPrincipalResolver, StreamableHttpServerConfig, mcp_router};
use openmail_remote::tls::server_config_from_files;
use openmail_security::{Action, EnvKeyringSecretSource};
use url::Url;

use crate::brief_cmd::{self, BriefsPaths};
use crate::cli::{ServeArgs, Transport};

/// Env vars carrying the http transport's TLS and auth material. Paths only:
/// secrets are never accepted on the command line.
pub const ENV_TLS_CERT: &str = "OPENMAIL_HTTP_TLS_CERT";
pub const ENV_TLS_KEY: &str = "OPENMAIL_HTTP_TLS_KEY";
pub const ENV_AUTH_TOKEN_FILE: &str = "OPENMAIL_HTTP_AUTH_TOKEN_FILE";
/// Comma list of actions (`read,organize,draft,send,delete`) the static bearer token grants.
/// Defaults to `read`; account permissions in the config still apply on top.
pub const ENV_STATIC_ACTIONS: &str = "OPENMAIL_HTTP_STATIC_ACTIONS";
/// JWT (OAuth resource server) mode: issuer, audience (this server's `/mcp` URL), JWKS URL and
/// the scope -> accounts mapping, e.g. `mail:work=work,shared;mail:home=home`.
pub const ENV_JWT_ISSUER: &str = "OPENMAIL_HTTP_JWT_ISSUER";
pub const ENV_JWT_AUDIENCE: &str = "OPENMAIL_HTTP_JWT_AUDIENCE";
pub const ENV_JWT_JWKS_URL: &str = "OPENMAIL_HTTP_JWT_JWKS_URL";
pub const ENV_JWT_SCOPE_ACCOUNTS: &str = "OPENMAIL_HTTP_JWT_SCOPE_ACCOUNTS";
/// Public base URL clients use (`https://mail.example.com`); its host joins the Host allowlist
/// and its well-known path is advertised in `WWW-Authenticate`.
pub const ENV_PUBLIC_URL: &str = "OPENMAIL_HTTP_PUBLIC_URL";
/// Extra comma-separated `Host` values and browser `Origin`s to accept.
pub const ENV_ALLOWED_HOSTS: &str = "OPENMAIL_HTTP_ALLOWED_HOSTS";
pub const ENV_ALLOWED_ORIGINS: &str = "OPENMAIL_HTTP_ALLOWED_ORIGINS";
/// Set to `1`/`true` to serve Prometheus metrics at `<mcp path>/metrics` (default off). The
/// route sits behind the same Origin check and bearer/JWT authentication as MCP itself.
pub const ENV_METRICS: &str = "OPENMAIL_HTTP_METRICS";
/// Route of the opt-in metrics endpoint, relative to the authenticated MCP mount.
pub const METRICS_ROUTE: &str = "/metrics";

/// JWT validation settings (all four are required together).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtSettings {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub scope_accounts: BTreeMap<String, Vec<String>>,
}

/// TLS and auth inputs for the http transport, resolved from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpSecurity {
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub auth_token_file: Option<PathBuf>,
    pub static_actions: Option<String>,
    pub jwt: Option<JwtSettings>,
    pub public_url: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    /// Expose `METRICS_ROUTE` (authenticated). Off unless the operator asks.
    pub metrics_enabled: bool,
}

/// `mail:work=work,shared;mail:home=home` -> scope => account ids.
pub fn parse_scope_accounts(raw: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let mut map = BTreeMap::new();
    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let (scope, accounts) = entry
            .split_once('=')
            .with_context(|| format!("scope mapping `{entry}` must look like scope=acct1,acct2"))?;
        let ids: Vec<String> = accounts
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_owned)
            .collect();
        if scope.trim().is_empty() || ids.is_empty() {
            bail!("scope mapping `{entry}` needs a scope and at least one account");
        }
        map.insert(scope.trim().to_owned(), ids);
    }
    Ok(map)
}

fn parse_actions(raw: &str) -> Result<Vec<Action>> {
    raw.split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(|a| match a {
            "read" => Ok(Action::Read),
            "organize" => Ok(Action::Organize),
            "draft" => Ok(Action::Draft),
            "send" => Ok(Action::Send),
            "delete" => Ok(Action::Delete),
            other => bail!("unknown action `{other}` in {ENV_STATIC_ACTIONS}"),
        })
        .collect()
}

fn split_list(raw: Option<String>) -> Vec<String> {
    raw.iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

impl HttpSecurity {
    pub fn from_env() -> Result<Self> {
        let text = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let path = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let jwt_parts = (
            text(ENV_JWT_ISSUER),
            text(ENV_JWT_AUDIENCE),
            text(ENV_JWT_JWKS_URL),
            text(ENV_JWT_SCOPE_ACCOUNTS),
        );
        let jwt = match jwt_parts {
            (None, None, None, None) => None,
            (Some(issuer), Some(audience), Some(jwks_url), Some(scopes)) => Some(JwtSettings {
                issuer,
                audience,
                jwks_url,
                scope_accounts: parse_scope_accounts(&scopes)?,
            }),
            _ => bail!(
                "JWT auth needs all of {ENV_JWT_ISSUER}, {ENV_JWT_AUDIENCE}, {ENV_JWT_JWKS_URL} and {ENV_JWT_SCOPE_ACCOUNTS}"
            ),
        };
        Ok(Self {
            tls_cert: path(ENV_TLS_CERT),
            tls_key: path(ENV_TLS_KEY),
            auth_token_file: path(ENV_AUTH_TOKEN_FILE),
            static_actions: text(ENV_STATIC_ACTIONS),
            jwt,
            public_url: text(ENV_PUBLIC_URL),
            allowed_hosts: split_list(text(ENV_ALLOWED_HOSTS)),
            allowed_origins: split_list(text(ENV_ALLOWED_ORIGINS)),
            metrics_enabled: text(ENV_METRICS)
                .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "True")),
        })
    }
}

/// Seam toward `openmail-mcp` (stdio) and `openmail-remote` (http).
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
    if security.auth_token_file.is_none() && security.jwt.is_none() {
        bail!(
            "refusing --transport http without authentication: set {ENV_AUTH_TOKEN_FILE} or the {ENV_JWT_ISSUER} family"
        );
    }
    if security.auth_token_file.is_some() && security.jwt.is_some() {
        bail!("configure exactly one of {ENV_AUTH_TOKEN_FILE} or JWT auth, not both");
    }
    Ok(addr)
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C only on non-unix). Backends race
/// their serve loop against this so in-flight work can drain before exit.
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
    let backend = LiveBackend {
        briefs: BriefsPaths::from_process(args.config.clone()),
    };
    run_with(args, &HttpSecurity::from_env()?, &backend)
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

/// Production wiring: real IMAP backend + OS/env secrets behind the MCP server. The config
/// path locates `briefs.toml`, which sits beside it.
struct LiveBackend {
    briefs: BriefsPaths,
}

impl ServeBackend for LiveBackend {
    fn serve_stdio(&self, config: &Config) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting async runtime")?;
        let secrets = Arc::new(EnvKeyringSecretSource::new());
        let backend = ImapBackend::new(config.accounts.clone(), config.limits.clone(), secrets)?;
        let metrics = Arc::new(Metrics::new());
        backend
            .pool()
            .set_observer(Observer::recording(Arc::clone(&metrics)));
        let server = build_server(Arc::new(config.clone()), backend)
            .with_observer(Observer::recording(Arc::clone(&metrics)));
        runtime.block_on(async {
            let (server, scheduler) = brief_cmd::attach(server, config, &self.briefs)?;
            // stdout is the JSON-RPC channel; the library never prints to it.
            let served = serve_stdio(server).await.context("serving MCP over stdio");
            if let Some(task) = scheduler {
                task.abort();
            }
            // stdio has no scrape endpoint, so leave one summary line for the operator. Counts
            // and account-id labels only.
            tracing::info!(metrics = %metrics.snapshot_json(), "serve stopped");
            served
        })
    }

    fn serve_http(&self, config: &Config, bind: SocketAddr, security: &HttpSecurity) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting async runtime")?;
        runtime.block_on(serve_https(config, &self.briefs, bind, security, async {
            if let Err(e) = shutdown_signal().await {
                tracing::error!(error = %e, "signal handler failed; shutting down");
            }
        }))
    }
}

/// Owner-only token file: refuse one that other local users can read.
fn read_token_file(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("reading token file {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "token file {} is accessible to other users (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            );
        }
    }
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("reading token file {}", path.display()))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("token file {} is empty", path.display());
    }
    Ok(token.to_owned())
}

/// The public base URL clients use; defaults to the bind address.
fn public_base(bind: SocketAddr, security: &HttpSecurity) -> Result<Url> {
    let raw = security
        .public_url
        .clone()
        .unwrap_or_else(|| format!("https://{bind}"));
    let url = Url::parse(&raw).with_context(|| format!("invalid {ENV_PUBLIC_URL} `{raw}`"))?;
    if url.scheme() != "https" {
        bail!("{ENV_PUBLIC_URL} must be an https URL");
    }
    Ok(url)
}

fn build_auth(
    config: &Config,
    security: &HttpSecurity,
    base: &Url,
) -> Result<(Arc<AuthState>, ProtectedResourceMetadata)> {
    let metadata_url = base
        .join(RESOURCE_METADATA_PATH)
        .context("building protected-resource metadata URL")?
        .to_string();
    let (authenticator, metadata): (Arc<dyn openmail_remote::auth::TokenAuthenticator>, _) =
        match (&security.jwt, &security.auth_token_file) {
            (Some(jwt), None) => {
                let cfg = JwtConfig::new(
                    &jwt.issuer,
                    &jwt.audience,
                    &jwt.jwks_url,
                    jwt.scope_accounts.clone(),
                )
                .context("invalid JWT settings")?;
                let scopes: Vec<&str> = jwt.scope_accounts.keys().map(String::as_str).collect();
                let metadata = ProtectedResourceMetadata::new(&jwt.audience, &jwt.issuer, &scopes);
                (
                    Arc::new(Authenticator::Jwt(JwtValidator::new(cfg, HttpsJwksFetcher))),
                    metadata,
                )
            }
            (None, Some(file)) => {
                let actions = parse_actions(security.static_actions.as_deref().unwrap_or("read"))?;
                let accounts: Vec<AccountId> =
                    config.accounts.iter().map(|a| a.id.clone()).collect();
                let bearer = StaticBearer::new(&read_token_file(file)?, actions, accounts);
                let resource = base.join("/mcp").context("building resource URI")?;
                let metadata = ProtectedResourceMetadata::static_bearer(resource.as_str());
                (
                    Arc::new(Authenticator::<HttpsJwksFetcher>::Static(bearer)),
                    metadata,
                )
            }
            _ => bail!("exactly one authentication mode must be configured"),
        };
    Ok((
        Arc::new(AuthState {
            authenticator,
            resource_metadata_url: metadata_url,
        }),
        metadata,
    ))
}

/// Host names the Streamable HTTP service accepts in the `Host` header (DNS-rebinding defence):
/// loopback, the bind address, the public URL's host and any configured extras.
fn allowed_hosts(bind: SocketAddr, base: &Url, extra: &[String]) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
        bind.ip().to_string(),
    ];
    if let Some(host) = base.host_str() {
        hosts.push(host.to_owned());
        if let Some(port) = base.port() {
            hosts.push(format!("{host}:{port}"));
        }
    }
    hosts.push(format!("{}:{}", bind.ip(), bind.port()));
    hosts.extend(extra.iter().cloned());
    hosts
}

/// Prometheus text for operators. Mounted inside the MCP router so the edge's Origin check and
/// authentication apply; never an MCP tool, so clients cannot read it through the protocol.
fn metrics_router(metrics: Arc<Metrics>) -> Router {
    Router::new().route(
        METRICS_ROUTE,
        get(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                (
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                    )],
                    metrics.render_prometheus(),
                )
            }
        }),
    )
}

async fn serve_https(
    config: &Config,
    briefs: &BriefsPaths,
    bind: SocketAddr,
    security: &HttpSecurity,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (Some(cert), Some(key)) = (&security.tls_cert, &security.tls_key) else {
        bail!("refusing --transport http without TLS");
    };
    let tls = server_config_from_files(cert, key).context("loading TLS material")?;
    let base = public_base(bind, security)?;
    let (auth, metadata) = build_auth(config, security, &base)?;

    let secrets = Arc::new(EnvKeyringSecretSource::new());
    let backend = ImapBackend::new(config.accounts.clone(), config.limits.clone(), secrets)?;
    let metrics = Arc::new(Metrics::new());
    backend
        .pool()
        .set_observer(Observer::recording(Arc::clone(&metrics)));
    // One server (and one shared backend/rate limiter); each MCP session gets a cheap clone
    // whose principal is resolved per request from the authenticated HTTP request.
    let server = build_server_with_resolver(
        Arc::new(config.clone()),
        backend,
        Arc::new(HttpPrincipalResolver),
        RateLimits::default(),
    )
    .with_observer(Observer::recording(Arc::clone(&metrics)));
    let (server, scheduler) = brief_cmd::attach(server, config, briefs)?;
    let mcp_config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts(
        bind,
        &base,
        &security.allowed_hosts,
    ));
    let cancel = mcp_config.cancellation_token.clone();
    let mut mcp = mcp_router(move || Ok(server.clone()), mcp_config);
    if security.metrics_enabled {
        mcp = mcp.merge(metrics_router(Arc::clone(&metrics)));
        tracing::info!("metrics endpoint enabled (authenticated)");
    }

    let mut http = HttpConfig::new(bind);
    http.auth = Some(auth);
    http.resource_metadata = Some(metadata);
    http.allowed_origins = security.allowed_origins.clone();

    tracing::info!(%bind, "serving MCP over https");
    let served = serve_tls(http, mcp, Readiness::default(), tls, async move {
        shutdown.await;
        // Ends open SSE streams so the graceful drain can finish.
        cancel.cancel();
    })
    .await
    .context("serving MCP over https");
    if let Some(task) = scheduler {
        task.abort();
    }
    served
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
            ..HttpSecurity::default()
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

    fn jwt() -> JwtSettings {
        JwtSettings {
            issuer: "https://idp.example".into(),
            audience: "https://mail.example/mcp".into(),
            jwks_url: "https://idp.example/jwks".into(),
            scope_accounts: BTreeMap::new(),
        }
    }

    #[test]
    fn jwt_alone_satisfies_auth_but_not_together_with_a_token_file() {
        let jwt_only = HttpSecurity {
            auth_token_file: None,
            jwt: Some(jwt()),
            ..full()
        };
        assert!(check_http_prerequisites("127.0.0.1:8765", &jwt_only).is_ok());
        let both = HttpSecurity {
            jwt: Some(jwt()),
            ..full()
        };
        assert!(
            err_text(check_http_prerequisites("127.0.0.1:8765", &both)).contains("exactly one")
        );
    }

    #[test]
    fn scope_mapping_parses_and_rejects_garbage() -> Result<()> {
        let m = parse_scope_accounts("mail:work=work, shared ; mail:home=home")?;
        assert_eq!(m["mail:work"], ["work", "shared"]);
        assert_eq!(m["mail:home"], ["home"]);
        assert!(parse_scope_accounts("no-equals").is_err());
        assert!(parse_scope_accounts("scope=").is_err());
        assert!(parse_scope_accounts("=acct").is_err());
        assert!(parse_actions("read,teleport").is_err());
        assert_eq!(parse_actions("read, draft")?, [Action::Read, Action::Draft]);
        Ok(())
    }

    #[test]
    fn host_allowlist_covers_public_host_and_extras_only() -> Result<()> {
        let base = Url::parse("https://mail.example.com:8443")?;
        let hosts = allowed_hosts("0.0.0.0:8765".parse()?, &base, &["alt.example".into()]);
        assert!(hosts.contains(&"mail.example.com".to_owned()));
        assert!(hosts.contains(&"mail.example.com:8443".to_owned()));
        assert!(hosts.contains(&"alt.example".to_owned()));
        assert!(!hosts.iter().any(|h| h == "evil.example"));
        assert!(
            public_base(
                "127.0.0.1:1".parse()?,
                &HttpSecurity {
                    public_url: Some("http://plain.example".into()),
                    ..HttpSecurity::default()
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn token_file_must_be_owner_only_and_non_empty() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("token");
        std::fs::write(&path, "s3cret\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(err_text(read_token_file(&path)).contains("chmod 600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(read_token_file(&path)?, "s3cret");
        std::fs::write(&path, "  \n")?;
        assert!(err_text(read_token_file(&path)).contains("empty"));
        Ok(())
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
    const HTTP_CONFIG: &str = r#"
version = 1
[[account]]
id = "work"
display_name = "Work"
email = "me@work.example"
auth = "password"
credential = { kind = "env", var = "OPENMAIL_T37_UNUSED" }
imap = { host = "127.0.0.1", port = 1, tls = "implicit" }
"#;

    /// The real `serve_https` wiring: TLS from files, static bearer from a token file, the real
    /// MCP service behind the edge, graceful stop.
    #[cfg(unix)]
    #[tokio::test]
    async fn serve_https_serves_mcp_behind_tls_and_bearer() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
        let cert_pem = cert.cert.pem();
        let (cert_path, key_path, token_path) = (
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
            dir.path().join("token"),
        );
        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
        std::fs::write(&token_path, "t37-static-token\n")?;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;

        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let bind: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let security = HttpSecurity {
            tls_cert: Some(cert_path),
            tls_key: Some(key_path),
            auth_token_file: Some(token_path),
            ..HttpSecurity::default()
        };
        let config = Config::from_toml(HTTP_CONFIG)?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let briefs = BriefsPaths {
            config: dir.path().join("config.toml"),
            state_dir: Some(dir.path().join("state")),
        };
        let server = tokio::spawn(async move {
            serve_https(&config, &briefs, bind, &security, async {
                let _ = stopped.await;
            })
            .await
        });

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes())?)
            .build()?;
        let url = |p: &str| format!("https://127.0.0.1:{port}{p}");
        let mut up = false;
        for _ in 0..100 {
            if client.get(url("/healthz")).send().await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(up, "server did not come up");

        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
        let post = |token: Option<&str>| {
            let mut r = client
                .post(url("/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(init);
            if let Some(t) = token {
                r = r.bearer_auth(t);
            }
            r
        };
        assert_eq!(post(None).send().await?.status(), 401);
        assert_eq!(post(Some("wrong")).send().await?.status(), 401);
        let ok = post(Some("t37-static-token")).send().await?;
        assert_eq!(ok.status(), 200);
        assert!(ok.headers().contains_key("mcp-session-id"));

        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(15), server).await???;
        Ok(())
    }

    /// `/mcp/metrics` is off by default and, once enabled, needs the same bearer as MCP.
    #[cfg(unix)]
    #[tokio::test]
    async fn metrics_endpoint_is_opt_in_and_authenticated() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
        let cert_pem = cert.cert.pem();
        let (cert_path, key_path, token_path) = (
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
            dir.path().join("token"),
        );
        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
        std::fs::write(&token_path, "t48-metrics-token\n")?;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes())?)
            .build()?;

        let mut statuses = Vec::new();
        for enabled in [false, true] {
            let port = std::net::TcpListener::bind("127.0.0.1:0")?
                .local_addr()?
                .port();
            let bind: SocketAddr = format!("127.0.0.1:{port}").parse()?;
            let security = HttpSecurity {
                tls_cert: Some(cert_path.clone()),
                tls_key: Some(key_path.clone()),
                auth_token_file: Some(token_path.clone()),
                metrics_enabled: enabled,
                ..HttpSecurity::default()
            };
            let config = Config::from_toml(HTTP_CONFIG)?;
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let briefs = BriefsPaths {
                config: dir.path().join("config.toml"),
                state_dir: Some(dir.path().join("state")),
            };
            let server = tokio::spawn(async move {
                serve_https(&config, &briefs, bind, &security, async {
                    let _ = stopped.await;
                })
                .await
            });
            let url = format!("https://127.0.0.1:{port}/mcp{METRICS_ROUTE}");
            let mut up = false;
            for _ in 0..100 {
                if client
                    .get(format!("https://127.0.0.1:{port}/healthz"))
                    .send()
                    .await
                    .is_ok()
                {
                    up = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(up, "server did not come up");
            let anon = client.get(&url).send().await?.status().as_u16();
            let authed = client
                .get(&url)
                .bearer_auth("t48-metrics-token")
                .send()
                .await?;
            let status = authed.status().as_u16();
            let body = authed.text().await?;
            statuses.push((anon, status, body));
            let _ = stop.send(());
            tokio::time::timeout(std::time::Duration::from_secs(15), server).await???;
        }
        let (anon_off, authed_off, _) = &statuses[0];
        assert_eq!(*anon_off, 401);
        assert_ne!(*authed_off, 200, "metrics must be off by default");
        let (anon_on, authed_on, body) = &statuses[1];
        assert_eq!(*anon_on, 401, "metrics must need the bearer");
        assert_eq!(*authed_on, 200);
        assert!(body.contains("openmail_auth_failures_total"), "{body}");
        Ok(())
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
