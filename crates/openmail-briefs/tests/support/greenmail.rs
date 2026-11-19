#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]
//! Test harness: disposable GreenMail IMAP server in docker, fronted by an in-process
//! TLS proxy (GreenMail's own certificate is not valid for the hostname, and the proxy
//! lets tests drop connections, count concurrency and hide capabilities).
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use openmail_core::backend::SecretSource;
use openmail_core::config::{
    AccountConfig, AuthMethod, CredentialRef, FolderMap, Permissions, ServerEndpoint, TlsMode,
};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const IMAGE: &str = "greenmail/standalone:2.1.3";
const GM_IMAP_PORT: u16 = 3143;
const GM_SMTP_PORT: u16 = 3025;
static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Greenmail {
    name: String,
    pub port: u16,
    pub smtp_port: u16,
}

impl Drop for Greenmail {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl Greenmail {
    /// `None` (with a loud message) when docker is unavailable, unless
    /// `OPENMAIL_REQUIRE_DOCKER=1`, in which case the test fails instead of skipping.
    pub fn start(users: &[(&str, &str)]) -> Option<Self> {
        if !docker_ok() {
            assert!(
                std::env::var("OPENMAIL_REQUIRE_DOCKER").is_err(),
                "docker required but unavailable"
            );
            eprintln!("SKIPPED: docker is unavailable; integration test did not run");
            return None;
        }
        let name = format!(
            "openmail-gm-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let user_list = users
            .iter()
            .map(|(u, p)| format!("{u}:{p}@localhost"))
            .collect::<Vec<_>>()
            .join(",");
        let opts = format!(
            "-Dgreenmail.setup.test.imap -Dgreenmail.setup.test.smtp -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users={user_list}"
        );
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "-p",
                &format!("127.0.0.1::{GM_IMAP_PORT}"),
                "-p",
                &format!("127.0.0.1::{GM_SMTP_PORT}"),
                "-e",
                &format!("GREENMAIL_OPTS={opts}"),
                IMAGE,
            ])
            .output()
            .expect("run docker");
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Constructed before the port is known so Drop removes the container on any later panic.
        let mut gm = Self {
            name: name.clone(),
            port: 0,
            smtp_port: 0,
        };
        let smtp_out = Command::new("docker")
            .args(["port", &name, &format!("{GM_SMTP_PORT}/tcp")])
            .output()
            .expect("docker port smtp");
        gm.smtp_port = String::from_utf8_lossy(&smtp_out.stdout)
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("parse mapped smtp port");
        let port_out = Command::new("docker")
            .args(["port", &name, &format!("{GM_IMAP_PORT}/tcp")])
            .output()
            .expect("docker port");
        let text = String::from_utf8_lossy(&port_out.stdout).into_owned();
        let port: u16 = text
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("parse mapped port");
        gm.port = port;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                use std::io::Read;
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = [0u8; 16];
                if s.read(&mut buf)
                    .is_ok_and(|n| n > 0 && buf.starts_with(b"* OK"))
                {
                    return Some(gm);
                }
            }
            assert!(Instant::now() < deadline, "GreenMail did not become ready");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Plain (non-TLS) direct session used only to seed mail and fixtures.
    pub async fn admin(&self, user: &str, pass: &str) -> async_imap::Session<TcpStream> {
        let tcp = TcpStream::connect(("127.0.0.1", self.port))
            .await
            .expect("connect admin");
        let mut client = async_imap::Client::new(tcp);
        client
            .read_response()
            .await
            .expect("greeting")
            .expect("greeting present");
        client
            .login(user, pass)
            .await
            .map_err(|(e, _)| e)
            .expect("admin login")
    }
}

#[derive(Default, Debug)]
pub struct Stats {
    pub active: AtomicUsize,
    pub peak: AtomicUsize,
    pub total: AtomicUsize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Implicit,
    StartTls,
}

pub struct TlsProxy {
    pub port: u16,
    pub cert: CertificateDer<'static>,
    pub stats: Arc<Stats>,
    kill: broadcast::Sender<()>,
}

impl TlsProxy {
    /// Drops every live connection, as a server restart or network cut would.
    pub fn kill_all(&self) {
        let _ = self.kill.send(());
    }

    pub async fn spawn(upstream_port: u16, mode: Mode, hide_move: bool) -> Self {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind proxy");
        let port = listener.local_addr().expect("addr").port();
        let stats = Arc::new(Stats::default());
        let (kill, _) = broadcast::channel(8);
        let (st, tx) = (stats.clone(), kill.clone());
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, st, mut rx) = (acceptor.clone(), st.clone(), tx.subscribe());
                tokio::spawn(async move {
                    st.total.fetch_add(1, Ordering::SeqCst);
                    let now = st.active.fetch_add(1, Ordering::SeqCst) + 1;
                    st.peak.fetch_max(now, Ordering::SeqCst);
                    tokio::select! {
                        _ = handle(client, upstream_port, mode, hide_move, acceptor) => {}
                        _ = rx.recv() => {}
                    }
                    st.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            port,
            cert,
            stats,
            kill,
        }
    }
}

async fn read_line(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b).await? == 0 {
            return Ok(line);
        }
        line.push(b[0]);
        if b[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn filter(chunk: &[u8], hide_move: bool) -> Vec<u8> {
    if hide_move && chunk.windows(12).any(|w| w == b"* CAPABILITY") {
        String::from_utf8_lossy(chunk)
            .replace(" MOVE", "")
            .into_bytes()
    } else {
        chunk.to_vec()
    }
}

async fn handle(
    mut client: TcpStream,
    upstream_port: u16,
    mode: Mode,
    hide_move: bool,
    acceptor: TlsAcceptor,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(("127.0.0.1", upstream_port)).await?;
    match mode {
        Mode::Implicit => {
            let tls = acceptor.accept(client).await?;
            pump(tls, upstream, hide_move).await
        }
        Mode::StartTls => {
            let greeting = read_line(&mut upstream).await?;
            client.write_all(&greeting).await?;
            loop {
                let line = read_line(&mut client).await?;
                if line.is_empty() {
                    return Ok(());
                }
                let text = String::from_utf8_lossy(&line).to_ascii_uppercase();
                if let Some(tag) = text
                    .split_whitespace()
                    .next()
                    .filter(|_| text.contains("STARTTLS"))
                {
                    client
                        .write_all(format!("{tag} OK Begin TLS negotiation now\r\n").as_bytes())
                        .await?;
                    break;
                }
                // Anything else before the upgrade is not expected from our client.
                client.write_all(b"* BAD STARTTLS required\r\n").await?;
            }
            let tls = acceptor.accept(client).await?;
            pump(tls, upstream, hide_move).await
        }
    }
}

async fn pump<C>(client: C, upstream: TcpStream, hide_move: bool) -> std::io::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();
    let up = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(());
            }
            uw.write_all(&buf[..n]).await?;
        }
    };
    let down = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(());
            }
            cw.write_all(&filter(&buf[..n], hide_move)).await?;
            cw.flush().await?;
        }
    };
    tokio::select! { r = up => r, r = down => r }
}

pub struct Secrets(pub HashMap<String, String>);

impl SecretSource for Secrets {
    fn resolve(&self, reference: &CredentialRef) -> openmail_core::Result<SecretString> {
        match reference {
            CredentialRef::Env { var } => self
                .0
                .get(var)
                .map(|v| SecretString::from(v.clone()))
                .ok_or_else(|| Error::new(ErrorCode::ConfigInvalid, "unknown test secret")),
            CredentialRef::Keyring { .. } => {
                Err(Error::new(ErrorCode::Unsupported, "no keyring in tests"))
            }
        }
    }
}

pub fn account(id: &str, user: &str, secret_var: &str, port: u16, tls: TlsMode) -> AccountConfig {
    AccountConfig {
        id: AccountId::new(id).expect("id"),
        display_name: id.to_owned(),
        email: format!("{user}@localhost"),
        imap: ServerEndpoint {
            host: "localhost".into(),
            port,
            tls,
        },
        smtp: None,
        auth: AuthMethod::Password,
        username: Some(user.to_owned()),
        credential: CredentialRef::Env {
            var: secret_var.to_owned(),
        },
        read_only: true,
        permissions: Permissions::default(),
        folders: FolderMap::default(),
        max_connections: 2,
        timeout_secs: 10,
    }
}

pub fn writable(mut cfg: AccountConfig) -> AccountConfig {
    cfg.read_only = false;
    cfg.permissions.organize = true;
    cfg
}

pub fn secrets(pairs: &[(&str, &str)]) -> Arc<Secrets> {
    Arc::new(Secrets(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    ))
}

#[allow(dead_code)]
pub fn eml_old(subject: &str, from: &str, id: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "From: {from}\r\nTo: alice@localhost\r\nSubject: {subject}\r\nDate: Mon, 01 Jan 2024 09:00:00 +0000\r\nMessage-ID: <{id}>\r\n{extra_headers}MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    )
}

pub const PDF_MAIL: &str = "From: bob@example.org\r\nTo: alice@localhost\r\nSubject: With attachment\r\nDate: Tue, 02 Jan 2024 09:00:00 +0000\r\nMessage-ID: <pdf-1@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"mx\"\r\n\r\n--mx\r\nContent-Type: text/plain\r\n\r\nsee file\r\n--mx\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--mx--\r\n";

/// A message dated now, so it falls inside any lookback window.
pub fn fresh_eml(subject: &str, from: &str, to: &str, id: &str, body: &str) -> String {
    let date = chrono::Utc::now().to_rfc2822();
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    )
}

impl Greenmail {
    pub async fn deliver(&self, user: &str, folder: &str, mail: &str) {
        let mut s = self.admin(user, "secret").await;
        s.append(folder, None, None, mail).await.expect("append");
        let _ = s.logout().await;
    }
}

/// A port nothing listens on: connecting fails immediately, like a server that is down.
pub fn dead_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}
