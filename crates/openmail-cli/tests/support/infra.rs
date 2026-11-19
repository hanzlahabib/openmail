//! Real-infrastructure fixtures: GreenMail in docker, a private test CA, and a TLS-terminating
//! proxy in front of GreenMail's plain IMAP port. Nothing here weakens the binary under test:
//! it verifies certificates normally and trusts the CA only through `SSL_CERT_FILE`.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const IMAGE: &str = "greenmail/standalone:2.1.3";
const GM_IMAP_PORT: u16 = 3143;
static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Greenmail {
    name: String,
    pub port: u16,
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

impl Greenmail {
    /// Starts a disposable server. Docker is mandatory for this suite: no silent skipping.
    pub fn start(users: &[(&str, &str)]) -> Self {
        let ok = Command::new("docker")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(
            ok,
            "docker is required for the e2e suite (OPENMAIL_REQUIRE_DOCKER=1) but is unavailable"
        );
        let name = format!(
            "openmail-e2e-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let list = users
            .iter()
            .map(|(u, p)| format!("{u}:{p}@localhost"))
            .collect::<Vec<_>>()
            .join(",");
        let opts = format!(
            "-Dgreenmail.setup.test.imap -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users={list}"
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
                "-e",
                &format!("GREENMAIL_OPTS={opts}"),
                IMAGE,
            ])
            .output()
            .expect("spawn docker");
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Built before the port is known so Drop removes the container on any later panic.
        let mut gm = Self {
            name: name.clone(),
            port: 0,
        };
        let mapped = Command::new("docker")
            .args(["port", &name, &format!("{GM_IMAP_PORT}/tcp")])
            .output()
            .expect("docker port");
        gm.port = String::from_utf8_lossy(&mapped.stdout)
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("mapped port");
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", gm.port)) {
                use std::io::Read;
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = [0u8; 8];
                if s.read(&mut buf)
                    .is_ok_and(|n| n > 0 && buf.starts_with(b"* OK"))
                {
                    return gm;
                }
            }
            assert!(Instant::now() < deadline, "GreenMail did not become ready");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Direct plain session, used only to seed mail.
    pub async fn admin(&self, user: &str, pass: &str) -> async_imap::Session<TcpStream> {
        let tcp = TcpStream::connect(("127.0.0.1", self.port))
            .await
            .expect("connect admin");
        let mut client = async_imap::Client::new(tcp);
        client
            .read_response()
            .await
            .expect("greeting io")
            .expect("greeting");
        client
            .login(user, pass)
            .await
            .map_err(|(e, _)| e)
            .expect("admin login")
    }

    pub async fn append(
        &self,
        user: &str,
        pass: &str,
        folder: &str,
        flags: Option<&str>,
        mail: &str,
    ) {
        let mut s = self.admin(user, pass).await;
        s.append(folder, flags, None, mail).await.expect("append");
        let _ = s.logout().await;
    }
}

/// Private test CA + a `localhost` leaf signed by it; the CA PEM is what `SSL_CERT_FILE` points at.
pub struct TestPki {
    pub ca_pem_path: PathBuf,
    acceptor: TlsAcceptor,
}

impl TestPki {
    pub fn generate(dir: &Path) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "OpenMail E2E Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_pem_path = dir.join("test-ca.pem");
        std::fs::write(&ca_pem_path, ca_cert.pem()).expect("write ca");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("leaf params")
            .signed_by(&leaf_key, &Issuer::new(ca_params, ca_key))
            .expect("leaf cert");
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .expect("server config");
        Self {
            ca_pem_path,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    /// TLS listener forwarding to `upstream_port`; returns the listening port.
    pub async fn proxy(&self, upstream_port: u16) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let acceptor = self.acceptor.clone();
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(client).await else {
                        return;
                    };
                    let Ok(up) = TcpStream::connect(("127.0.0.1", upstream_port)).await else {
                        return;
                    };
                    let (mut cr, mut cw) = tokio::io::split(tls);
                    let (mut ur, mut uw) = up.into_split();
                    let a = async { tokio::io::copy(&mut cr, &mut uw).await };
                    let b = async { tokio::io::copy(&mut ur, &mut cw).await };
                    let _ = tokio::select! { r = a => r, r = b => r };
                    let _ = cw.shutdown().await;
                });
            }
        });
        port
    }
}

pub fn eml(subject: &str, from: &str, to: &str, id: &str, body: &str) -> String {
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Mon, 01 Jan 2024 09:00:00 +0000\r\nMessage-ID: <{id}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
    )
}
