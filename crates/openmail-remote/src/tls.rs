//! In-process TLS termination (rustls, ring provider) as an axum [`Listener`].
//!
//! Handshakes run in their own task with a deadline, so a client that stalls
//! mid-handshake cannot block the accept loop (slowloris).

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ServerConfig, version};
use tokio_rustls::server::TlsStream;

/// A client that has not finished the TLS handshake after this long is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Completed handshakes waiting for the HTTP server to pick them up.
const ACCEPT_QUEUE: usize = 64;
/// Pause after a failed `accept` (typically fd exhaustion) so the loop cannot spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("reading {what}: {source}")]
    Read {
        what: &'static str,
        source: io::Error,
    },
    #[error("no certificate found in the certificate PEM")]
    NoCertificate,
    #[error("no private key found in the key PEM")]
    NoKey,
    #[error("invalid certificate/key pair: {0}")]
    Config(String),
}

/// Build a server config from PEM text. TLS 1.2 and 1.3 only; HTTP/1.1 ALPN
/// because the edge serves HTTP/1.1.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsError::NoCertificate)?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::NoKey)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Read a certificate chain and private key from PEM files.
pub fn server_config_from_files(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let read =
        |path: &Path, what| std::fs::read(path).map_err(|source| TlsError::Read { what, source });
    server_config(&read(cert, "TLS certificate")?, &read(key, "TLS key")?)
}

/// TLS-terminating listener; yields only completed handshakes.
#[derive(Debug)]
pub struct TlsListener {
    local: SocketAddr,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    accept_task: JoinHandle<()>,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, ready) = mpsc::channel(ACCEPT_QUEUE);
        let accept_task = tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "tcp accept failed");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        // A closed receiver means the server is shutting down.
                        Ok(Ok(tls)) => drop(tx.send((tls, peer)).await),
                        Ok(Err(e)) => tracing::debug!(error = %e, "tls handshake failed"),
                        Err(_) => tracing::debug!("tls handshake timed out"),
                    }
                });
            }
        });
        Ok(Self {
            local,
            ready,
            accept_task,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(pair) => pair,
            // The accept task only ends via Drop, so this is unreachable while
            // `self` is alive; park rather than busy-loop.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}
