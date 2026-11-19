//! TLS client configuration. Certificate and hostname verification are always on;
//! there is deliberately no "accept invalid certs" switch. Private CAs are supported
//! by adding trusted roots, never by disabling verification.
use std::sync::Arc;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::ring};

use crate::error::{ImapError, ImapResult};

/// Builds a connector trusting the OS store plus `extra_roots`. When the OS store
/// yields nothing (minimal containers) the bundled Mozilla roots are used instead.
pub fn connector(extra_roots: &[CertificateDer<'static>]) -> ImapResult<TlsConnector> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        if roots.add(cert).is_err() {
            tracing::debug!("skipped an unparsable OS root certificate");
        }
    }
    if roots.is_empty() {
        tracing::warn!("no usable OS root certificates; falling back to bundled Mozilla roots");
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for cert in extra_roots {
        roots
            .add(cert.clone())
            .map_err(|_| ImapError::Connection("invalid extra root certificate".into()))?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| ImapError::Connection("TLS protocol setup failed".into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
