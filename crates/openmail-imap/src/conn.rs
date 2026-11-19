//! Opening and authenticating one IMAP session (implicit TLS or STARTTLS).
use std::fmt::Debug;

use async_imap::imap_proto::{Response, Status};
use async_imap::{Authenticator, Client, Session};
use openmail_core::config::{AccountConfig, AuthMethod, ServerEndpoint, TlsMode};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::error::{ImapError, ImapResult};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> Io for T {}
pub type BoxedIo = Box<dyn Io>;
pub type ImapSession = Session<BoxedIo>;

struct XOAuth2 {
    payload: String,
    sent: bool,
}

impl Authenticator for XOAuth2 {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> String {
        // Second round is the server's JSON error challenge; an empty reply ends it.
        if std::mem::replace(&mut self.sent, true) { String::new() } else { self.payload.clone() }
    }
}

async fn tcp(ep: &ServerEndpoint) -> ImapResult<TcpStream> {
    let s = TcpStream::connect((ep.host.as_str(), ep.port))
        .await
        .map_err(|e| ImapError::Connection(format!("cannot reach {}:{}: {}", ep.host, ep.port, e.kind())))?;
    // Interactive request/response protocol: avoid Nagle delays.
    s.set_nodelay(true).map_err(|e| ImapError::Connection(e.to_string()))?;
    Ok(s)
}

async fn handshake<T: Io + 'static>(
    stream: T,
    tls: &TlsConnector,
    ep: &ServerEndpoint,
) -> ImapResult<BoxedIo> {
    let name = ServerName::try_from(ep.host.clone()).map_err(|_| ImapError::Connection("invalid server host name".into()))?;
    let s = tls.connect(name, stream).await.map_err(|e| ImapError::Connection(format!("TLS handshake failed: {e}")))?;
    Ok(Box::new(s))
}

async fn expect_greeting<T: Io + 'static>(client: &mut Client<T>) -> ImapResult<()> {
    let greeting = client.read_response().await.map_err(|e| ImapError::Connection(e.to_string()))?;
    let Some(greeting) = greeting else { return Err(ImapError::Connection("server closed the connection".into())) };
    match greeting.parsed() {
        Response::Data { status: Status::Ok | Status::PreAuth, .. } => Ok(()),
        _ => Err(ImapError::Connection("server refused the connection".into())),
    }
}

/// Connects, secures the channel and authenticates. Auth rejection -> `ImapError::Auth`.
pub async fn open(cfg: &AccountConfig, secret: &SecretString, tls: &TlsConnector) -> ImapResult<ImapSession> {
    let ep = &cfg.imap;
    let client: Client<BoxedIo> = match ep.tls {
        TlsMode::Implicit => {
            let mut c = Client::new(handshake(tcp(ep).await?, tls, ep).await?);
            expect_greeting(&mut c).await?;
            c
        }
        TlsMode::StartTls => {
            let mut plain = Client::new(tcp(ep).await?);
            expect_greeting(&mut plain).await?;
            plain.run_command_and_check_ok("STARTTLS", None).await.map_err(|_| {
                ImapError::Connection("server refused STARTTLS; refusing to continue unencrypted".into())
            })?;
            // No new greeting follows a successful STARTTLS upgrade.
            Client::new(handshake(plain.into_inner(), tls, ep).await?)
        }
    };
    let user = cfg.login_name();
    let result = match cfg.auth {
        AuthMethod::Password => client.login(user, secret.expose_secret()).await,
        AuthMethod::Oauth2 => {
            let payload = format!("user={user}\x01auth=Bearer {}\x01\x01", secret.expose_secret());
            client.authenticate("XOAUTH2", XOAuth2 { payload, sent: false }).await
        }
    };
    result.map_err(|(e, _)| match e {
        async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => ImapError::Auth,
        other => other.into(),
    })
}
