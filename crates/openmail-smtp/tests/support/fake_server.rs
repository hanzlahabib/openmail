//! A scriptable, in-process SMTP(S) server for tests. It binds to 127.0.0.1 only and
//! records everything it receives so tests can assert on what actually crossed the wire.
#![allow(dead_code)]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsKind {
    /// TLS from the first byte.
    Implicit,
    /// Plain greeting, STARTTLS offered.
    StartTls,
    /// No TLS at all (and no STARTTLS in EHLO).
    Plain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AfterData {
    Accept,
    Reject,
    /// Read the whole message, then never answer.
    Hang,
}

#[derive(Clone)]
pub struct Script {
    pub tls: TlsKind,
    pub auth: Option<(String, String)>,
    pub reject_rcpt: bool,
    pub after_data: AfterData,
}

impl Script {
    pub fn new(tls: TlsKind) -> Self {
        Self { tls, auth: Some(("me@example.com".into(), "s3cret".into())), reject_rcpt: false, after_data: AfterData::Accept }
    }
}

#[derive(Debug, Clone)]
pub struct Received {
    pub from: String,
    pub rcpts: Vec<String>,
    pub data: String,
}

#[derive(Default)]
pub struct State {
    pub connections: AtomicUsize,
    pub auth_attempts: AtomicUsize,
    pub auth_over_plaintext: AtomicBool,
    pub messages: std::sync::Mutex<Vec<Received>>,
    /// Fires when a full message body has been received (before the final reply).
    pub data_received: Notify,
}

impl State {
    pub fn message_count(&self) -> usize {
        self.messages.lock().map(|m| m.len()).unwrap_or(0)
    }
}

pub struct Server {
    pub port: u16,
    pub state: Arc<State>,
    pub root_pem: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start(script: Script) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let root_pem = ck.cert.pem().into_bytes();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let state = Arc::new(State::default());
    let st = Arc::clone(&state);
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            st.connections.fetch_add(1, Ordering::SeqCst);
            let (script, st, acceptor) = (script.clone(), Arc::clone(&st), acceptor.clone());
            tokio::spawn(async move { connection(tcp, script, st, acceptor).await });
        }
    });
    Server { port, state, root_pem, task }
}

enum Next<S> {
    Done,
    Upgrade(S),
}

async fn connection(tcp: TcpStream, script: Script, st: Arc<State>, acceptor: TlsAcceptor) {
    match script.tls {
        TlsKind::Implicit => {
            if let Ok(tls) = acceptor.accept(tcp).await {
                let _ = session(BufReader::new(tls), true, true, &script, &st).await;
            }
        }
        TlsKind::Plain => {
            let _ = session(BufReader::new(tcp), false, true, &script, &st).await;
        }
        TlsKind::StartTls => {
            if let Some(Next::Upgrade(tcp)) = session(BufReader::new(tcp), false, true, &script, &st).await
                && let Ok(tls) = acceptor.accept(tcp).await
            {
                let _ = session(BufReader::new(tls), true, false, &script, &st).await;
            }
        }
    }
}

async fn reply<S: AsyncRead + AsyncWrite + Unpin>(s: &mut BufReader<S>, text: &str) -> Option<()> {
    s.get_mut().write_all(text.as_bytes()).await.ok()?;
    s.get_mut().flush().await.ok()
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(mut s: BufReader<S>, secure: bool, greet: bool, script: &Script, st: &State) -> Option<Next<S>> {
    if greet {
        reply(&mut s, "220 localhost ready\r\n").await?;
    }
    let (mut from, mut rcpts) = (String::new(), Vec::new());
    let mut authed = script.auth.is_none();
    loop {
        let mut line = String::new();
        if s.read_line(&mut line).await.ok()? == 0 {
            return Some(Next::Done);
        }
        let cmd = line.trim_end().to_owned();
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let mut r = String::from("250-localhost\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-SIZE 52428800\r\n");
            if !secure && script.tls == TlsKind::StartTls {
                r.push_str("250-STARTTLS\r\n");
            }
            if script.auth.is_some() {
                r.push_str("250-AUTH PLAIN\r\n");
            }
            r.push_str("250 OK\r\n");
            reply(&mut s, &r).await?;
        } else if upper == "STARTTLS" {
            reply(&mut s, "220 go ahead\r\n").await?;
            return Some(Next::Upgrade(s.into_inner()));
        } else if upper.starts_with("AUTH PLAIN") {
            st.auth_attempts.fetch_add(1, Ordering::SeqCst);
            if !secure {
                st.auth_over_plaintext.store(true, Ordering::SeqCst);
            }
            let mut b64 = cmd[10..].trim().to_owned();
            if b64.is_empty() {
                reply(&mut s, "334 \r\n").await?;
                b64.clear();
                s.read_line(&mut b64).await.ok()?;
            }
            let decoded = STANDARD.decode(b64.trim()).unwrap_or_default();
            let parts: Vec<&[u8]> = decoded.split(|b| *b == 0).collect();
            let ok = matches!((&script.auth, parts.as_slice()), (Some((u, p)), [_, user, pass]) if user == &u.as_bytes() && pass == &p.as_bytes());
            if ok {
                authed = true;
                reply(&mut s, "235 2.7.0 ok\r\n").await?;
            } else {
                reply(&mut s, "535 5.7.8 bad credentials\r\n").await?;
            }
        } else if upper.starts_with("MAIL FROM") {
            if !authed {
                reply(&mut s, "530 5.7.0 auth required\r\n").await?;
                continue;
            }
            from = cmd[10..].split_whitespace().next().unwrap_or("").trim_matches(['<', '>']).to_owned();
            rcpts.clear();
            reply(&mut s, "250 ok\r\n").await?;
        } else if upper.starts_with("RCPT TO") {
            if script.reject_rcpt {
                reply(&mut s, "550 5.1.1 no such user\r\n").await?;
            } else {
                rcpts.push(cmd[8..].split_whitespace().next().unwrap_or("").trim_matches(['<', '>']).to_owned());
                reply(&mut s, "250 ok\r\n").await?;
            }
        } else if upper == "DATA" {
            reply(&mut s, "354 end with <CRLF>.<CRLF>\r\n").await?;
            let mut data = String::new();
            loop {
                let mut l = String::new();
                if s.read_line(&mut l).await.ok()? == 0 {
                    return Some(Next::Done);
                }
                if l == ".\r\n" {
                    break;
                }
                data.push_str(&l);
            }
            if let Ok(mut m) = st.messages.lock() {
                m.push(Received { from: from.clone(), rcpts: rcpts.clone(), data });
            }
            st.data_received.notify_waiters();
            match script.after_data {
                AfterData::Accept => reply(&mut s, "250 2.0.0 queued\r\n").await?,
                AfterData::Reject => reply(&mut s, "554 5.7.1 rejected\r\n").await?,
                AfterData::Hang => {
                    // Keep the socket open and silent until the client gives up.
                    let mut sink = [0u8; 64];
                    while s.read(&mut sink).await.ok()? > 0 {}
                    return Some(Next::Done);
                }
            }
        } else if upper == "QUIT" {
            reply(&mut s, "221 bye\r\n").await?;
            return Some(Next::Done);
        } else if upper == "RSET" || upper == "NOOP" {
            reply(&mut s, "250 ok\r\n").await?;
        } else {
            reply(&mut s, "500 unknown\r\n").await?;
        }
    }
}
