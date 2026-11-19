//! SMTP session driver. We drive lettre's `AsyncSmtpConnection` command by command
//! (instead of its all-in-one `send`) because idempotency needs to know exactly
//! when the DATA phase begins: before it, any failure is a definite "not sent";
//! after it, anything short of a server verdict is `Uncertain`.
use std::time::Duration;

use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{
    AsyncSmtpConnection, Certificate, CertificateStore, TlsParameters,
};
use lettre::transport::smtp::commands::{Data, Mail, Rcpt};
use lettre::transport::smtp::extension::{ClientId, Extension, MailBodyParameter, MailParameter};
use openmail_core::backend::SecretSource;
use openmail_core::config::{AccountConfig, AuthMethod, ServerEndpoint, TlsMode};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use openmail_observe::metrics::Counter;
use openmail_observe::observer::Observer;
use secrecy::ExposeSecret;

use crate::approval::ApprovalProof;
use crate::builder::{
    BuiltMessage, address_domain, build_message, generate_message_id, validate_sender,
};
use crate::outbox::{Begin, NewAttempt, OutboxRecord, OutboxState, OutboxStore, Outcome};
use crate::request::{SendRequest, SmtpLimits};

/// How long a `Pending` record without DATA is considered possibly still running
/// elsewhere. Covers connect + auth + envelope phases at the maximum configurable
/// per-phase timeout (300 s) with margin.
const PENDING_LEASE: Duration = Duration::from_secs(15 * 60);
/// Best-effort QUIT must not delay the caller.
const QUIT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Default)]
pub struct SmtpOptions {
    /// Extra From addresses allowed besides the account address.
    pub aliases: Vec<String>,
    pub limits: SmtpLimits,
    /// PEM CA certificates trusted *in addition to* the built-in web roots (private
    /// CAs, test servers). Verification itself can never be disabled.
    pub extra_root_certs_pem: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// The server accepted the message in this call.
    Sent { message_id: String },
    /// The key was already accepted earlier; nothing was sent.
    AlreadyAccepted { message_id: String },
}

#[derive(Debug)]
pub struct SmtpClient<O, S> {
    outbox: O,
    secrets: S,
    options: SmtpOptions,
    observer: Observer,
}

fn coded(code: ErrorCode, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// Maps a lettre error that happened *before* any message data was written.
fn map_pre_data(e: &lettre::transport::smtp::Error, what: &str) -> Error {
    if e.is_tls() {
        return coded(
            ErrorCode::ConnectionFailed,
            format!("TLS failure during {what}"),
        );
    }
    if e.is_timeout() {
        return coded(ErrorCode::Timeout, format!("timed out during {what}"));
    }
    if let Some(code) = e.status() {
        return match what {
            "authentication" => coded(
                ErrorCode::AuthFailed,
                format!("authentication rejected by server (SMTP {code})"),
            ),
            "recipient" => coded(
                ErrorCode::InvalidInput,
                format!("recipient rejected by server (SMTP {code})"),
            ),
            _ => coded(
                ErrorCode::ConnectionFailed,
                format!("server refused {what} (SMTP {code})"),
            ),
        };
    }
    if what == "authentication" {
        return coded(
            ErrorCode::AuthFailed,
            "authentication could not be completed",
        );
    }
    coded(
        ErrorCode::ConnectionFailed,
        format!("connection failed during {what}"),
    )
}

fn timed_out(what: &str) -> Error {
    coded(ErrorCode::Timeout, format!("timed out during {what}"))
}

impl<O: OutboxStore, S: SecretSource> SmtpClient<O, S> {
    pub fn new(outbox: O, secrets: S, options: SmtpOptions) -> Self {
        Self {
            outbox,
            secrets,
            options,
            observer: Observer::noop(),
        }
    }

    /// Counts attempts, uncertain outcomes and auth failures per account id. Default: no-op.
    #[must_use]
    pub fn with_observer(mut self, observer: Observer) -> Self {
        self.observer = observer;
        self
    }

    pub fn outbox(&self) -> &O {
        &self.outbox
    }

    /// Operator recovery for `Uncertain` sends; see RECOVERY.md.
    pub async fn resolve_uncertain(
        &self,
        account: &AccountId,
        key: &str,
        outcome: Outcome,
        note: &str,
    ) -> Result<OutboxRecord> {
        let rec = self
            .outbox
            .resolve_uncertain(account, key, outcome, note)
            .await?;
        tracing::warn!(account = %account, key, ?outcome, "operator resolved uncertain send");
        Ok(rec)
    }

    pub async fn send(
        &self,
        account: &AccountConfig,
        request: SendRequest,
        proof: ApprovalProof,
    ) -> Result<SendOutcome> {
        let endpoint = account
            .smtp
            .as_ref()
            .ok_or_else(|| coded(ErrorCode::ConfigInvalid, "account has no SMTP section"))?;
        request.validate(&self.options.limits)?;
        validate_sender(&request.from, &account.email, &self.options.aliases)?;
        let hash = request.content_hash();
        if proof.account() != &account.id || proof.content_hash() != &hash {
            return Err(coded(
                ErrorCode::ApprovalInvalid,
                "approval does not match the content being sent",
            ));
        }

        let message_id = generate_message_id(&account.email)?;
        let built = build_message(&request, &message_id)?;
        let attempt = NewAttempt {
            account: account.id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            content_hash: hash.to_hex(),
            message_id,
            recipients: u32::try_from(request.recipient_count()).unwrap_or(u32::MAX),
            approval_token: proof.audit_ref().to_owned(),
        };
        let record = match self.outbox.begin(attempt, PENDING_LEASE).await? {
            Begin::Started(rec) => rec,
            Begin::Existing(rec) => return existing(&rec),
        };
        // A retried key keeps its original Message-ID so receivers can de-duplicate.
        let built = if record.message_id == built.message_id {
            built
        } else {
            build_message(&request, &record.message_id)?
        };

        // Counted once the outbox accepted the attempt: an idempotent replay is not an attempt.
        self.observer
            .incr_account(Counter::SmtpAttempts, account.id.as_str());
        let result = self.deliver(account, endpoint, &record, &built).await;
        match &result {
            Err(DeliveryError::Uncertain(_)) => self
                .observer
                .incr_account(Counter::SmtpUncertain, account.id.as_str()),
            Err(DeliveryError::NotSent(e)) if e.code() == ErrorCode::AuthFailed => self
                .observer
                .incr_account(Counter::AuthFailures, account.id.as_str()),
            _ => {}
        }
        let (state, detail) = match &result {
            Ok(()) => (OutboxState::Accepted, None),
            Err(DeliveryError::NotSent(e)) => (OutboxState::Rejected, Some(e.to_string())),
            Err(DeliveryError::Uncertain(e)) => (OutboxState::Uncertain, Some(e.to_string())),
        };
        if let Err(e) = self
            .outbox
            .finish(
                &account.id,
                &record.idempotency_key,
                state,
                detail.as_deref(),
            )
            .await
        {
            // Cannot persist the verdict: the safe reading of an unrecorded post-DATA attempt is Uncertain,
            // which startup recovery applies to any row left Pending with data_started.
            tracing::error!(account = %account.id, error = %e, "failed to record send outcome");
        }
        tracing::info!(account = %account.id, message_id = %record.message_id, recipients = record.recipients, outcome = state.as_str(), "smtp send finished");
        match result {
            Ok(()) => Ok(SendOutcome::Sent {
                message_id: record.message_id,
            }),
            Err(DeliveryError::NotSent(e)) => Err(e),
            Err(DeliveryError::Uncertain(e)) => Err(coded(
                ErrorCode::DeliveryUncertain,
                format!(
                    "delivery state unknown ({e}); the message may have been sent — check the Sent folder before retrying"
                ),
            )),
        }
    }

    async fn deliver(
        &self,
        account: &AccountConfig,
        endpoint: &ServerEndpoint,
        record: &OutboxRecord,
        built: &BuiltMessage,
    ) -> std::result::Result<(), DeliveryError> {
        let timeout = account.timeout();
        let mut conn = tokio::time::timeout(timeout, self.open_session(account, endpoint, timeout))
            .await
            .map_err(|_| DeliveryError::NotSent(timed_out("connect")))?
            .map_err(DeliveryError::NotSent)?;

        let envelope_result = tokio::time::timeout(timeout, send_envelope(&mut conn, built)).await;
        match envelope_result {
            Err(_) => {
                abort_quick(&mut conn).await;
                return Err(DeliveryError::NotSent(timed_out("envelope")));
            }
            Ok(Err(e)) => {
                abort_quick(&mut conn).await;
                return Err(DeliveryError::NotSent(e));
            }
            Ok(Ok(())) => {}
        }

        // Durable marker BEFORE DATA is issued: a crash from here on resolves to Uncertain.
        if let Err(e) = self
            .outbox
            .mark_data_started(&account.id, &record.idempotency_key)
            .await
        {
            abort_quick(&mut conn).await;
            return Err(DeliveryError::NotSent(e));
        }

        let data_result = tokio::time::timeout(timeout, send_data(&mut conn, &built.raw)).await;
        let outcome = match data_result {
            Err(_) => Err(DeliveryError::Uncertain(timed_out("message transfer"))),
            Ok(r) => r,
        };
        match &outcome {
            Ok(()) => {
                let _ = tokio::time::timeout(QUIT_TIMEOUT, conn.quit()).await;
            }
            Err(_) => abort_quick(&mut conn).await,
        }
        outcome
    }

    async fn open_session(
        &self,
        account: &AccountConfig,
        endpoint: &ServerEndpoint,
        timeout: Duration,
    ) -> Result<AsyncSmtpConnection> {
        let tls = self.tls_parameters(&endpoint.host)?;
        let domain = address_domain(&account.email)
            .unwrap_or("localhost")
            .to_owned();
        let hello = ClientId::Domain(domain);
        let addr = (endpoint.host.as_str(), endpoint.port);
        let mut conn = match endpoint.tls {
            TlsMode::Implicit => {
                AsyncSmtpConnection::connect_tokio1(addr, Some(timeout), &hello, Some(tls), None)
                    .await
                    .map_err(|e| map_pre_data(&e, "connect"))?
            }
            TlsMode::StartTls => {
                let mut c =
                    AsyncSmtpConnection::connect_tokio1(addr, Some(timeout), &hello, None, None)
                        .await
                        .map_err(|e| map_pre_data(&e, "connect"))?;
                if !c.can_starttls() {
                    abort_quick(&mut c).await;
                    return Err(coded(
                        ErrorCode::ConnectionFailed,
                        "server does not offer STARTTLS; refusing to continue unencrypted",
                    ));
                }
                if let Err(e) = c.starttls(tls, &hello).await {
                    abort_quick(&mut c).await;
                    return Err(map_pre_data(&e, "STARTTLS"));
                }
                c
            }
        };
        if !conn.is_encrypted() {
            abort_quick(&mut conn).await;
            return Err(coded(
                ErrorCode::ConnectionFailed,
                "connection is not encrypted; refusing to authenticate",
            ));
        }
        let secret = self.secrets.resolve(&account.credential)?;
        let creds = Credentials::new(
            account.login_name().to_owned(),
            secret.expose_secret().to_owned(),
        );
        let mechanisms: &[Mechanism] = match account.auth {
            AuthMethod::Password => &[Mechanism::Plain, Mechanism::Login],
            // The resolved secret must be a valid access token; refreshing is the caller's job.
            AuthMethod::Oauth2 => &[Mechanism::Xoauth2],
        };
        if let Err(e) = conn.auth(mechanisms, &creds).await {
            abort_quick(&mut conn).await;
            return Err(map_pre_data(&e, "authentication"));
        }
        Ok(conn)
    }

    fn tls_parameters(&self, host: &str) -> Result<TlsParameters> {
        let mut builder = TlsParameters::builder(host.to_owned())
            .certificate_store(CertificateStore::WebpkiRoots);
        for pem in &self.options.extra_root_certs_pem {
            let cert = Certificate::from_pem(pem).map_err(|_| {
                coded(
                    ErrorCode::ConfigInvalid,
                    "invalid extra root certificate PEM",
                )
            })?;
            builder = builder.add_root_certificate(cert);
        }
        builder
            .build_rustls()
            .map_err(|_| coded(ErrorCode::ConnectionFailed, "cannot initialise TLS"))
    }
}

/// lettre's `abort()` sends QUIT and waits for the reply with no timeout of its own; a
/// silent server would hang us forever, so bound it.
async fn abort_quick(conn: &mut AsyncSmtpConnection) {
    let _ = tokio::time::timeout(QUIT_TIMEOUT, conn.abort()).await;
}

enum DeliveryError {
    /// Definitely not delivered (failed before DATA, or the server refused).
    NotSent(Error),
    /// Past the point of no return without a server verdict.
    Uncertain(Error),
}

fn existing(rec: &OutboxRecord) -> Result<SendOutcome> {
    match rec.state {
        OutboxState::Accepted => Ok(SendOutcome::AlreadyAccepted {
            message_id: rec.message_id.clone(),
        }),
        OutboxState::Uncertain => Err(coded(
            ErrorCode::DeliveryUncertain,
            "an earlier attempt with this idempotency key has unknown delivery state; not re-sending (see RECOVERY.md)",
        )),
        OutboxState::Pending => Err(coded(
            ErrorCode::InvalidInput,
            "a send with this idempotency key is already in progress",
        )),
        OutboxState::Rejected => Err(coded(
            ErrorCode::Internal,
            "rejected record returned as existing",
        )),
    }
}

async fn send_envelope(conn: &mut AsyncSmtpConnection, built: &BuiltMessage) -> Result<()> {
    let mut params = Vec::new();
    // Domains are punycoded in the builder, so only local parts can still be non-ASCII.
    if built
        .envelope
        .from()
        .into_iter()
        .chain(built.envelope.to())
        .any(|a| !a.user().is_ascii())
    {
        if !conn.server_info().supports_feature(Extension::SmtpUtfEight) {
            return Err(coded(
                ErrorCode::Unsupported,
                "an address needs SMTPUTF8 but the server does not support it",
            ));
        }
        params.push(MailParameter::SmtpUtfEight);
    }
    if !built.raw.is_ascii() {
        if !conn.server_info().supports_feature(Extension::EightBitMime) {
            return Err(coded(
                ErrorCode::Unsupported,
                "message needs 8BITMIME but the server does not support it",
            ));
        }
        params.push(MailParameter::Body(MailBodyParameter::EightBitMime));
    }
    conn.command(Mail::new(built.envelope.from().cloned(), params))
        .await
        .map_err(|e| map_pre_data(&e, "sender"))?;
    // All-or-nothing: a partially delivered message is worse than a clear failure.
    for rcpt in built.envelope.to() {
        conn.command(Rcpt::new(rcpt.clone(), vec![]))
            .await
            .map_err(|e| map_pre_data(&e, "recipient"))?;
    }
    Ok(())
}

async fn send_data(
    conn: &mut AsyncSmtpConnection,
    raw: &[u8],
) -> std::result::Result<(), DeliveryError> {
    let verdict = |e: lettre::transport::smtp::Error| {
        let err = coded(
            ErrorCode::ConnectionFailed,
            format!(
                "server refused message{}",
                e.status()
                    .map(|c| format!(" (SMTP {c})"))
                    .unwrap_or_default()
            ),
        );
        if e.is_transient() || e.is_permanent() {
            DeliveryError::NotSent(err)
        } else {
            DeliveryError::Uncertain(err)
        }
    };
    let go_ahead = conn.command(Data).await.map_err(verdict)?;
    if !go_ahead.is_positive() {
        return Err(DeliveryError::NotSent(coded(
            ErrorCode::ConnectionFailed,
            "server did not accept DATA",
        )));
    }
    let done = conn.message(raw).await.map_err(verdict)?;
    if done.code().severity == lettre::transport::smtp::response::Severity::PositiveCompletion {
        Ok(())
    } else {
        Err(DeliveryError::Uncertain(coded(
            ErrorCode::ConnectionFailed,
            "unexpected reply to message content",
        )))
    }
}
