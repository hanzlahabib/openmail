//! Digest email through `openmail-smtp`.
//!
//! This is a deliberate, narrow exception to "sending needs a human-granted approval": a
//! digest is the owner's own briefing delivered to the owner's own mailbox, so there is no
//! third party to protect from an agent-chosen send. The exception is enforced structurally,
//! not by policy text:
//! - [`SmtpDigestSender`] is bound to one account and takes no recipient from the caller; a
//!   `Digest` addressed to anything but that account's own address is refused;
//! - the `ApprovalProof` the SMTP client demands can only be minted by an `ApprovalConsumer`,
//!   and the one used here ([`OwnerOnlyConsumer`]) approves exactly one request shape: a single
//!   `To` that equals the owner's address, with the fixed digest subject prefix;
//! - the account must have SMTP configured and `permissions.send` granted (and not be
//!   read-only), so a read-only deployment never sends anything;
//! - every attempt is recorded in the shared store before any network I/O, at most
//!   [`MAX_DIGESTS_PER_DAY`] per account per day, one per brief id.
//!
//! Nothing here is reachable from an MCP tool; digests go out from `brief now --email` or a
//! configured schedule only.
use std::time::Duration;

use chrono::Utc;
use openmail_core::backend::SecretSource;
use openmail_core::config::AccountConfig;
use openmail_core::model::Address;
use openmail_core::{Error, ErrorCode, Result};
use openmail_smtp::{
    ApprovalConsumer, ApprovalProof, SendRequest, SendRequestDescriptor, SmtpClient, SqliteOutbox,
};

use crate::delivery::{Digest, DigestSender};
use crate::engine::SharedStore;
use crate::store::DigestClaim;

/// Every digest subject starts with this; the consumer checks it so the approval cannot be
/// reused for arbitrary mail.
pub const DIGEST_SUBJECT_PREFIX: &str = "[OpenMail brief]";
/// One scheduled brief plus a few manual ones; past this something is looping.
pub const MAX_DIGESTS_PER_DAY: u32 = 6;
const RATE_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Principal name recorded in the SMTP audit trail.
const PRINCIPAL: &str = "openmail-briefs-digest";

fn denied(msg: &str) -> Error {
    Error::new(ErrorCode::AccessDenied, msg)
}

/// Approves one thing: a digest to the owner.
#[derive(Debug, Clone)]
pub struct OwnerOnlyConsumer {
    owner: String,
}

impl OwnerOnlyConsumer {
    pub fn new(owner_email: &str) -> Self {
        Self {
            owner: owner_email.trim().to_lowercase(),
        }
    }
}

impl ApprovalConsumer for OwnerOnlyConsumer {
    fn consume(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
        _token: Option<&str>,
    ) -> Result<()> {
        let recipients = descriptor.recipients();
        let to_owner_only =
            matches!(recipients, [only] if only.trim().eq_ignore_ascii_case(&self.owner));
        if principal != PRINCIPAL
            || !to_owner_only
            || !descriptor.subject().starts_with(DIGEST_SUBJECT_PREFIX)
        {
            return Err(denied(
                "digest approvals cover the owner's own address only",
            ));
        }
        Ok(())
    }
}

/// Sends digests for one account to that account's own address.
pub struct SmtpDigestSender<S> {
    client: SmtpClient<SqliteOutbox, S>,
    account: AccountConfig,
    store: SharedStore,
}

impl<S> std::fmt::Debug for SmtpDigestSender<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpDigestSender")
            .field("account", &self.account.id)
            .finish_non_exhaustive()
    }
}

impl<S: SecretSource> SmtpDigestSender<S> {
    /// Fails unless the account may send at all.
    pub fn new(
        client: SmtpClient<SqliteOutbox, S>,
        account: AccountConfig,
        store: SharedStore,
    ) -> Result<Self> {
        if account.smtp.is_none() {
            return Err(Error::new(
                ErrorCode::ConfigInvalid,
                format!(
                    "account '{}' has no SMTP section, so it cannot send digests",
                    account.id
                ),
            ));
        }
        if account.read_only || !account.permissions.send {
            return Err(denied(
                "digest delivery needs an account with permissions.send granted and read_only = false",
            ));
        }
        Ok(Self {
            client,
            account,
            store,
        })
    }

    /// The only address this sender will ever deliver to.
    pub fn owner_address(&self) -> &str {
        &self.account.email
    }

    fn claim(&self, digest: &Digest) -> Result<DigestClaim> {
        let now = Utc::now();
        let window = chrono::Duration::from_std(RATE_WINDOW)
            .map_err(|_| Error::new(ErrorCode::Internal, "rate window out of range"))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "brief store lock poisoned"))?;
        store.claim_digest(
            &digest.brief_id,
            &self.account.id,
            &digest.recipient,
            &now.to_rfc3339(),
            &(now - window).to_rfc3339(),
            MAX_DIGESTS_PER_DAY,
        )
    }

    fn finish(&self, id: i64, state: &str) {
        let outcome = self
            .store
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "brief store lock poisoned"))
            .and_then(|s| s.finish_digest(id, state));
        if let Err(e) = outcome {
            // The send result matters more than the audit row; say loudly that the row is stale.
            tracing::error!(error = %e, state, "failed to record digest outcome");
        }
    }
}

impl<S: SecretSource> DigestSender for SmtpDigestSender<S> {
    async fn send(&self, digest: &Digest) -> Result<()> {
        if !digest
            .recipient
            .trim()
            .eq_ignore_ascii_case(self.account.email.trim())
        {
            return Err(denied(
                "digests can only be sent to the account owner's own address",
            ));
        }
        let claim_id = match self.claim(digest)? {
            DigestClaim::Claimed(id) => id,
            // Another process or an earlier run already owns this brief's digest.
            DigestClaim::AlreadySent => return Ok(()),
            DigestClaim::RateLimited => {
                return Err(Error::new(
                    ErrorCode::RateLimited,
                    format!(
                        "digest limit of {MAX_DIGESTS_PER_DAY} per day reached for this account"
                    ),
                ));
            }
        };
        let owner = Address {
            name: None,
            email: self.account.email.clone(),
        };
        let request = SendRequest {
            idempotency_key: format!("digest-{}", digest.brief_id),
            from: Address {
                name: Some("OpenMail briefs".to_owned()),
                email: self.account.email.clone(),
            },
            to: vec![owner],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: format!("{DIGEST_SUBJECT_PREFIX} {}", digest.subject),
            text: Some(digest.body_markdown.clone()),
            html: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
        };
        let consumer = OwnerOnlyConsumer::new(&self.account.email);
        let proof = ApprovalProof::obtain(&consumer, PRINCIPAL, &self.account.id, &request, None)?;
        let result = self.client.send(&self.account, request, proof).await;
        let state = match &result {
            Ok(_) => "sent",
            Err(e) if e.code() == ErrorCode::DeliveryUncertain => "uncertain",
            Err(_) => "failed",
        };
        self.finish(claim_id, state);
        tracing::info!(account = %self.account.id, brief = %digest.brief_id, state, "digest delivery finished");
        result.map(|_| ())
    }
}

/// Used when no digest account is configured: delivery is simply unavailable.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDigest;

impl DigestSender for NoDigest {
    async fn send(&self, _digest: &Digest) -> Result<()> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "digest delivery is not configured ([briefs.digest])",
        ))
    }
}
