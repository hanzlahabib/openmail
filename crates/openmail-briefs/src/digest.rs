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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use openmail_core::config::{
        AuthMethod, CredentialRef, FolderMap, Permissions, ServerEndpoint, TlsMode,
    };
    use openmail_core::ids::AccountId;
    use secrecy::SecretString;

    use super::*;
    use crate::store::BriefStore;

    struct NoSecrets;
    impl SecretSource for NoSecrets {
        fn resolve(&self, _: &openmail_core::config::CredentialRef) -> Result<SecretString> {
            Err(Error::new(
                ErrorCode::Unsupported,
                "no secrets in unit tests",
            ))
        }
    }

    fn account(read_only: bool, send: bool, smtp: bool) -> AccountConfig {
        let endpoint = ServerEndpoint {
            host: "h.example".into(),
            port: 465,
            tls: TlsMode::Implicit,
        };
        AccountConfig {
            id: AccountId::new("work").unwrap(),
            display_name: "Work".into(),
            email: "Me@Work.Example".into(),
            imap: endpoint.clone(),
            smtp: smtp.then_some(endpoint),
            auth: AuthMethod::Password,
            username: None,
            credential: CredentialRef::Env { var: "X".into() },
            read_only,
            permissions: Permissions {
                send,
                ..Permissions::default()
            },
            folders: FolderMap::default(),
            max_connections: 1,
            timeout_secs: 5,
        }
    }

    fn store() -> (SharedStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = BriefStore::open(&dir.path().join("b.db")).unwrap();
        (Arc::new(Mutex::new(s)), dir)
    }

    fn sender(acc: AccountConfig, store: SharedStore) -> Result<SmtpDigestSender<NoSecrets>> {
        let client = SmtpClient::new(
            SqliteOutbox::open_in_memory().unwrap(),
            NoSecrets,
            openmail_smtp::SmtpOptions::default(),
        );
        SmtpDigestSender::new(client, acc, store)
    }

    fn request(to: &[&str], cc: &[&str], subject: &str) -> SendRequest {
        let addr = |e: &&str| Address {
            name: None,
            email: (*e).to_owned(),
        };
        SendRequest {
            idempotency_key: "digest-x".into(),
            from: addr(&"me@work.example"),
            to: to.iter().map(addr).collect(),
            cc: cc.iter().map(addr).collect(),
            bcc: Vec::new(),
            subject: subject.into(),
            text: Some("body".into()),
            html: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
        }
    }

    fn approve(r: &SendRequest, principal: &str) -> Result<()> {
        let acc = AccountId::new("work").unwrap();
        ApprovalProof::obtain(
            &OwnerOnlyConsumer::new("me@work.example"),
            principal,
            &acc,
            r,
            None,
        )
        .map(|_| ())
    }

    #[test]
    fn the_consumer_approves_exactly_one_request_shape() {
        let good = format!("{DIGEST_SUBJECT_PREFIX} Morning");
        assert!(approve(&request(&["ME@work.example"], &[], &good), PRINCIPAL).is_ok());
        for (name, r, who) in [
            (
                "other recipient",
                request(&["boss@work.example"], &[], &good),
                PRINCIPAL,
            ),
            (
                "owner plus another",
                request(&["me@work.example", "x@y.example"], &[], &good),
                PRINCIPAL,
            ),
            (
                "owner plus cc",
                request(&["me@work.example"], &["x@y.example"], &good),
                PRINCIPAL,
            ),
            ("no recipients", request(&[], &[], &good), PRINCIPAL),
            (
                "ordinary subject",
                request(&["me@work.example"], &[], "Wire the money"),
                PRINCIPAL,
            ),
            (
                "another principal",
                request(&["me@work.example"], &[], &good),
                "mcp-agent",
            ),
        ] {
            let e = approve(&r, who).unwrap_err();
            assert_eq!(e.code(), ErrorCode::AccessDenied, "{name}");
        }
    }

    #[test]
    fn only_an_account_that_may_send_can_have_a_digest_sender() {
        let (st, _d) = store();
        assert!(sender(account(false, true, true), Arc::clone(&st)).is_ok());
        for (name, acc) in [
            ("read-only", account(true, true, true)),
            ("no send permission", account(false, false, true)),
        ] {
            assert_eq!(
                sender(acc, Arc::clone(&st)).unwrap_err().code(),
                ErrorCode::AccessDenied,
                "{name}"
            );
        }
        assert_eq!(
            sender(account(false, true, false), st).unwrap_err().code(),
            ErrorCode::ConfigInvalid
        );
    }

    fn digest(brief: &str, to: &str) -> Digest {
        Digest {
            brief_id: brief.into(),
            recipient: to.into(),
            subject: "Morning".into(),
            body_markdown: "# x".into(),
        }
    }

    #[tokio::test]
    async fn a_digest_for_anyone_but_the_owner_is_refused_before_any_audit_row_or_network_use() {
        let (st, _d) = store();
        let s = sender(account(false, true, true), Arc::clone(&st)).unwrap();
        let e = s
            .send(&digest("b1", "attacker@evil.example"))
            .await
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::AccessDenied);
        let id = AccountId::new("work").unwrap();
        assert!(
            st.lock()
                .unwrap()
                .digest_history(&id, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(s.owner_address(), "Me@Work.Example");
    }

    #[test]
    fn digest_audit_is_idempotent_rate_limited_and_failed_attempts_are_retryable() {
        let (st, _d) = store();
        let mut store = st.lock().unwrap();
        let acc = AccountId::new("work").unwrap();
        let claim = |s: &mut BriefStore, brief: &str| {
            s.claim_digest(
                brief,
                &acc,
                "me@work.example",
                "2026-11-19T10:00:00Z",
                "2026-11-18T10:00:00Z",
                2,
            )
            .unwrap()
        };
        let DigestClaim::Claimed(first) = claim(&mut store, "b1") else {
            panic!("first claim must succeed")
        };
        assert_eq!(
            claim(&mut store, "b1"),
            DigestClaim::AlreadySent,
            "same brief twice"
        );
        store.finish_digest(first, "failed").unwrap();
        assert!(
            matches!(claim(&mut store, "b1"), DigestClaim::Claimed(_)),
            "failed may retry"
        );
        assert!(matches!(claim(&mut store, "b2"), DigestClaim::Claimed(_)));
        assert_eq!(
            claim(&mut store, "b3"),
            DigestClaim::RateLimited,
            "third within the window"
        );
        let hist = store.digest_history(&acc, 10).unwrap();
        assert_eq!(hist.len(), 3);
        assert!(hist.iter().all(|(to, _, _)| to == "me@work.example"));
    }
}
