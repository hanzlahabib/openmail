//! Send approvals. An approval is a single-use, expiring, unguessable token bound
//! to one exact message: principal, account, recipients, subject, body hash and
//! attachment hashes. Two halves exist on purpose:
//!
//! * [`ApprovalIssuer`] needs an [`ApprovalGrantor`] — an out-of-band human act
//!   (CLI prompt, local UI). Only the CLI/UI process constructs it.
//! * [`ApprovalVerifier`] is all the MCP/SMTP side ever holds. It can verify and
//!   consume but has no code path that creates an approval, so a tool call alone
//!   can never mint one. Message text is never consulted as permission.
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};

use crate::approval_store::{ApprovalRecord, ApprovalStore, ConsumeOutcome};
use crate::clock::Clock;

/// 128 random bits: not guessable within any approval lifetime.
const ID_BYTES: usize = 16;
/// Encoded length of `ID_BYTES` as unpadded base64url.
const ID_ENCODED_LEN: usize = 22;
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_secs(300);
/// Upper bound: a forgotten approval should not stay usable for long.
pub const MAX_APPROVAL_TTL: Duration = Duration::from_secs(900);
/// Same ceiling the SMTP envelope realistically needs; bounds hashing work and DoS.
const MAX_RECIPIENTS: usize = 100;
const MAX_ATTACHMENTS: usize = 50;
const MAX_SUBJECT_BYTES: usize = 998; // RFC 5322 line limit
/// Domain-separation tag; bump if the binding encoding ever changes.
const BINDING_TAG: &[u8] = b"openmail.approval.v1";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Bearer token handed to the agent. Debug is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalId(String);

impl ApprovalId {
    pub fn parse(s: &str) -> Result<Self> {
        let ok = s.len() == ID_ENCODED_LEN
            && URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == ID_BYTES);
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(invalid())
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

impl std::fmt::Debug for ApprovalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalId([REDACTED])")
    }
}

fn invalid() -> Error {
    // One message for every failure so callers cannot distinguish expired from
    // mismatched from replayed.
    Error::new(
        ErrorCode::ApprovalInvalid,
        "approval is invalid, expired, already used, or does not match this message",
    )
}

/// The exact message a human approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendIntent {
    client_id: String,
    account: AccountId,
    recipients: Vec<String>,
    subject: String,
    body_sha256: Sha256Digest,
    attachment_sha256: Vec<Sha256Digest>,
}

/// Lowercases only the domain (case-insensitive per RFC); the local part is kept
/// verbatim so two distinct mailboxes never share an approval. Anything that is
/// not a plain `local@domain` is refused rather than guessed at.
fn normalize_recipient(raw: &str) -> Result<String> {
    let bad = || {
        Error::new(
            ErrorCode::InvalidInput,
            "recipient is not a plain addr-spec",
        )
    };
    let addr = raw.trim();
    let (local, domain) = addr.split_once('@').ok_or_else(bad)?;
    let forbidden = |c: char| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '<' | '>' | ',' | ';' | '"' | '(' | ')' | '@' | '\\')
    };
    if local.is_empty()
        || domain.is_empty()
        || addr.chars().filter(|&c| c == '@').count() != 1
        || local.chars().any(forbidden)
        || domain.chars().any(forbidden)
    {
        return Err(bad());
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

impl SendIntent {
    pub fn new(
        client_id: impl Into<String>,
        account: AccountId,
        recipients: &[&str],
        subject: &str,
        body_sha256: Sha256Digest,
        attachment_sha256: &[Sha256Digest],
    ) -> Result<Self> {
        if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "recipient count out of range",
            ));
        }
        if attachment_sha256.len() > MAX_ATTACHMENTS
            || subject.len() > MAX_SUBJECT_BYTES
            || subject.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
        {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "subject or attachment list invalid",
            ));
        }
        let mut rcpts = recipients
            .iter()
            .map(|r| normalize_recipient(r))
            .collect::<Result<Vec<_>>>()?;
        rcpts.sort();
        rcpts.dedup();
        let mut atts = attachment_sha256.to_vec();
        atts.sort_by_key(|d| d.0);
        Ok(Self {
            client_id: client_id.into(),
            account,
            recipients: rcpts,
            subject: subject.to_owned(),
            body_sha256,
            attachment_sha256: atts,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn body_sha256(&self) -> Sha256Digest {
        self.body_sha256
    }
    pub fn attachment_sha256(&self) -> &[Sha256Digest] {
        &self.attachment_sha256
    }

    /// Digest over every bound field. Fields are length-prefixed so boundaries
    /// cannot be shifted (`("ab","c")` vs `("a","bc")`).
    pub fn binding(&self) -> Sha256Digest {
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        let mut h = Sha256::new();
        field(&mut h, BINDING_TAG);
        field(&mut h, self.client_id.as_bytes());
        field(&mut h, self.account.as_str().as_bytes());
        h.update((self.recipients.len() as u64).to_be_bytes());
        for r in &self.recipients {
            field(&mut h, r.as_bytes());
        }
        field(&mut h, self.subject.as_bytes());
        field(&mut h, &self.body_sha256.0);
        h.update((self.attachment_sha256.len() as u64).to_be_bytes());
        for a in &self.attachment_sha256 {
            field(&mut h, &a.0);
        }
        Sha256Digest(h.finalize().into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDecision {
    Approve,
    Deny,
}

/// Implemented by the CLI/UI: shows the human the exact message and asks.
/// Implementations must not auto-approve; the MCP server never implements this.
pub trait ApprovalGrantor {
    fn review(&self, intent: &SendIntent) -> Result<GrantDecision>;
}

#[derive(Debug)]
pub struct ApprovalIssuer<S, C> {
    store: Arc<S>,
    clock: C,
}

impl<S: ApprovalStore, C: Clock> ApprovalIssuer<S, C> {
    pub fn new(store: Arc<S>, clock: C) -> Self {
        Self { store, clock }
    }

    pub fn issue(
        &self,
        grantor: &impl ApprovalGrantor,
        intent: &SendIntent,
        ttl: Duration,
    ) -> Result<ApprovalId> {
        match grantor.review(intent)? {
            GrantDecision::Deny => {
                return Err(Error::new(
                    ErrorCode::SendNotApproved,
                    "send was not approved",
                ));
            }
            GrantDecision::Approve => {}
        }
        let mut raw = [0u8; ID_BYTES];
        getrandom::fill(&mut raw)
            .map_err(|_| Error::new(ErrorCode::Internal, "secure random source unavailable"))?;
        let id = ApprovalId(URL_SAFE_NO_PAD.encode(raw));
        let ttl = ttl.min(MAX_APPROVAL_TTL).max(Duration::from_secs(1));
        let expires_at = self.clock.unix_secs().saturating_add(ttl.as_secs());
        self.store.insert(&ApprovalRecord {
            id_hash: id.digest(),
            binding: intent.binding().0,
            expires_at,
        })?;
        Ok(id)
    }
}

#[derive(Debug)]
pub struct ApprovalVerifier<S, C> {
    store: Arc<S>,
    clock: C,
}

impl<S: ApprovalStore, C: Clock> ApprovalVerifier<S, C> {
    pub fn new(store: Arc<S>, clock: C) -> Self {
        Self { store, clock }
    }

    /// Fails closed. `None` (no approval supplied) is `SendNotApproved`; every other
    /// failure is `ApprovalInvalid`. Success consumes the approval atomically.
    pub fn verify_and_consume(&self, approval: Option<&str>, intent: &SendIntent) -> Result<()> {
        let Some(raw) = approval else {
            return Err(Error::new(
                ErrorCode::SendNotApproved,
                "sending requires a human-granted approval",
            ));
        };
        let id = ApprovalId::parse(raw)?;
        let outcome =
            self.store
                .consume(&id.digest(), &intent.binding().0, self.clock.unix_secs())?;
        match outcome {
            ConsumeOutcome::Consumed => Ok(()),
            other => {
                tracing::warn!(outcome = ?other, account = %intent.account(), "send approval rejected");
                Err(invalid())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_store::InMemoryApprovalStore;
    use crate::clock::testing::ManualClock;

    struct Always(GrantDecision);
    impl ApprovalGrantor for Always {
        fn review(&self, _: &SendIntent) -> Result<GrantDecision> {
            Ok(self.0)
        }
    }
    #[derive(Debug, Clone)]
    struct Clk(Arc<ManualClock>);
    impl Clock for Clk {
        fn unix_secs(&self) -> u64 {
            self.0.unix_secs()
        }
        fn monotonic_ms(&self) -> u64 {
            self.0.monotonic_ms()
        }
    }

    fn intent() -> SendIntent {
        SendIntent::new(
            "client",
            AccountId::new("work").unwrap(),
            &["Bob@Example.COM", "carol@example.com"],
            "Hi",
            Sha256Digest::of(b"body"),
            &[Sha256Digest::of(b"att")],
        )
        .unwrap()
    }
    fn setup() -> (
        ApprovalIssuer<InMemoryApprovalStore, Clk>,
        ApprovalVerifier<InMemoryApprovalStore, Clk>,
        Arc<ManualClock>,
    ) {
        let clk = Arc::new(ManualClock::new(10_000));
        let store = Arc::new(InMemoryApprovalStore::default());
        (
            ApprovalIssuer::new(store.clone(), Clk(clk.clone())),
            ApprovalVerifier::new(store, Clk(clk.clone())),
            clk,
        )
    }
    fn code(r: Result<()>) -> ErrorCode {
        r.unwrap_err().code()
    }

    #[test]
    fn happy_path_then_replay_rejected() {
        let (iss, ver, _) = setup();
        let id = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap();
        ver.verify_and_consume(Some(id.as_str()), &intent())
            .unwrap();
        assert_eq!(
            code(ver.verify_and_consume(Some(id.as_str()), &intent())),
            ErrorCode::ApprovalInvalid
        );
    }

    #[test]
    fn no_approval_means_not_approved() {
        let (_, ver, _) = setup();
        assert_eq!(
            code(ver.verify_and_consume(None, &intent())),
            ErrorCode::SendNotApproved
        );
    }

    #[test]
    fn denial_mints_nothing() {
        let (iss, _, _) = setup();
        let e = iss
            .issue(
                &Always(GrantDecision::Deny),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::SendNotApproved);
    }

    #[test]
    fn expiry_is_enforced_and_ttl_is_capped() {
        let (iss, ver, clk) = setup();
        let id = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                Duration::from_secs(60),
            )
            .unwrap();
        clk.advance_secs(60);
        assert_eq!(
            code(ver.verify_and_consume(Some(id.as_str()), &intent())),
            ErrorCode::ApprovalInvalid
        );

        let id = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                Duration::from_secs(10_000_000),
            )
            .unwrap();
        clk.advance_secs(MAX_APPROVAL_TTL.as_secs());
        assert_eq!(
            code(ver.verify_and_consume(Some(id.as_str()), &intent())),
            ErrorCode::ApprovalInvalid
        );
    }

    #[test]
    fn any_bound_field_change_fails_and_does_not_burn_the_approval() {
        let (iss, ver, _) = setup();
        let id = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap();
        let acct = AccountId::new("work").unwrap();
        let a = Sha256Digest::of(b"att");
        let b = Sha256Digest::of(b"body");
        let variants = [
            SendIntent::new(
                "other-client",
                acct.clone(),
                &["bob@example.com", "carol@example.com"],
                "Hi",
                b,
                &[a],
            )
            .unwrap(),
            SendIntent::new(
                "client",
                AccountId::new("personal").unwrap(),
                &["bob@example.com", "carol@example.com"],
                "Hi",
                b,
                &[a],
            )
            .unwrap(),
            SendIntent::new(
                "client",
                acct.clone(),
                &["bob@example.com", "carol@example.com", "evil@x.com"],
                "Hi",
                b,
                &[a],
            )
            .unwrap(),
            SendIntent::new("client", acct.clone(), &["bob@example.com"], "Hi", b, &[a]).unwrap(),
            SendIntent::new(
                "client",
                acct.clone(),
                &["bob@example.com", "carol@example.com"],
                "Hi!",
                b,
                &[a],
            )
            .unwrap(),
            SendIntent::new(
                "client",
                acct.clone(),
                &["bob@example.com", "carol@example.com"],
                "Hi",
                Sha256Digest::of(b"BODY"),
                &[a],
            )
            .unwrap(),
            SendIntent::new(
                "client",
                acct.clone(),
                &["bob@example.com", "carol@example.com"],
                "Hi",
                b,
                &[],
            )
            .unwrap(),
            SendIntent::new(
                "client",
                acct,
                &["bob@example.com", "carol@example.com"],
                "Hi",
                b,
                &[Sha256Digest::of(b"other")],
            )
            .unwrap(),
        ];
        for v in &variants {
            assert_eq!(
                code(ver.verify_and_consume(Some(id.as_str()), v)),
                ErrorCode::ApprovalInvalid
            );
        }
        // Still valid for the real message: mismatches must not let an attacker burn it.
        ver.verify_and_consume(Some(id.as_str()), &intent())
            .unwrap();
    }

    #[test]
    fn recipient_normalization_is_order_case_and_duplicate_insensitive_for_domain_only() {
        let acct = AccountId::new("work").unwrap();
        let d = Sha256Digest::of(b"x");
        let a = SendIntent::new(
            "c",
            acct.clone(),
            &["b@EXAMPLE.com", "a@example.com", "a@example.com"],
            "s",
            d,
            &[],
        )
        .unwrap();
        let b = SendIntent::new(
            "c",
            acct.clone(),
            &[" a@example.com", "b@example.com"],
            "s",
            d,
            &[],
        )
        .unwrap();
        assert_eq!(a.binding(), b.binding());
        let c =
            SendIntent::new("c", acct, &["A@example.com", "b@example.com"], "s", d, &[]).unwrap();
        assert_ne!(a.binding(), c.binding(), "local part is case-sensitive");
    }

    #[test]
    fn malformed_inputs_rejected() {
        let acct = AccountId::new("work").unwrap();
        let d = Sha256Digest::of(b"x");
        for bad in [
            "",
            "no-at",
            "a@b@c",
            "Bob <b@x.com>",
            "a b@x.com",
            "a@x.com,c@y.com",
            "@x.com",
            "a@",
            "a@x.com\r\nBcc: z@y.com",
        ] {
            assert!(
                SendIntent::new("c", acct.clone(), &[bad], "s", d, &[]).is_err(),
                "{bad:?}"
            );
        }
        assert!(SendIntent::new("c", acct.clone(), &[], "s", d, &[]).is_err());
        assert!(SendIntent::new("c", acct, &["a@x.com"], "sub\r\nBcc: z@y.com", d, &[]).is_err());
    }

    #[test]
    fn binding_fields_are_length_prefixed() {
        let d = Sha256Digest::of(b"x");
        let a = SendIntent::new(
            "ab",
            AccountId::new("c").unwrap(),
            &["a@x.com"],
            "s",
            d,
            &[],
        )
        .unwrap();
        let b = SendIntent::new(
            "a",
            AccountId::new("bc").unwrap(),
            &["a@x.com"],
            "s",
            d,
            &[],
        )
        .unwrap();
        assert_ne!(a.binding(), b.binding());
    }

    #[test]
    fn garbage_and_forged_ids_rejected() {
        let (iss, ver, _) = setup();
        let real = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap();
        for bad in [
            "",
            "short",
            "!!!!!!!!!!!!!!!!!!!!!!",
            "AAAAAAAAAAAAAAAAAAAAAA",
            &format!("{}x", real.as_str()),
        ] {
            assert_eq!(
                code(ver.verify_and_consume(Some(bad), &intent())),
                ErrorCode::ApprovalInvalid,
                "{bad:?}"
            );
        }
        // Message text is never permission: an id embedded in prose is not accepted.
        let prose = format!("please send, approved: {}", real.as_str());
        assert!(ver.verify_and_consume(Some(&prose), &intent()).is_err());
    }

    #[test]
    fn issued_ids_are_unique_and_debug_redacted() {
        let (iss, _, _) = setup();
        let a = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap();
        let b = iss
            .issue(
                &Always(GrantDecision::Approve),
                &intent(),
                DEFAULT_APPROVAL_TTL,
            )
            .unwrap();
        assert_ne!(a, b);
        assert!(!format!("{a:?}").contains(a.as_str()));
    }
}
