//! Approval binding. The security/MCP layers own the permission decision; this crate
//! only verifies that the approval they hand over was issued for the exact content
//! about to leave the machine.
use std::fmt;

use openmail_core::Result;
use openmail_core::ids::AccountId;
use sha2::{Digest, Sha256};

use crate::request::SendRequest;

/// 8 bytes (64 bits) is enough to correlate an audit row with an approval without
/// storing anything replayable.
const AUDIT_REF_BYTES: usize = 8;

/// SHA-256 over a canonical, length-prefixed encoding of everything that defines
/// a message (see `SendRequest::content_hash`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub(crate) fn from_digest(hasher: Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// What an approval must bind, derived by this crate from the real [`SendRequest`]
/// (never supplied by the caller). Recipients are the raw To+Cc+Bcc addresses in
/// order; normalization is the consumer's job so one rule lives in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequestDescriptor {
    account: AccountId,
    recipients: Vec<String>,
    subject: String,
    content_hash: ContentHash,
    attachment_sha256: Vec<[u8; 32]>,
}

impl SendRequestDescriptor {
    pub(crate) fn from_request(account: &AccountId, request: &SendRequest) -> Self {
        Self {
            account: account.clone(),
            recipients: request
                .to
                .iter()
                .chain(&request.cc)
                .chain(&request.bcc)
                .map(|a| a.email.clone())
                .collect(),
            subject: request.subject.clone(),
            content_hash: request.content_hash(),
            attachment_sha256: request
                .attachments
                .iter()
                .map(|a| Sha256::digest(&a.data).into())
                .collect(),
        }
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
    /// Covers body, html, cc/bcc, references and attachments; see `SendRequest::content_hash`.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }
    pub fn attachment_sha256(&self) -> &[[u8; 32]] {
        &self.attachment_sha256
    }
}

/// Implemented by the security layer. A successful return means the approval was
/// verified against `descriptor` for `principal` AND atomically consumed (single
/// use). `token` is the bearer approval id the agent supplied, if any.
pub trait ApprovalConsumer {
    fn consume(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
        token: Option<&str>,
    ) -> Result<()>;
}

/// Capability proving an approval for one exact request was consumed.
///
/// There is deliberately no constructor taking caller-supplied data: the only way
/// to get one is [`ApprovalProof::obtain`], which runs an [`ApprovalConsumer`]
/// against a descriptor this crate derives from the request itself. It is neither
/// `Clone` nor `Copy`, and `SmtpClient::send` takes it by value.
///
/// ```compile_fail
/// use openmail_smtp::{ApprovalProof, ContentHash};
/// // No public constructor exists, so a caller cannot fabricate a proof.
/// let _ = ApprovalProof::new(todo!(), "token");
/// ```
///
/// ```compile_fail
/// use openmail_smtp::ApprovalProof;
/// // Fields are private: struct-literal forgery does not compile.
/// let _ = ApprovalProof { content_hash: todo!(), account: todo!(), audit_ref: todo!() };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovalProof {
    content_hash: ContentHash,
    account: AccountId,
    audit_ref: String,
}

impl ApprovalProof {
    /// Consumes the approval for exactly `request` on `account`.
    pub fn obtain(
        consumer: &impl ApprovalConsumer,
        principal: &str,
        account: &AccountId,
        request: &SendRequest,
        token: Option<&str>,
    ) -> Result<Self> {
        let descriptor = SendRequestDescriptor::from_request(account, request);
        consumer.consume(principal, &descriptor, token)?;
        // The bearer token is a secret; the audit trail keeps only a digest prefix.
        let audit_ref = token.map_or_else(String::new, |t| {
            let d = Sha256::digest(t.as_bytes());
            let hex: String = d
                .iter()
                .take(AUDIT_REF_BYTES)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("sha256:{hex}")
        });
        Ok(Self {
            content_hash: descriptor.content_hash,
            account: descriptor.account,
            audit_ref,
        })
    }

    pub(crate) fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    pub(crate) fn account(&self) -> &AccountId {
        &self.account
    }

    pub(crate) fn audit_ref(&self) -> &str {
        &self.audit_ref
    }
}
