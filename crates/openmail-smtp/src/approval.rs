//! Approval binding. The security/MCP layers own the permission decision; this crate
//! only verifies that the approval they hand over was issued for the exact content
//! about to leave the machine.
use std::fmt;

use sha2::{Digest, Sha256};

/// SHA-256 over a canonical, length-prefixed encoding of everything that defines
/// a message (see `SendRequest::content_hash`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub(crate) fn from_digest(hasher: Sha256) -> Self {
        Self(hasher.finalize().into())
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

/// Opaque proof that a human/policy approved sending a specific content hash.
/// Construct it only after approval; `token` is the caller's own approval id and
/// is recorded in the audit trail verbatim (never interpreted here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalProof {
    content_hash: ContentHash,
    token: String,
}

impl ApprovalProof {
    pub fn new(content_hash: ContentHash, token: impl Into<String>) -> Self {
        Self {
            content_hash,
            token: token.into(),
        }
    }

    pub(crate) fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}
