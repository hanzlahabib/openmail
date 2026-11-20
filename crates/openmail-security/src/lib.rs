//! Security layer: secret resolution, authorization, send approvals, redaction
//! and rate limiting. Everything here fails closed: when a check cannot be
//! completed, the operation is denied.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod approval;
pub mod approval_store;
pub mod authz;
pub mod clock;
pub mod pending;
pub mod ratelimit;
pub mod redact;
pub mod secret;
pub mod send_policy;

pub use approval::{
    ApprovalGrantor, ApprovalId, ApprovalIssuer, ApprovalVerifier, GrantDecision, SendIntent,
    Sha256Digest,
};
pub use approval_store::{ApprovalStore, InMemoryApprovalStore, SqliteApprovalStore};
pub use authz::{Action, Authorizer, Principal};
pub use clock::{Clock, SystemClock};
pub use pending::{
    DEFAULT_TOKEN_TTL, HumanConfirmation, PendingApproval, PendingApprovals, PendingId,
    PendingStatus,
};
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use redact::Redacted;
pub use secret::EnvKeyringSecretSource;
pub use send_policy::{ApprovalMode, PolicyConsumer, SendPolicyStore};
