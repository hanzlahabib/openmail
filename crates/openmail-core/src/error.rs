use serde::Serialize;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Stable, machine-readable error identifiers. Part of the public tool contract:
/// add variants, never rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    ConfigInvalid,
    AccountNotFound,
    AccessDenied,
    ReadOnlyAccount,
    SendNotApproved,
    ApprovalInvalid,
    AuthFailed,
    ConnectionFailed,
    Timeout,
    FolderNotFound,
    StaleReference,
    MessageNotFound,
    LimitExceeded,
    RateLimited,
    InvalidInput,
    DeliveryUncertain,
    Unsupported,
    Internal,
}

/// Errors never carry secrets or message bodies in their `Display` output.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{code:?}: {message}")]
    Coded { code: ErrorCode, message: String },
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Coded { code, message: message.into() }
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Coded { code, .. } => *code,
        }
    }
}
