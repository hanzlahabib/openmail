//! Internal error type. Classifies async-imap failures so the pool can decide
//! whether a session is still usable, and maps to the stable core `ErrorCode`s.
//! Messages never include server response text beyond a short sanitized form,
//! and never credentials.
use openmail_core::{Error, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum ImapError {
    /// Network-level failure: the session must be discarded.
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("timed out")]
    Timeout,
    #[error("authentication failed")]
    Auth,
    /// Server answered NO/BAD to a command; session remains usable.
    #[error("server rejected command: {0}")]
    Rejected(String),
    #[error(transparent)]
    Core(#[from] Error),
}

impl ImapError {
    pub fn core(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Core(Error::new(code, message))
    }

    /// True when the underlying session can no longer be trusted.
    pub fn is_connection_level(&self) -> bool {
        matches!(self, Self::Connection(_) | Self::Timeout)
    }
}

impl From<async_imap::error::Error> for ImapError {
    fn from(e: async_imap::error::Error) -> Self {
        use async_imap::error::Error as E;
        match e {
            E::Io(e) => Self::Connection(e.to_string()),
            E::ConnectionLost => Self::Connection("connection lost".into()),
            E::No(m) | E::Bad(m) => Self::Rejected(sanitize(&m)),
            E::Validate(_) => Self::core(
                ErrorCode::InvalidInput,
                "value contains characters not allowed in IMAP commands",
            ),
            E::Parse(_) => Self::Connection("unparseable server response".into()),
            _ => Self::Connection("unexpected IMAP client error".into()),
        }
    }
}

impl From<ImapError> for Error {
    fn from(e: ImapError) -> Self {
        match e {
            ImapError::Core(e) => e,
            ImapError::Connection(m) => Error::new(ErrorCode::ConnectionFailed, m),
            ImapError::Timeout => Error::new(ErrorCode::Timeout, "IMAP operation timed out"),
            ImapError::Auth => Error::new(
                ErrorCode::AuthFailed,
                "IMAP authentication failed; check the configured credential",
            ),
            ImapError::Rejected(m) => Error::new(
                ErrorCode::Internal,
                format!("IMAP server rejected the command: {m}"),
            ),
        }
    }
}

/// Keeps server text short and single-line before it is surfaced.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(120).collect()
}

pub type ImapResult<T> = Result<T, ImapError>;
