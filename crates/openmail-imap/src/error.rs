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
    /// I/O errors can wrap raw server bytes (parse failures), so only the kind is kept:
    /// message content must never end up in an error string.
    pub fn io(e: &std::io::Error) -> Self {
        Self::Connection(format!("I/O error: {}", e.kind()))
    }

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
            E::Io(e) => Self::io(&e),
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

/// Longest server-supplied text surfaced in an error: enough for a human-readable
/// reason, too short to smuggle a payload.
const MAX_SERVER_TEXT_CHARS: usize = 200;

/// Server text is attacker-controlled: single line, no invisible/bidi characters, bounded.
fn sanitize(s: &str) -> String {
    crate::hygiene::bounded_remote_text(s, MAX_SERVER_TEXT_CHARS)
}

pub type ImapResult<T> = Result<T, ImapError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_rejection_text_is_bounded_and_clean() {
        let raw = format!("NO bad\r\n* INJECT\u{202E}\u{200B}{}", "z".repeat(1000));
        let ImapError::Rejected(m) = ImapError::from(async_imap::error::Error::No(raw)) else {
            panic!("expected Rejected");
        };
        assert_eq!(m.chars().count(), MAX_SERVER_TEXT_CHARS);
        assert!(m.starts_with("NO bad* INJECT"), "{m}");
        assert!(!m.contains(['\r', '\n', '\u{202E}', '\u{200B}']));
    }
}
