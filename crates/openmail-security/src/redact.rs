//! Helpers that keep secrets and personal data out of logs.
use std::fmt;

/// Wraps any value so `Display`/`Debug` never reveal it. Use for anything that
/// might end up in a `tracing` field or an error message.
pub struct Redacted<T>(T);

const PLACEHOLDER: &str = "[REDACTED]";

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    /// Deliberately named so every access to the inner value is greppable.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

/// Headers that are safe to log: structural/technical only. `Subject`, `From`,
/// `To`, `Cc`, `Reply-To`, `Authorization` and anything `X-*` carry personal data
/// or credentials and are intentionally absent.
pub const LOG_SAFE_HEADERS: &[&str] = &["content-type", "content-transfer-encoding", "date", "message-id", "mime-version"];

/// Longest header value kept in a log line (long values are usually attacker-chosen noise).
const MAX_LOGGED_HEADER_VALUE: usize = 128;

pub fn is_log_safe_header(name: &str) -> bool {
    LOG_SAFE_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name.trim()))
}

/// Keeps only allowlisted headers, strips control characters (log injection)
/// and truncates values on a char boundary.
pub fn loggable_headers<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(name, _)| is_log_safe_header(name))
        .map(|(name, value)| {
            let clean: String = value.chars().filter(|c| !c.is_control()).take(MAX_LOGGED_HEADER_VALUE).collect();
            (name.trim().to_ascii_lowercase(), clean)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_never_prints_value() {
        let r = Redacted::new("CANARY-s3cret");
        assert_eq!(format!("{r}"), "[REDACTED]");
        assert_eq!(format!("{r:?}"), "[REDACTED]");
        assert_eq!(format!("{:#?}", Some(&r)), "Some(\n    [REDACTED],\n)");
        assert_eq!(*r.expose(), "CANARY-s3cret");
    }

    #[test]
    fn header_allowlist_drops_pii_and_credentials() {
        let kept = loggable_headers([
            ("Subject", "salary"),
            ("From", "a@b.c"),
            ("Authorization", "Bearer CANARY"),
            ("X-Custom", "x"),
            ("Message-ID", "<1@example.com>"),
            ("DATE", "Mon, 1 Jan 2024"),
        ]);
        assert_eq!(kept, vec![("message-id".to_owned(), "<1@example.com>".to_owned()), ("date".to_owned(), "Mon, 1 Jan 2024".to_owned())]);
    }

    #[test]
    fn header_values_are_sanitized_and_truncated() {
        let long = format!("a\r\nFAKE LOG LINE{}", "x".repeat(500));
        let kept = loggable_headers([("Message-Id", long.as_str())]);
        assert!(!kept[0].1.contains('\n') && !kept[0].1.contains('\r'));
        assert_eq!(kept[0].1.chars().count(), MAX_LOGGED_HEADER_VALUE);
    }
}
