//! Tracing subscriber setup. Output always goes to stderr: stdout carries the
//! MCP JSON-RPC stream in stdio mode and must never receive log lines.

use std::io;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::util::SubscriberInitExt;

/// Log line format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl LogFormat {
    /// Parses `json` / `text` (case-insensitive); anything else is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "text" | "pretty" | "plain" => Some(Self::Text),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TracingInitError {
    #[error("invalid log filter directive: {0}")]
    Filter(String),
    #[error("a global tracing subscriber is already installed")]
    AlreadyInstalled,
}

/// Default filter when none is configured: quiet dependencies, info for us.
pub const DEFAULT_FILTER: &str = "info";

/// Cap applied to rmcp unless the operator names it. rmcp logs whole tool results (mail bodies)
/// at debug, so a blanket `debug` would copy mailbox content into stderr.
const RMCP_CAP: &str = "rmcp=info";

/// The filter `init_tracing` installs, exposed so callers can assert on it with a scoped
/// subscriber.
pub fn build_filter(directives: Option<&str>) -> Result<EnvFilter, TracingInitError> {
    let (filter, explicit) = match directives {
        Some(d) => (
            EnvFilter::try_new(d).map_err(|e| TracingInitError::Filter(e.to_string()))?,
            d.to_owned(),
        ),
        None => {
            let env = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default();
            (
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER)),
                env,
            )
        }
    };
    if explicit.contains("rmcp") {
        return Ok(filter);
    }
    let cap = RMCP_CAP
        .parse()
        .map_err(|_| TracingInitError::Filter(RMCP_CAP.to_owned()))?;
    Ok(filter.add_directive(cap))
}

/// Installs the global subscriber writing to stderr. `directives` overrides
/// `RUST_LOG`; `None` falls back to `RUST_LOG` then [`DEFAULT_FILTER`].
pub fn init_tracing(format: LogFormat, directives: Option<&str>) -> Result<(), TracingInitError> {
    let filter = build_filter(directives)?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(true);
    let result = match format {
        LogFormat::Json => builder.json().finish().try_init(),
        LogFormat::Text => builder.finish().try_init(),
    };
    result.map_err(|_| TracingInitError::AlreadyInstalled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats() {
        assert_eq!(LogFormat::parse("JSON"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse(" text "), Some(LogFormat::Text));
        assert_eq!(LogFormat::parse("xml"), None);
    }

    #[test]
    fn rejects_bad_directive() {
        assert!(matches!(
            build_filter(Some("openmail=notalevel")),
            Err(TracingInitError::Filter(_))
        ));
        assert!(build_filter(Some("openmail_imap=debug,warn")).is_ok());
    }

    #[test]
    fn rmcp_is_capped_unless_named() {
        let capped = build_filter(Some("debug")).map(|f| f.to_string());
        assert!(capped.is_ok_and(|f| f.contains("rmcp=info")));
        let open = build_filter(Some("debug,rmcp=debug")).map(|f| f.to_string());
        assert!(open.is_ok_and(|f| !f.contains("rmcp=info")));
    }

    #[test]
    fn second_init_reports_already_installed() {
        // Only one global subscriber per process; the first call may succeed or
        // another test may have won, but a repeat must always error cleanly.
        let _ = init_tracing(LogFormat::Json, Some("info"));
        assert!(matches!(
            init_tracing(LogFormat::Text, Some("info")),
            Err(TracingInitError::AlreadyInstalled)
        ));
    }
}
