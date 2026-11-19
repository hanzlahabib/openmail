//! Validation of search arguments into the core `SearchQuery`.
use openmail_core::model::SearchQuery;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

use crate::error::ToolError;
use crate::input::{MAX_ARG_CHARS, SearchInput};

/// Normalize `YYYY-MM-DD` or an RFC 3339 timestamp to an RFC 3339 string; reject anything else.
fn normalize_date(field: &str, raw: &str) -> Result<String, ToolError> {
    let bad = || {
        ToolError::invalid(format!(
            "{field} must be YYYY-MM-DD or an RFC 3339 timestamp"
        ))
    };
    if OffsetDateTime::parse(raw, &Rfc3339).is_ok() {
        return Ok(raw.to_owned());
    }
    let mut parts = raw.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let month = m
        .parse::<u8>()
        .ok()
        .and_then(|n| Month::try_from(n).ok())
        .ok_or_else(bad)?;
    let date = Date::from_calendar_date(
        y.parse().map_err(|_| bad())?,
        month,
        d.parse().map_err(|_| bad())?,
    )
    .map_err(|_| bad())?;
    Ok(format!("{date}T00:00:00Z"))
}

fn check_text(field: &str, v: Option<String>) -> Result<Option<String>, ToolError> {
    match v {
        Some(s) if s.trim().is_empty() => {
            Err(ToolError::invalid(format!("{field} must not be empty")))
        }
        Some(s) if s.chars().count() > MAX_ARG_CHARS => Err(ToolError::invalid(format!(
            "{field} is longer than {MAX_ARG_CHARS} characters"
        ))),
        other => Ok(other),
    }
}

pub fn build_query(i: SearchInput) -> Result<SearchQuery, ToolError> {
    let q = SearchQuery {
        folder: check_text("folder", i.folder)?,
        from: check_text("from", i.from)?,
        to: check_text("to", i.to)?,
        subject: check_text("subject", i.subject)?,
        text: check_text("text", i.text)?,
        since: i.since.map(|s| normalize_date("since", &s)).transpose()?,
        before: i.before.map(|s| normalize_date("before", &s)).transpose()?,
        unread: i.unread,
        flagged: i.flagged,
        has_attachment: i.has_attachment,
    };
    let has_filter = q.from.is_some()
        || q.to.is_some()
        || q.subject.is_some()
        || q.text.is_some()
        || q.since.is_some()
        || q.before.is_some()
        || q.unread.is_some()
        || q.flagged.is_some()
        || q.has_attachment.is_some();
    if !has_filter {
        return Err(ToolError::invalid(
            "at least one search filter is required; use mail_list_messages to browse a folder",
        ));
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_normalized_or_rejected() {
        assert_eq!(
            normalize_date("since", "2026-02-03").unwrap(),
            "2026-02-03T00:00:00Z"
        );
        assert_eq!(
            normalize_date("since", "2026-02-03T10:00:00+01:00").unwrap(),
            "2026-02-03T10:00:00+01:00"
        );
        for bad in [
            "2026-13-01",
            "2026-02-30",
            "yesterday",
            "2026-2-3",
            "2026-02-03-01",
        ] {
            assert!(normalize_date("since", bad).is_err(), "{bad}");
        }
    }
}
