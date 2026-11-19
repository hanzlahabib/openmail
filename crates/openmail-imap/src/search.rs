//! Translates `SearchQuery` into an IMAP SEARCH key string. Only what IMAP can answer
//! server-side is sent; `has_attachment` cannot be (no standard key), so it is
//! returned as a client-side filter evaluated on BODYSTRUCTURE.
use openmail_core::model::SearchQuery;
use openmail_core::{Error, ErrorCode, Result};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

#[derive(Debug, PartialEq, Eq)]
pub struct Translated {
    /// Keys joined by spaces; never empty ("ALL" when there are no filters).
    pub criteria: String,
    /// Non-ASCII values present: the command must be prefixed with `CHARSET UTF-8`.
    pub needs_utf8: bool,
    /// Client-side filter on attachment presence.
    pub has_attachment: Option<bool>,
}

fn invalid(m: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, m)
}

/// IMAP quoted string. Control characters (incl. CR/LF/NUL) are rejected rather than
/// stripped so a crafted value can never inject extra commands.
pub fn quote(s: &str) -> Result<String> {
    if s.chars().any(char::is_control) {
        return Err(invalid("search values must not contain control characters"));
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn imap_date(s: &str) -> Result<String> {
    let dt = OffsetDateTime::parse(s, &Rfc3339)
        .map(|d| d.to_offset(time::UtcOffset::UTC))
        .ok()
        .map(|d| (d.year(), u8::from(d.month()), d.day()))
        .or_else(|| plain_date(s))
        .ok_or_else(|| invalid(format!("'{s}' is not an RFC 3339 date")))?;
    let (y, m, d) = dt;
    Ok(format!("{d}-{}-{y}", MONTHS[usize::from(m) - 1]))
}

/// Accepts a bare `YYYY-MM-DD`.
fn plain_date(s: &str) -> Option<(i32, u8, u8)> {
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i32, u8, u8) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    time::Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()?;
    Some((y, m, d))
}

pub fn translate(q: &SearchQuery) -> Result<Translated> {
    let mut keys: Vec<String> = Vec::new();
    let mut needs_utf8 = false;
    let mut text_key = |name: &str, v: &Option<String>, keys: &mut Vec<String>| -> Result<()> {
        if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
            needs_utf8 |= !v.is_ascii();
            keys.push(format!("{name} {}", quote(v)?));
        }
        Ok(())
    };
    text_key("FROM", &q.from, &mut keys)?;
    text_key("TO", &q.to, &mut keys)?;
    text_key("SUBJECT", &q.subject, &mut keys)?;
    text_key("TEXT", &q.text, &mut keys)?;
    if let Some(s) = &q.since {
        keys.push(format!("SINCE {}", imap_date(s)?));
    }
    if let Some(s) = &q.before {
        keys.push(format!("BEFORE {}", imap_date(s)?));
    }
    match q.unread {
        Some(true) => keys.push("UNSEEN".into()),
        Some(false) => keys.push("SEEN".into()),
        None => {}
    }
    match q.flagged {
        Some(true) => keys.push("FLAGGED".into()),
        Some(false) => keys.push("UNFLAGGED".into()),
        None => {}
    }
    if keys.is_empty() {
        keys.push("ALL".into());
    }
    Ok(Translated { criteria: keys.join(" "), needs_utf8, has_attachment: q.has_attachment })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_all() {
        let t = translate(&SearchQuery::default()).unwrap();
        assert_eq!(t.criteria, "ALL");
        assert!(!t.needs_utf8);
    }

    #[test]
    fn full_translation() {
        let q = SearchQuery {
            from: Some("alice@example.com".into()),
            subject: Some("say \"hi\"".into()),
            since: Some("2026-03-05T10:00:00Z".into()),
            before: Some("2026-04-01".into()),
            unread: Some(true),
            flagged: Some(false),
            ..Default::default()
        };
        let t = translate(&q).unwrap();
        assert_eq!(
            t.criteria,
            r#"FROM "alice@example.com" SUBJECT "say \"hi\"" SINCE 5-Mar-2026 BEFORE 1-Apr-2026 UNSEEN UNFLAGGED"#
        );
    }

    #[test]
    fn offset_dates_use_utc_day() {
        let q = SearchQuery { since: Some("2026-03-05T01:00:00+05:00".into()), ..Default::default() };
        assert_eq!(translate(&q).unwrap().criteria, "SINCE 4-Mar-2026");
    }

    #[test]
    fn injection_attempts_rejected() {
        let q = SearchQuery { subject: Some("x\r\nA1 DELETE INBOX".into()), ..Default::default() };
        assert_eq!(translate(&q).unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(quote("a\\b").unwrap(), r#""a\\b""#);
    }

    #[test]
    fn bad_date_rejected() {
        let q = SearchQuery { since: Some("yesterday".into()), ..Default::default() };
        assert_eq!(translate(&q).unwrap_err().code(), ErrorCode::InvalidInput);
        let q = SearchQuery { since: Some("2026-13-40".into()), ..Default::default() };
        assert!(translate(&q).is_err());
    }

    #[test]
    fn non_ascii_flags_charset_and_attachment_is_client_side() {
        let q = SearchQuery { text: Some("café".into()), has_attachment: Some(true), ..Default::default() };
        let t = translate(&q).unwrap();
        assert!(t.needs_utf8);
        assert_eq!(t.has_attachment, Some(true));
        assert_eq!(t.criteria, "TEXT \"café\"");
    }
}
