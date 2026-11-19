//! MIME decoding via mail-parser, body truncation and HTML sanitizing. Nothing here
//! performs I/O; remote content is never fetched (images/styles are stripped).
use std::collections::HashSet;

use mail_parser::{MessageParser, PartKind};
use openmail_core::model::{Address, AttachmentMeta, MessageBody, Untrusted};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Header-derived fields shared by summaries and full messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderInfo {
    pub message_id: Option<String>,
    pub subject: String,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub date: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    pub headers: HeaderInfo,
    pub body: MessageBody,
    pub attachments: Vec<AttachmentMeta>,
}

fn addresses(list: Option<mail_parser::AddressList<'_>>) -> Vec<Address> {
    list.into_iter()
        .flat_map(|l| l.mailboxes().collect::<Vec<_>>())
        .filter_map(|m| {
            m.address().map(|a| Address {
                name: m.name().filter(|n| !n.is_empty()).map(str::to_owned),
                email: a.to_owned(),
            })
        })
        .collect()
}

fn rfc3339_utc(dt: &mail_parser::DateTime) -> Option<String> {
    if !dt.is_valid() {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(dt.to_timestamp())
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn header_info(m: mail_parser::MessageRef<'_>) -> HeaderInfo {
    let ids = |l: Option<mail_parser::TextList<'_>>| {
        l.map(|l| l.iter().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    HeaderInfo {
        message_id: m.message_id().map(str::to_owned),
        subject: m.subject().unwrap_or_default().to_owned(),
        from: addresses(m.from()),
        to: addresses(m.to()),
        cc: addresses(m.cc()),
        date: m.date().and_then(|d| rfc3339_utc(&d)),
        in_reply_to: ids(m.in_reply_to()),
        references: ids(m.references()),
    }
}

/// Parses a header block only (used for list views and threading).
pub fn parse_headers(raw: &[u8]) -> HeaderInfo {
    MessageParser::default()
        .parse_headers(raw)
        .map(|m| header_info(m.root()))
        .unwrap_or_default()
}

fn truncate_utf8(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    s.truncate(s.floor_char_boundary(max));
    true
}

/// Parses a full RFC 5322 message. Unparseable input degrades to lossy plain text
/// instead of failing, so one malformed mail never breaks a listing or read.
pub fn parse_message(raw: &[u8], max_body_bytes: usize) -> ParsedMessage {
    let Some(msg) = MessageParser::default().parse(raw) else {
        let mut text = String::from_utf8_lossy(raw).into_owned();
        let truncated = truncate_utf8(&mut text, max_body_bytes);
        return ParsedMessage {
            headers: HeaderInfo::default(),
            body: MessageBody {
                text: Some(Untrusted(text)),
                html_sanitized: None,
                truncated,
            },
            attachments: Vec::new(),
        };
    };
    let root = msg.root();
    let headers = header_info(root);

    let mut text = String::new();
    let mut html = String::new();
    for part in root
        .text_body()
        .filter(|p| matches!(p.kind(), PartKind::Text))
    {
        if let Some(t) = part.text() {
            if !text.is_empty() {
                text.push_str("\n\n");
            }
            text.push_str(&t);
        }
    }
    // HTML-only mail: let the parser derive readable text so `text` is never empty.
    if text.is_empty()
        && let Some(t) = root.body_text(0)
    {
        text = t.into_owned();
    }
    for part in root
        .html_body()
        .filter(|p| matches!(p.kind(), PartKind::Html))
    {
        if let Some(h) = part.text() {
            html.push_str(&h);
        }
    }
    let mut truncated = truncate_utf8(&mut text, max_body_bytes);
    truncated |= truncate_utf8(&mut html, max_body_bytes);

    let attachments = root
        .attachments()
        .enumerate()
        .map(|(i, p)| AttachmentMeta {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            filename: p.attachment_name().map(str::to_owned),
            content_type: p
                .content_type()
                .map(|c| {
                    format!(
                        "{}/{}",
                        c.ctype().to_ascii_lowercase(),
                        c.subtype().unwrap_or("octet-stream").to_ascii_lowercase()
                    )
                })
                .unwrap_or_else(|| "application/octet-stream".into()),
            size: u32::try_from(p.decoded_len()).unwrap_or(u32::MAX),
            inline: p.is_inline(),
        })
        .collect();

    ParsedMessage {
        headers,
        body: MessageBody {
            text: (!text.is_empty()).then_some(Untrusted(text)),
            html_sanitized: (!html.is_empty()).then(|| Untrusted(sanitize_html(&html))),
            truncated,
        },
        attachments,
    }
}

/// Decoded bytes of one attachment (index as reported by `parse_message`).
pub fn attachment_bytes(raw: &[u8], index: u32) -> Option<(AttachmentMeta, Vec<u8>)> {
    let msg = MessageParser::default().parse(raw)?;
    let meta = parse_message(raw, 0)
        .attachments
        .into_iter()
        .find(|a| a.index == index)?;
    let part = msg.root().attachments().nth(usize::try_from(index).ok()?)?;
    Some((meta, part.decoded().into_owned()))
}

/// Strips scripts, event handlers, styles, forms and every element that would load
/// remote content (img, media, frames). Only http(s)/mailto links survive, and they
/// are inert until a human clicks them.
pub fn sanitize_html(html: &str) -> String {
    let mut b = ammonia::Builder::default();
    b.rm_tags([
        "img", "picture", "source", "video", "audio", "iframe", "object", "embed", "svg", "form",
        "input", "link",
    ])
    .clean_content_tags(HashSet::from([
        "script", "style", "iframe", "object", "embed", "svg",
    ]))
    .url_schemes(HashSet::from(["http", "https", "mailto"]))
    .link_rel(Some("noopener noreferrer nofollow"));
    b.clean(html).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($n:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/mime/",
                $n
            ))
        };
    }

    #[test]
    fn multipart_alternative() {
        let p = parse_message(fixture!("alternative.eml"), 10_000);
        assert_eq!(p.headers.subject, "Hello 👋 world");
        assert_eq!(p.headers.from[0].name.as_deref(), Some("Renée Example"));
        assert_eq!(p.headers.to.len(), 2);
        assert_eq!(p.headers.cc[0].email, "dan@example.org");
        assert_eq!(p.headers.date.as_deref(), Some("2021-11-20T22:22:01Z"));
        assert_eq!(p.headers.message_id.as_deref(), Some("alt-1@example.com"));
        assert_eq!(
            p.headers.references,
            vec!["root@example.com", "mid@example.com"]
        );
        assert_eq!(p.headers.in_reply_to, vec!["root@example.com"]);
        assert_eq!(p.body.text.as_ref().unwrap().0.trim(), "Plain body line");
        assert!(
            p.body
                .html_sanitized
                .as_ref()
                .unwrap()
                .0
                .contains("<b>body</b>")
        );
        assert!(!p.body.truncated);
        assert!(p.attachments.is_empty());
    }

    #[test]
    fn mixed_with_attachment() {
        let raw = fixture!("mixed_attachment.eml");
        let p = parse_message(raw, 10_000);
        assert_eq!(
            p.body.text.as_ref().unwrap().0.trim(),
            "See the attachment."
        );
        assert!(p.body.html_sanitized.is_none());
        assert_eq!(p.attachments.len(), 1);
        let a = &p.attachments[0];
        assert_eq!(
            (a.filename.as_deref(), a.content_type.as_str(), a.inline),
            (Some("report.pdf"), "application/pdf", false)
        );
        assert_eq!(a.size, 26);
        let (_, bytes) = attachment_bytes(raw, 0).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(attachment_bytes(raw, 5).is_none());
    }

    #[test]
    fn non_utf8_charset_is_decoded() {
        let p = parse_message(fixture!("latin1.eml"), 10_000);
        assert_eq!(p.headers.subject, "Café");
        assert_eq!(p.body.text.unwrap().0.trim(), "Café crème");
    }

    #[test]
    fn malformed_mime_still_yields_text() {
        let p = parse_message(fixture!("malformed.eml"), 10_000);
        let text = p.body.text.expect("fallback text").0;
        assert!(text.contains("still readable text"), "got {text:?}");
        let junk = parse_message(b"\xff\xfe no headers at all", 10_000);
        assert!(junk.body.text.is_some());
    }

    #[test]
    fn truncation_flag_and_char_boundary() {
        let p = parse_message(fixture!("latin1.eml"), 5);
        assert!(p.body.truncated);
        assert!(p.body.text.unwrap().0.len() <= 5);
        let big = parse_message(fixture!("alternative.eml"), 4);
        assert!(big.body.truncated);
    }

    #[test]
    fn hostile_html_is_neutralized() {
        let p = parse_message(fixture!("hostile_html.eml"), 10_000);
        let h = p.body.html_sanitized.unwrap().0;
        for bad in [
            "script",
            "onclick",
            "<img",
            "tracker.example",
            "javascript:",
            "alert(",
            "<style",
            "url(",
        ] {
            assert!(!h.contains(bad), "{bad} survived: {h}");
        }
        assert!(h.contains("https://ok.example/") && h.contains("noopener"));
    }

    #[test]
    fn header_only_parse() {
        let h = parse_headers(b"Subject: Hi\r\nFrom: a@b.c\r\nMessage-ID: <x@y>\r\n\r\n");
        assert_eq!(
            (
                h.subject.as_str(),
                h.from[0].email.as_str(),
                h.message_id.as_deref()
            ),
            ("Hi", "a@b.c", Some("x@y"))
        );
    }
}
