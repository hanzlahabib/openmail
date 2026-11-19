//! Property tests for MIME parsing and HTML sanitizing: arbitrary input must never
//! panic, never exceed the body cap, never leak invisible/bidi characters and never
//! yield active or remote-loading HTML.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use base64::{Engine, engine::general_purpose::STANDARD};
use openmail_imap::html;
use openmail_imap::mime::{attachment_bytes, parse_headers, parse_message};
use proptest::prelude::*;
use unicode_general_category::{GeneralCategory, get_general_category};

fn is_invisible(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Format | GeneralCategory::PrivateUse | GeneralCategory::Unassigned
    )
}

fn assert_clean_line(s: &str, what: &str) {
    for c in s.chars() {
        assert!(
            !is_invisible(c) && !c.is_control(),
            "{what} contains U+{:04X}: {s:?}",
            c as u32
        );
    }
}

fn assert_clean_body(s: &str, what: &str) {
    for c in s.chars() {
        assert!(
            matches!(c, '\n' | '\r' | '\t') || !(is_invisible(c) || c.is_control()),
            "{what} contains U+{:04X}",
            c as u32
        );
    }
}

/// Characters that are invisible or bidi-controlling, mixed with ordinary text.
fn hostile_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => prop::char::range('a', 'z'),
        1 => prop::sample::select(vec![
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}',
            '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{2060}', '\u{FEFF}', '\u{00AD}', '\u{E0041}', '\u{E007F}', '\u{E000}', '\u{0378}',
            '\u{0000}', '\u{0007}', '\u{0085}',
        ]),
    ]
}

fn hostile_text() -> impl Strategy<Value = String> {
    prop::collection::vec(hostile_char(), 0..40).prop_map(|v| v.into_iter().collect())
}

const HTML_TOKENS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script src=//evil.example/x.js></script>",
    "<img src=http://t.example/p.gif>",
    "<img src=\"cid:x\" onerror=\"alert(1)\">",
    "<iframe src=\"https://e.example\"></iframe>",
    "<a href=\"https://x.example/\">link</a>",
    "<a href=\"javascript:alert(1)\">js</a>",
    "<style>@import url(http://x.example/a.css);</style>",
    "<svg onload=alert(1)><image href=http://x.example/i.png></svg>",
    "<div style=\"background:url(http://x.example/b.png)\">d</div>",
    "<link rel=stylesheet href=http://x.example/s.css>",
    "<object data=http://x.example/o></object>",
    "<embed src=http://x.example/e>",
    "<form action=http://x.example><input name=q></form>",
    "<video src=http://x.example/v><source src=http://x.example/v2></video>",
    "<meta http-equiv=refresh content=\"0;url=http://x.example\">",
    "<base href=http://x.example/>",
    "<p>",
    "</p>",
    "<b>",
    "</b>",
    "<div hidden>H</div>",
    "<table><tr><td>",
    "</td></tr></table>",
    "<",
    ">",
    "<b",
    "&amp;",
    "&lt;script&gt;",
    "&#x202E;",
    "&",
    "\"",
    "'",
    "<!--",
    "-->",
    "<![CDATA[",
    "text",
    " ",
    "\n",
];

fn html_soup() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            4 => prop::sample::select(HTML_TOKENS.to_vec()).prop_map(str::to_owned),
            1 => any::<String>(),
            1 => hostile_text(),
        ],
        0..30,
    )
    .prop_map(|v| v.concat())
}

/// Scans serialized HTML for tag/attribute content; ammonia escapes `<` in text, so a
/// raw `<` always opens a tag.
fn assert_inert_html(out: &str) {
    let lower = out.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        let close = after.find('>').unwrap_or(after.len());
        let tag = &after[..close];
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        assert!(
            !matches!(
                name.as_str(),
                "script"
                    | "img"
                    | "iframe"
                    | "style"
                    | "svg"
                    | "object"
                    | "embed"
                    | "form"
                    | "input"
                    | "link"
                    | "meta"
                    | "base"
                    | "video"
                    | "audio"
                    | "source"
                    | "picture"
                    | "a"
                    | "template"
                    | "noscript"
            ),
            "active/remote tag <{name}> survived: {out}"
        );
        for attr in [
            "src",
            "srcset",
            "href",
            "style",
            "action",
            "data",
            "background",
            "poster",
        ] {
            assert!(
                !tag.contains(&format!("{attr}=")),
                "attribute {attr} survived in <{tag}>: {out}"
            );
        }
        assert!(
            !tag.contains("http:") && !tag.contains("https:") && !tag.contains("//"),
            "remote URL inside tag <{tag}>"
        );
        assert!(
            !tag.contains("javascript:") && !tag.contains(" on"),
            "handler in <{tag}>"
        );
        rest = &after[close..];
    }
}

fn wrap(content_type: &str, body: &str) -> Vec<u8> {
    format!("From: a@b.c\r\nSubject: s\r\nContent-Type: {content_type}\r\n\r\n{body}").into_bytes()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn parse_never_panics_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..4096),
        max in 0usize..2048,
    ) {
        let _ = parse_headers(&raw);
        let p = parse_message(&raw, max);
        for a in &p.attachments {
            let _ = attachment_bytes(&raw, a.index);
        }
    }

    #[test]
    fn parse_never_panics_on_header_shaped_bytes(
        raw in "([A-Za-z-]{1,15}: [ -~]{0,40}\\r?\\n|--[a-z]{1,4}\\r?\\n|\\r?\\n|=\\?[a-z0-9-]{1,8}\\?[BbQq]\\?[ -~]{0,12}\\?=){0,40}",
    ) {
        let _ = parse_message(raw.as_bytes(), 512);
    }

    #[test]
    fn text_body_never_exceeds_cap(body in "[ -~\\n]{0,3000}", max in 0usize..1500) {
        let p = parse_message(&wrap("text/plain; charset=utf-8", &body), max);
        if let Some(t) = &p.body.text {
            prop_assert!(t.0.len() <= max, "text {} > cap {}", t.0.len(), max);
        }
        // ASCII input is kept verbatim, so content longer than the cap must be flagged.
        if body.trim().len() > max {
            prop_assert!(p.body.truncated, "cut text was not flagged truncated");
        }
    }

    #[test]
    fn multibyte_text_is_cut_on_char_boundaries(s in "[é世🙂a]{0,500}", max in 0usize..300) {
        let p = parse_message(&wrap("text/plain; charset=utf-8", &s), max);
        if let Some(t) = &p.body.text {
            prop_assert!(t.0.len() <= max);
            prop_assert!(s.contains(t.0.as_str()), "kept text is not a slice of the input");
        }
    }

    #[test]
    fn html_body_never_exceeds_cap(h in html_soup(), max in 0usize..2000) {
        let p = parse_message(&wrap("text/html; charset=utf-8", &h), max);
        if let Some(t) = &p.body.text {
            prop_assert!(t.0.len() <= max, "text {} > cap {}", t.0.len(), max);
        }
        if let Some(s) = &p.body.html_sanitized {
            prop_assert!(s.0.len() <= max, "sanitized html {} > cap {}: {:?}", s.0.len(), max, s.0);
        }
    }

    #[test]
    fn sanitized_html_is_inert(h in html_soup()) {
        assert_inert_html(&html::sanitize(&h));
    }

    #[test]
    fn sanitized_html_via_message_is_inert(h in html_soup()) {
        let p = parse_message(&wrap("text/html; charset=utf-8", &h), 1 << 20);
        if let Some(s) = &p.body.html_sanitized {
            assert_inert_html(&s.0);
        }
    }

    #[test]
    fn sanitize_and_to_text_never_panic(h in any::<String>()) {
        let _ = html::sanitize(&h);
        let _ = html::to_text(&h);
    }

    #[test]
    fn sanitized_html_has_no_invisible_characters(
        parts in prop::collection::vec(hostile_text(), 1..6),
    ) {
        let h = format!("<p>{}</p>", parts.join("</p><p>&#x202E;&#x200B;"));
        let p = parse_message(&wrap("text/html; charset=utf-8", &h), 1 << 20);
        if let Some(s) = &p.body.html_sanitized {
            assert_clean_body(&s.0, "sanitized html");
        }
    }

    #[test]
    fn html_text_projection_has_no_invisible_characters(h in html_soup()) {
        let p = parse_message(&wrap("text/html; charset=utf-8", &h), 1 << 20);
        if let Some(t) = &p.body.text {
            assert_clean_body(&t.0, "html-derived text");
        }
    }

    #[test]
    fn headers_and_text_never_emit_invisible_characters(
        subject in hostile_text(),
        name in hostile_text(),
        body in hostile_text(),
        file in hostile_text(),
    ) {
        let raw = format!(
            "From: \"{name}\" <a{name}@example.com>\r\nTo: <t@example.com>\r\nSubject: {subject}\r\n\
             Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n--B\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"{file}\"\r\n\r\nxx\r\n--B--\r\n"
        );
        let p = parse_message(raw.as_bytes(), 1 << 20);
        assert_clean_line(&p.headers.subject, "subject");
        for a in p.headers.from.iter().chain(&p.headers.to) {
            assert_clean_line(&a.email, "email");
            if let Some(n) = &a.name {
                assert_clean_line(n, "display name");
            }
        }
        if let Some(t) = &p.body.text {
            assert_clean_body(&t.0, "text body");
        }
        for a in &p.attachments {
            if let Some(f) = &a.filename {
                assert_clean_line(f, "attachment filename");
            }
        }
    }

    #[test]
    fn rfc2047_encoded_subjects_are_cleaned(subject in hostile_text()) {
        let enc = STANDARD.encode(subject.as_bytes());
        let raw = format!("From: a@b.c\r\nSubject: =?utf-8?B?{enc}?=\r\n\r\nx");
        let p = parse_message(raw.as_bytes(), 1000);
        assert_clean_line(&p.headers.subject, "encoded subject");
        assert_clean_line(&parse_headers(raw.as_bytes()).subject, "encoded subject (headers)");
    }
}
