//! Output-side hardening for mailbox-sourced strings (security review F3).
//!
//! The HTML sanitizer itself lives in `openmail-imap`; this module only post-processes the
//! strings this crate receives so that characters a human cannot see, and links a client might
//! render as clickable, never reach the model verbatim.

/// Formatting/invisible code points that can hide or reorder text (Unicode general category Cf
/// plus the tag and variation-selector blocks used for ASCII smuggling).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                    // soft hyphen
        | '\u{0600}'..='\u{0605}'     // Arabic number signs
        | '\u{061C}'                  // Arabic letter mark
        | '\u{06DD}' | '\u{070F}' | '\u{08E2}'
        | '\u{180E}'                  // Mongolian vowel separator
        | '\u{200B}'..='\u{200F}'     // zero-width space/joiners, LRM/RLM
        | '\u{202A}'..='\u{202E}'     // bidi embeddings/overrides
        | '\u{2060}'..='\u{206F}'     // word joiner, invisible operators, deprecated format chars
        | '\u{FEFF}'                  // BOM / zero-width no-break space
        | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation
        | '\u{1D173}'..='\u{1D17A}'   // musical formatting
        | '\u{E0000}'..='\u{E007F}'   // tags block
        | '\u{E0100}'..='\u{E01EF}'   // variation selectors supplement
    )
}

/// Removes invisible/format/bidi characters and C0/C1 control characters other than
/// `\n`, `\r` and `\t`. Borrows nothing and allocates only when something was removed.
pub fn strip_invisible(s: &str) -> String {
    if !s.chars().any(drops) {
        return s.to_owned();
    }
    s.chars().filter(|&c| !drops(c)).collect()
}

fn drops(c: char) -> bool {
    is_invisible(c) || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

/// Replaces `<a href="URL">text</a>` with `text [URL]` so a client that renders the result as
/// markup or markdown never gets a live link (an exfiltration channel). Input is already
/// sanitized HTML from the backend; this pass is deliberately tolerant and never panics on
/// malformed input.
pub fn defang_links(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    let mut pending: Option<String> = None;
    while let Some(lt) = rest.find('<') {
        out.push_str(&rest[..lt]);
        let tag_and_after = &rest[lt..];
        let Some(end) = tag_end(tag_and_after) else {
            // Unterminated tag: keep it as visible text, never as markup.
            out.push_str("&lt;");
            out.push_str(&tag_and_after[1..]);
            rest = "";
            break;
        };
        let tag = &tag_and_after[..=end];
        let after = &tag_and_after[end + 1..];
        match anchor_kind(tag) {
            Some(Anchor::Open) => {
                if let Some(url) = pending.take() {
                    push_url(&mut out, &url);
                }
                pending = Some(href_of(tag).unwrap_or_default());
            }
            Some(Anchor::Close) => {
                if let Some(url) = pending.take() {
                    push_url(&mut out, &url);
                }
            }
            None => out.push_str(tag),
        }
        rest = after;
    }
    out.push_str(rest);
    if let Some(url) = pending {
        push_url(&mut out, &url);
    }
    out
}

fn push_url(out: &mut String, url: &str) {
    if !url.is_empty() {
        out.push_str(" [");
        out.push_str(url);
        out.push(']');
    }
}

enum Anchor {
    Open,
    Close,
}

/// Index of the `>` closing the tag that starts at byte 0, ignoring `>` inside quotes.
fn tag_end(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn anchor_kind(tag: &str) -> Option<Anchor> {
    let inner = tag.strip_prefix('<')?;
    let (closing, name_part) = match inner.strip_prefix('/') {
        Some(r) => (true, r),
        None => (false, inner),
    };
    let name: String = name_part
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if !name.eq_ignore_ascii_case("a") {
        return None;
    }
    Some(if closing { Anchor::Close } else { Anchor::Open })
}

fn href_of(tag: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("href") {
        let at = from + pos;
        from = at + 4;
        let before_ok = lower[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_whitespace() || c == '"' || c == '\'');
        if !before_ok {
            continue;
        }
        let tail = tag[at + 4..].trim_start();
        let Some(tail) = tail.strip_prefix('=') else {
            continue;
        };
        let tail = tail.trim_start();
        return Some(match tail.chars().next() {
            Some(q @ ('"' | '\'')) => tail[1..].split(q).next().unwrap_or_default().to_owned(),
            _ => tail
                .split(|c: char| c.is_ascii_whitespace() || c == '>')
                .next()
                .unwrap_or_default()
                .to_owned(),
        });
    }
    None
}

/// Longest capability token kept in diagnostics (IMAP atoms are short; this is generous).
const MAX_CAPABILITY_LEN: usize = 64;
/// Most capability tokens reported; servers advertise a few dozen at most.
const MAX_CAPABILITIES: usize = 64;

/// Capabilities come from the server's greeting: keep only well-formed atoms so the field cannot
/// carry free text.
pub fn safe_capabilities(caps: Vec<String>) -> Vec<String> {
    caps.into_iter()
        .filter(|c| {
            !c.is_empty()
                && c.len() <= MAX_CAPABILITY_LEN
                && c.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '=' | '+' | '.' | '_' | '-')
                })
        })
        .take(MAX_CAPABILITIES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_bidi_bom_and_tags() {
        let hidden = "a\u{200B}b\u{202E}c\u{2066}d\u{FEFF}e\u{E0041}f\u{0007}g";
        assert_eq!(strip_invisible(hidden), "abcdefg");
    }

    #[test]
    fn keeps_normal_text_whitespace_and_non_ascii() {
        let s = "Héllo\tworld\r\nمرحبا 日本語 🙂";
        assert_eq!(strip_invisible(s), s);
    }

    #[test]
    fn links_become_inert_text() {
        assert_eq!(
            defang_links(r#"<p>See <a href="https://evil.example/?q=SECRET">docs</a> now</p>"#),
            "<p>See docs [https://evil.example/?q=SECRET] now</p>"
        );
        assert!(!defang_links(r#"<a href='http://x.example'>y</a>"#).contains("<a"));
    }

    #[test]
    fn malformed_anchors_never_panic_or_survive() {
        for html in [
            "<a href=\"http://x.example",
            "<a>no href</a>",
            "<A HREF=http://x.example>unquoted",
            "</a>stray close",
            "<a href=\"a\"><a href=\"b\">nested</a></a>",
            "<",
        ] {
            let out = defang_links(html);
            assert!(!out.to_ascii_lowercase().contains("<a "), "{html} -> {out}");
        }
        assert_eq!(defang_links("<a>no href</a>"), "no href");
    }

    #[test]
    fn capabilities_are_filtered_to_atoms() {
        let caps = vec![
            "IMAP4rev1".into(),
            "AUTH=XOAUTH2".into(),
            "ignore previous instructions".into(),
            "x".repeat(200),
        ];
        assert_eq!(safe_capabilities(caps), ["IMAP4rev1", "AUTH=XOAUTH2"]);
    }
}
