//! Text hygiene for attacker-controlled strings (subjects, names, filenames, bodies,
//! server error text): invisible/format/bidi characters are the carrier for hidden
//! prompt-injection payloads and spoofed filenames, so they never reach the client.
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

/// Cf (format) covers ZWSP/ZWJ, bidi controls, BOM, word-joiners and the U+E0000 tag
/// block; Co/Cn (private-use/unassigned) are also dropped as they have no legitimate
/// mail-text role and are used for tag smuggling.
fn is_invisible(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Format | GeneralCategory::PrivateUse | GeneralCategory::Unassigned
    )
}

/// Single-line fields: also drops every control character (incl. CR/LF/NUL/TAB).
pub fn clean_line(s: &str) -> String {
    s.nfc()
        .filter(|&c| !is_invisible(c) && !c.is_control())
        .collect()
}

/// Multi-line bodies: keeps `\n`, `\r` and `\t` but drops other controls and invisibles.
pub fn clean_body(s: &str) -> String {
    s.nfc()
        .filter(|&c| matches!(c, '\n' | '\r' | '\t') || !(is_invisible(c) || c.is_control()))
        .collect()
}

/// Bounded, single-line rendering of text controlled by a remote server.
pub fn bounded_remote_text(s: &str, max_chars: usize) -> String {
    clean_line(s).chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_invisible_bidi_and_tag_characters() {
        let hostile = "pay\u{200B}ment\u{202E}fdp.exe\u{2066}x\u{FEFF}\u{E0041}\u{E0067}!";
        assert_eq!(clean_line(hostile), "paymentfdp.exex!");
        assert_eq!(clean_line("a\r\nb\0c"), "abc");
    }

    #[test]
    fn body_keeps_newlines_and_normalises_nfc() {
        assert_eq!(clean_body("a\u{200D}\nb\u{0000}\tc"), "a\nb\tc");
        // 'e' + combining acute composes to the single code point U+00E9.
        assert_eq!(clean_body("cafe\u{301}"), "caf\u{e9}");
    }

    #[test]
    fn remote_text_is_bounded_and_single_line() {
        let s = format!("x\n{}", "y".repeat(500));
        let out = bounded_remote_text(&s, 200);
        assert_eq!(out.chars().count(), 200);
        assert!(!out.contains('\n'));
    }
}
