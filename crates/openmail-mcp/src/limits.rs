//! Result-size caps. Constants are fixed here, not configurable per call.

/// Folder lists above this are cut and flagged; accounts with more folders are rare and
/// an unbounded list would blow a model's context.
pub const MAX_FOLDERS: usize = 500;
/// Thread results above this are cut and flagged.
pub const MAX_THREAD_MESSAGES: usize = 200;
/// Default page size when the caller gives no `limit`.
pub const DEFAULT_PAGE_SIZE: u32 = 20;

/// Largest attachment returned inline (base64 inflates by a third and the whole result lands in
/// a model's context, so this is far below what mail servers accept).
pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
/// Draft/forward text bodies above this are refused: 1 MiB of text is already far beyond a
/// human-reviewable message and bounds hashing and APPEND work.
pub const MAX_DRAFT_BODY_BYTES: usize = 1024 * 1024;
/// RFC 5322 line limit for a header such as Subject.
pub const MAX_SUBJECT_CHARS: usize = 998;
/// Same ceiling the approval binding accepts (openmail-security).
pub const MAX_RECIPIENTS: usize = 100;

/// Cut `s` to at most `max` bytes on a char boundary. Returns whether it was cut.
pub fn truncate_utf8(mut s: String, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    (s, true)
}

#[cfg(test)]
mod tests {
    use super::truncate_utf8;

    #[test]
    fn truncates_on_char_boundary() {
        let (s, cut) = truncate_utf8("aé".repeat(3), 4);
        assert!(cut);
        assert_eq!(s, "aéa");
    }

    #[test]
    fn short_strings_untouched() {
        assert_eq!(truncate_utf8("abc".into(), 3), ("abc".into(), false));
    }
}
