//! Modified UTF-7 mailbox names (RFC 3501 §5.1.3). async-imap passes names through
//! verbatim, so non-ASCII folder names must be converted here.
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};

pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&STANDARD_NO_PAD.encode(bytes).replace('/', ","));
        out.push('-');
        pending.clear();
    };
    for c in name.chars() {
        if ('\u{20}'..='\u{7e}').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Lenient decode: malformed sequences are kept literally rather than failing a LIST.
pub fn decode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('-') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let chunk = &after[..end];
        if chunk.is_empty() {
            out.push('&');
        } else if let Some(s) = decode_chunk(chunk) {
            out.push_str(&s);
        } else {
            out.push_str(&rest[start..start + end + 2]);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn decode_chunk(chunk: &str) -> Option<String> {
    let bytes = STANDARD_NO_PAD.decode(chunk.replace(',', "/")).ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]])).collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_examples() {
        assert_eq!(encode("~peter/mail/台北/日本語"), "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
        assert_eq!(decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-"), "~peter/mail/台北/日本語");
    }

    #[test]
    fn ampersand_and_ascii() {
        assert_eq!(encode("A&B"), "A&-B");
        assert_eq!(decode("A&-B"), "A&B");
        assert_eq!(encode("INBOX/Sub"), "INBOX/Sub");
    }

    #[test]
    fn roundtrip_with_astral() {
        for s in ["Entwürfe", "😀 inbox", "a&é&b"] {
            assert_eq!(decode(&encode(s)), s);
        }
    }

    #[test]
    fn malformed_is_kept() {
        assert_eq!(decode("bad&"), "bad&");
        assert_eq!(decode("x&!!!-y"), "x&!!!-y");
    }
}
