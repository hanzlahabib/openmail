//! Locating and decoding one MIME part without downloading the whole message.
//!
//! Attachment indices are defined by the message parser (`mime::parse_message`),
//! whose classification of "attachment" (RFC 8621 semantics) cannot be reproduced
//! from BODYSTRUCTURE by hand without drifting. Instead a body-less *skeleton* of
//! the message (same nesting, content types, dispositions and content ids, one
//! leaf body = the leaf's ordinal) is rendered from BODYSTRUCTURE and run through
//! the same parser. Classification depends on structure and headers, never on
//! content, so the index maps to exactly one IMAP section.
use async_imap::imap_proto::{BodyContentCommon, BodyParams, BodyStructure, ContentEncoding};
use mail_parser::MessageParser;
use openmail_core::model::AttachmentMeta;

use crate::hygiene::clean_line;

/// Hostile servers can send arbitrarily deep structures; bound the walk.
const MAX_DEPTH: usize = 16;
/// Upper bound on leaves rendered into the skeleton.
const MAX_LEAVES: usize = 2_000;

/// Transfer encodings the decoder understands; anything else is treated as identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Identity,
    Base64,
    QuotedPrintable,
}

impl Encoding {
    fn from_proto(e: &ContentEncoding<'_>) -> Self {
        match e {
            ContentEncoding::Base64 => Self::Base64,
            ContentEncoding::QuotedPrintable => Self::QuotedPrintable,
            _ => Self::Identity,
        }
    }

    fn header(self) -> &'static str {
        match self {
            Self::Identity => "binary",
            Self::Base64 => "base64",
            Self::QuotedPrintable => "quoted-printable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Located {
    /// IMAP section path, e.g. `[2, 1]` for `BODY[2.1]`.
    pub section: Vec<u32>,
    /// Encoded size reported by the server.
    pub octets: u32,
    pub encoding: Encoding,
    /// `size` is filled by the caller once the bytes are decoded.
    pub meta: AttachmentMeta,
}

struct Leaf {
    section: Vec<u32>,
    octets: u32,
    encoding: Encoding,
}

fn param_text(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect()
}

fn params(p: &BodyParams<'_>) -> String {
    p.as_ref()
        .map(|v| {
            v.iter()
                .filter(|(k, _)| {
                    k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.*".contains(c))
                })
                .map(|(k, val)| format!("; {k}=\"{}\"", param_text(val)))
                .collect()
        })
        .unwrap_or_default()
}

fn common_headers(common: &BodyContentCommon<'_>, content_type: Option<String>) -> String {
    let ty = content_type.unwrap_or_else(|| {
        format!(
            "{}/{}{}",
            param_text(&common.ty.ty),
            param_text(&common.ty.subtype),
            params(&common.ty.params)
        )
    });
    let mut h = format!("Content-Type: {ty}\r\n");
    if let Some(d) = &common.disposition {
        h.push_str(&format!(
            "Content-Disposition: {}{}\r\n",
            param_text(&d.ty),
            params(&d.params)
        ));
    }
    h
}

struct Skeleton {
    text: String,
    leaves: Vec<Leaf>,
    boundaries: usize,
}

impl Skeleton {
    fn leaf(
        &mut self,
        common: &BodyContentCommon<'_>,
        other: &async_imap::imap_proto::BodyContentSinglePart<'_>,
        section: Vec<u32>,
        content_type: Option<String>,
    ) {
        let ordinal = self.leaves.len();
        self.text.push_str(&common_headers(common, content_type));
        if let Some(id) = &other.id {
            self.text
                .push_str(&format!("Content-ID: {}\r\n", param_text(id)));
        }
        self.text.push_str(&format!(
            "Content-Transfer-Encoding: 7bit\r\n\r\n{ordinal}\r\n"
        ));
        self.leaves.push(Leaf {
            section,
            octets: other.octets,
            encoding: Encoding::from_proto(&other.transfer_encoding),
        });
    }

    /// Returns false when the structure exceeds the safety bounds.
    fn node(&mut self, bs: &BodyStructure<'_>, section: Vec<u32>, depth: usize) -> bool {
        if depth > MAX_DEPTH || self.leaves.len() > MAX_LEAVES {
            return false;
        }
        match bs {
            BodyStructure::Multipart { common, bodies, .. } => {
                self.boundaries += 1;
                let b = format!("om-skel-{}", self.boundaries);
                self.text.push_str(&common_headers(
                    common,
                    Some(format!(
                        "multipart/{}; boundary=\"{b}\"",
                        param_text(&common.ty.subtype)
                    )),
                ));
                self.text.push_str("\r\n");
                for (i, child) in bodies.iter().enumerate() {
                    self.text.push_str(&format!("--{b}\r\n"));
                    let mut path = section.clone();
                    path.push(u32::try_from(i + 1).unwrap_or(u32::MAX));
                    if !self.node(child, path, depth + 1) {
                        return false;
                    }
                }
                self.text.push_str(&format!("--{b}--\r\n"));
            }
            BodyStructure::Basic { common, other, .. }
            | BodyStructure::Text { common, other, .. } => {
                self.leaf(common, other, section, None);
            }
            BodyStructure::Message { common, other, .. } => {
                // A nested message is a single downloadable part; its body is never
                // descended into (and must not be re-parsed as a message by the skeleton).
                self.leaf(
                    common,
                    other,
                    section,
                    Some("application/x-om-message".into()),
                );
            }
        }
        true
    }
}

/// Finds the section holding attachment `index` (numbering as in `mime::parse_message`).
pub fn locate(bs: &BodyStructure<'_>, index: u32) -> Option<Located> {
    let mut sk = Skeleton {
        text: String::from("MIME-Version: 1.0\r\n"),
        leaves: Vec::new(),
        boundaries: 0,
    };
    // A non-multipart message body is section 1.
    let root_path = if matches!(bs, BodyStructure::Multipart { .. }) {
        Vec::new()
    } else {
        vec![1]
    };
    if !sk.node(bs, root_path, 0) {
        return None;
    }
    let msg = MessageParser::default().parse(sk.text.as_bytes())?;
    let part = msg.root().attachments().nth(usize::try_from(index).ok()?)?;
    let ordinal: usize = std::str::from_utf8(&part.decoded())
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let leaf = sk.leaves.get(ordinal)?;
    let meta = AttachmentMeta {
        index,
        filename: part
            .attachment_name()
            .map(clean_line)
            .filter(|n| !n.is_empty()),
        content_type: part
            .content_type()
            .map(|c| {
                format!(
                    "{}/{}",
                    c.ctype().to_ascii_lowercase(),
                    c.subtype().unwrap_or("octet-stream").to_ascii_lowercase()
                )
            })
            .unwrap_or_else(|| "application/octet-stream".into()),
        size: 0,
        inline: part.is_inline(),
    };
    Some(Located {
        section: leaf.section.clone(),
        octets: leaf.octets,
        encoding: leaf.encoding,
        meta,
    })
}

/// Reverses the part's Content-Transfer-Encoding.
pub fn decode(raw: &[u8], encoding: Encoding) -> Option<Vec<u8>> {
    let mut wrapped = format!(
        "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: {}\r\n\r\n",
        encoding.header()
    )
    .into_bytes();
    wrapped.extend_from_slice(raw);
    let msg = MessageParser::default().parse(&wrapped)?;
    Some(msg.root_part().decoded().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_and_identity() {
        assert_eq!(
            decode(b"JVBERi0xLjQK", Encoding::Base64).unwrap(),
            b"%PDF-1.4\n"
        );
        assert_eq!(decode(b"abc", Encoding::Identity).unwrap(), b"abc");
        assert_eq!(decode(b"a=3Db", Encoding::QuotedPrintable).unwrap(), b"a=b");
    }
}
