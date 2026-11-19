//! Send request model, validation and the canonical content hash.
use openmail_core::model::Address;
use openmail_core::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};

use crate::approval::ContentHash;

/// Default total message cap. 25 MiB is the common SMTP relay ceiling
/// (Gmail/Outlook); base64 expansion makes anything larger fail remotely anyway.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 25 * 1024 * 1024;
/// Default per-attachment cap; keeps one oversized file from eating the whole budget.
pub const DEFAULT_MAX_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;
/// Default recipient cap across To/Cc/Bcc; bounds accidental mass mailing.
pub const DEFAULT_MAX_RECIPIENTS: usize = 50;
/// Idempotency keys are stored and logged; bound them.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpLimits {
    pub max_attachment_bytes: usize,
    /// Sum of body text, HTML and all attachment bytes (before MIME encoding).
    pub max_total_bytes: usize,
    pub max_recipients: usize,
}

impl Default for SmtpLimits {
    fn default() -> Self {
        Self {
            max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

// Manual Debug: never print attachment bytes.
impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field("bytes", &self.data.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SendRequest {
    /// Caller-chosen, unique per intended message. Repeating it never re-sends an
    /// accepted or uncertain message.
    pub idempotency_key: String,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    /// Message-ID of the message being replied to, with angle brackets.
    pub in_reply_to: Option<String>,
    /// Thread ancestry, oldest first, each with angle brackets.
    pub references: Vec<String>,
}

// Manual Debug: bodies and recipients' content stay out of logs.
impl std::fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendRequest")
            .field("idempotency_key", &self.idempotency_key)
            .field("recipients", &self.recipient_count())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, msg)
}

fn has_ctl(s: &str) -> bool {
    s.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
}

impl SendRequest {
    pub fn recipient_count(&self) -> usize {
        self.to.len() + self.cc.len() + self.bcc.len()
    }

    pub fn validate(&self, limits: &SmtpLimits) -> Result<()> {
        let key = &self.idempotency_key;
        if key.is_empty()
            || key.len() > MAX_IDEMPOTENCY_KEY_LEN
            || !key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid(
                "idempotency_key must be 1-128 printable ASCII characters",
            ));
        }
        if self.to.is_empty() && self.cc.is_empty() && self.bcc.is_empty() {
            return Err(invalid("at least one recipient is required"));
        }
        if self.recipient_count() > limits.max_recipients {
            return Err(Error::new(
                ErrorCode::LimitExceeded,
                format!("more than {} recipients", limits.max_recipients),
            ));
        }
        if has_ctl(&self.subject) {
            return Err(invalid("subject must not contain line breaks"));
        }
        if self.text.is_none() && self.html.is_none() {
            return Err(invalid("message needs a text or html body"));
        }
        for a in self.all_addresses() {
            if has_ctl(&a.email) || a.name.as_deref().is_some_and(has_ctl) {
                return Err(invalid(
                    "addresses and display names must not contain line breaks",
                ));
            }
        }
        for id in self.in_reply_to.iter().chain(&self.references) {
            if !is_message_id(id) {
                return Err(invalid(
                    "In-Reply-To/References entries must look like <id@host>",
                ));
            }
        }
        let mut total =
            self.text.as_ref().map_or(0, String::len) + self.html.as_ref().map_or(0, String::len);
        for a in &self.attachments {
            if has_ctl(&a.filename) || has_ctl(&a.content_type) || a.filename.is_empty() {
                return Err(invalid("attachment filename/content type invalid"));
            }
            if a.data.len() > limits.max_attachment_bytes {
                return Err(Error::new(
                    ErrorCode::LimitExceeded,
                    format!(
                        "attachment '{}' exceeds {} bytes",
                        a.filename, limits.max_attachment_bytes
                    ),
                ));
            }
            total += a.data.len();
        }
        if total > limits.max_total_bytes {
            return Err(Error::new(
                ErrorCode::LimitExceeded,
                format!("message exceeds {} bytes", limits.max_total_bytes),
            ));
        }
        Ok(())
    }

    fn all_addresses(&self) -> impl Iterator<Item = &Address> {
        std::iter::once(&self.from)
            .chain(&self.to)
            .chain(&self.cc)
            .chain(&self.bcc)
    }

    /// Canonical hash of everything that defines the message. Excludes the idempotency
    /// key (it names the intent, not the content) and the generated Message-ID.
    /// Addresses are lower-cased so equivalent requests hash alike.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        let mut field = |bytes: &[u8]| {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        };
        field(b"openmail-smtp/content/v1");
        let addr = |tag: &[u8], list: &[Address], field: &mut dyn FnMut(&[u8])| {
            field(tag);
            field(&(list.len() as u64).to_be_bytes());
            for a in list {
                field(a.name.as_deref().unwrap_or("").as_bytes());
                field(a.email.to_lowercase().as_bytes());
            }
        };
        addr(b"from", std::slice::from_ref(&self.from), &mut field);
        addr(b"to", &self.to, &mut field);
        addr(b"cc", &self.cc, &mut field);
        addr(b"bcc", &self.bcc, &mut field);
        field(self.subject.as_bytes());
        for body in [&self.text, &self.html] {
            field(&[u8::from(body.is_some())]);
            field(body.as_deref().unwrap_or("").as_bytes());
        }
        field(self.in_reply_to.as_deref().unwrap_or("").as_bytes());
        field(&(self.references.len() as u64).to_be_bytes());
        for r in &self.references {
            field(r.as_bytes());
        }
        field(&(self.attachments.len() as u64).to_be_bytes());
        for a in &self.attachments {
            field(a.filename.as_bytes());
            field(a.content_type.as_bytes());
            field(Sha256::digest(&a.data).as_slice());
        }
        ContentHash::from_digest(h)
    }
}

/// `<local@host>` with no whitespace/controls; deliberately lenient on the inner
/// syntax because real-world Message-IDs are messy.
fn is_message_id(s: &str) -> bool {
    s.len() > 2
        && s.len() <= 998
        && s.starts_with('<')
        && s.ends_with('>')
        && s.contains('@')
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> SendRequest {
        SendRequest {
            idempotency_key: "k1".into(),
            from: Address {
                name: Some("Me".into()),
                email: "me@example.com".into(),
            },
            to: vec![Address {
                name: None,
                email: "you@example.org".into(),
            }],
            cc: vec![],
            bcc: vec![],
            subject: "Hi".into(),
            text: Some("hello".into()),
            html: None,
            attachments: vec![],
            in_reply_to: None,
            references: vec![],
        }
    }

    #[test]
    fn valid_request_passes() {
        assert!(sample().validate(&SmtpLimits::default()).is_ok());
    }

    #[test]
    fn hash_ignores_key_and_address_case_but_tracks_content() {
        let a = sample();
        let mut b = sample();
        b.idempotency_key = "other".into();
        b.to[0].email = "YOU@example.org".into();
        assert_eq!(a.content_hash(), b.content_hash());
        b.text = Some("hello!".into());
        assert_ne!(a.content_hash(), b.content_hash());
        let mut c = sample();
        c.bcc.push(Address {
            name: None,
            email: "x@y.z".into(),
        });
        assert_ne!(
            a.content_hash(),
            c.content_hash(),
            "bcc must be bound by approval"
        );
    }

    #[test]
    fn hash_field_boundaries_are_unambiguous() {
        let mut a = sample();
        let mut b = sample();
        a.subject = "ab".into();
        a.text = Some("c".into());
        b.subject = "a".into();
        b.text = Some("bc".into());
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn rejects_header_injection_and_limits() {
        let l = SmtpLimits::default();
        let mut r = sample();
        r.subject = "x\r\nBcc: evil@x.y".into();
        assert_eq!(r.validate(&l).unwrap_err().code(), ErrorCode::InvalidInput);
        let mut r = sample();
        r.to[0].name = Some("a\nb".into());
        assert_eq!(r.validate(&l).unwrap_err().code(), ErrorCode::InvalidInput);
        let mut r = sample();
        r.to = (0..51)
            .map(|i| Address {
                name: None,
                email: format!("u{i}@x.y"),
            })
            .collect();
        assert_eq!(r.validate(&l).unwrap_err().code(), ErrorCode::LimitExceeded);
        let mut r = sample();
        r.attachments.push(Attachment {
            filename: "a.bin".into(),
            content_type: "application/octet-stream".into(),
            data: vec![0; 11],
        });
        let tight = SmtpLimits {
            max_attachment_bytes: 10,
            ..SmtpLimits::default()
        };
        assert_eq!(
            r.validate(&tight).unwrap_err().code(),
            ErrorCode::LimitExceeded
        );
        let mut r = sample();
        r.in_reply_to = Some("not-an-id".into());
        assert_eq!(r.validate(&l).unwrap_err().code(), ErrorCode::InvalidInput);
        let mut r = sample();
        r.idempotency_key = String::new();
        assert!(r.validate(&l).is_err());
    }
}
