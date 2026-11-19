//! RFC 5322 message construction on top of lettre's builder. Bcc recipients go into
//! the SMTP envelope only; they never appear in any header.
use lettre::Message;
use lettre::address::{Address as LettreAddress, Envelope};
use lettre::message::header::ContentType;
use lettre::message::{Attachment as MimeAttachment, Mailbox, MultiPart, SinglePart};
use openmail_core::model::Address;
use openmail_core::{Error, ErrorCode, Result};

use crate::request::SendRequest;

/// A fully built message plus the envelope to hand to the SMTP session.
#[derive(Debug)]
pub struct BuiltMessage {
    pub raw: Vec<u8>,
    pub envelope: Envelope,
    pub message_id: String,
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, msg)
}

fn parse_address(email: &str) -> Result<LettreAddress> {
    // Error text intentionally omits nothing sensitive: addresses are not secrets, but keep it terse.
    let bad = || invalid(format!("invalid email address '{email}'"));
    // Punycode the domain ourselves so IDN recipients work on servers without SMTPUTF8
    // (lettre only validates the Unicode domain and would otherwise require SMTPUTF8).
    let (user, domain) = email.rsplit_once('@').ok_or_else(bad)?;
    let domain = if domain.is_ascii() {
        domain.to_owned()
    } else {
        idna::domain_to_ascii(domain).map_err(|_| bad())?
    };
    format!("{user}@{domain}").parse().map_err(|_| bad())
}

fn mailbox(a: &Address) -> Result<Mailbox> {
    Ok(Mailbox::new(
        a.name.clone().filter(|n| !n.is_empty()),
        parse_address(&a.email)?,
    ))
}

/// Domain part used for Message-ID and EHLO; the validated account address is the source.
pub fn address_domain(email: &str) -> Option<&str> {
    email
        .rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| !d.is_empty())
}

/// From must be the account's own address or an explicitly configured alias
/// (case-insensitive; the display name is not part of the identity).
pub fn validate_sender(from: &Address, account_email: &str, aliases: &[String]) -> Result<()> {
    let ok = from.email.eq_ignore_ascii_case(account_email)
        || aliases.iter().any(|a| from.email.eq_ignore_ascii_case(a));
    if ok {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::AccessDenied,
            "From address is not this account's address or a configured alias",
        ))
    }
}

/// `<uuid@domain>`: random so it is unique across restarts, domain so replies and
/// bounces thread against the sending identity.
pub fn generate_message_id(account_email: &str) -> Result<String> {
    let domain = address_domain(account_email)
        .ok_or_else(|| Error::new(ErrorCode::ConfigInvalid, "account email has no domain"))?;
    Ok(format!("<{}@{domain}>", uuid::Uuid::new_v4().simple()))
}

pub fn build_message(request: &SendRequest, message_id: &str) -> Result<BuiltMessage> {
    let from = mailbox(&request.from)?;
    let mut builder = Message::builder()
        .from(from.clone())
        .subject(request.subject.clone())
        .date_now()
        .message_id(Some(message_id.to_owned()));
    for a in &request.to {
        builder = builder.to(mailbox(a)?);
    }
    for a in &request.cc {
        builder = builder.cc(mailbox(a)?);
    }
    if let Some(id) = &request.in_reply_to {
        builder = builder.in_reply_to(id.clone());
    }
    if !request.references.is_empty() {
        // lettre's `references()` replaces rather than appends: pass the whole chain at once.
        builder = builder.references(request.references.join(" "));
    }

    let recipients = request
        .to
        .iter()
        .chain(&request.cc)
        .chain(&request.bcc)
        .map(|a| parse_address(&a.email))
        .collect::<Result<Vec<_>>>()?;
    let envelope =
        Envelope::new(Some(from.email.clone()), recipients).map_err(|e| invalid(e.to_string()))?;
    builder = builder.envelope(envelope.clone());

    let message = if request.attachments.is_empty() {
        match (&request.text, &request.html) {
            (Some(t), Some(h)) => {
                builder.multipart(MultiPart::alternative_plain_html(t.clone(), h.clone()))
            }
            (Some(t), None) => builder.singlepart(SinglePart::plain(t.clone())),
            (None, Some(h)) => builder.singlepart(SinglePart::html(h.clone())),
            (None, None) => return Err(invalid("message needs a text or html body")),
        }
    } else {
        let mut mixed = match (&request.text, &request.html) {
            (Some(t), Some(h)) => MultiPart::mixed()
                .multipart(MultiPart::alternative_plain_html(t.clone(), h.clone())),
            (Some(t), None) => MultiPart::mixed().singlepart(SinglePart::plain(t.clone())),
            (None, Some(h)) => MultiPart::mixed().singlepart(SinglePart::html(h.clone())),
            (None, None) => return Err(invalid("message needs a text or html body")),
        };
        for a in &request.attachments {
            let ct = ContentType::parse(&a.content_type).map_err(|_| {
                invalid(format!(
                    "invalid content type for attachment '{}'",
                    a.filename
                ))
            })?;
            mixed =
                mixed.singlepart(MimeAttachment::new(a.filename.clone()).body(a.data.clone(), ct));
        }
        builder.multipart(mixed)
    }
    .map_err(|e| invalid(format!("cannot build message: {e}")))?;

    Ok(BuiltMessage {
        raw: message.formatted(),
        envelope,
        message_id: message_id.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::request::Attachment;

    fn base() -> SendRequest {
        SendRequest {
            idempotency_key: "k".into(),
            from: Address {
                name: Some("Ünï Sender".into()),
                email: "me@example.com".into(),
            },
            to: vec![Address {
                name: Some("You".into()),
                email: "you@example.org".into(),
            }],
            cc: vec![Address {
                name: None,
                email: "cc@example.org".into(),
            }],
            bcc: vec![Address {
                name: None,
                email: "secret@example.net".into(),
            }],
            subject: "Grüße".into(),
            text: Some("plain".into()),
            html: Some("<p>html</p>".into()),
            attachments: vec![],
            in_reply_to: Some("<orig@example.org>".into()),
            references: vec!["<root@example.org>".into(), "<orig@example.org>".into()],
        }
    }

    fn text(b: &BuiltMessage) -> String {
        String::from_utf8_lossy(&b.raw).into_owned()
    }

    #[test]
    fn alternative_with_threading_headers_and_hidden_bcc() {
        let b = build_message(&base(), "<abc@example.com>").unwrap();
        let t = text(&b);
        assert!(t.contains("Message-ID: <abc@example.com>"));
        assert!(t.contains("In-Reply-To: <orig@example.org>"));
        assert!(
            t.contains("References: <root@example.org> <orig@example.org>"),
            "{t}"
        );
        assert!(t.contains("multipart/alternative"));
        assert!(t.contains("text/plain") && t.contains("text/html"));
        assert!(
            !t.contains("secret@example.net"),
            "bcc must not be in headers"
        );
        let rcpts: Vec<String> = b.envelope.to().iter().map(ToString::to_string).collect();
        assert_eq!(
            rcpts,
            ["you@example.org", "cc@example.org", "secret@example.net"]
        );
        assert!(
            t.is_ascii(),
            "non-ASCII display name/subject must be MIME-encoded"
        );
    }

    #[test]
    fn plain_only_is_not_multipart() {
        let mut r = base();
        r.html = None;
        let t = text(&build_message(&r, "<a@b.c>").unwrap());
        assert!(!t.contains("multipart"));
        assert!(t.contains("text/plain"));
    }

    #[test]
    fn attachments_produce_mixed() {
        let mut r = base();
        r.attachments.push(Attachment {
            filename: "r.pdf".into(),
            content_type: "application/pdf".into(),
            data: b"%PDF-1".to_vec(),
        });
        let t = text(&build_message(&r, "<a@b.c>").unwrap());
        assert!(t.contains("multipart/mixed") && t.contains("multipart/alternative"));
        assert!(t.contains("application/pdf") && t.contains("r.pdf"));
    }

    #[test]
    fn idn_domain_is_punycoded_in_envelope() {
        let mut r = base();
        r.to = vec![Address {
            name: None,
            email: "x@bücher.example".into(),
        }];
        let b = build_message(&r, "<a@b.c>").unwrap();
        assert_eq!(b.envelope.to()[0].domain(), "xn--bcher-kva.example");
    }

    #[test]
    fn sender_identity() {
        let me = Address {
            name: Some("Anything".into()),
            email: "Me@Example.com".into(),
        };
        assert!(validate_sender(&me, "me@example.com", &[]).is_ok());
        let other = Address {
            name: None,
            email: "ceo@example.com".into(),
        };
        assert_eq!(
            validate_sender(&other, "me@example.com", &[])
                .unwrap_err()
                .code(),
            ErrorCode::AccessDenied
        );
        assert!(validate_sender(&other, "me@example.com", &["ceo@example.com".into()]).is_ok());
    }

    #[test]
    fn message_id_uses_account_domain_and_is_unique() {
        let a = generate_message_id("me@example.com").unwrap();
        assert!(a.starts_with('<') && a.ends_with("@example.com>"));
        assert_ne!(a, generate_message_id("me@example.com").unwrap());
    }

    #[test]
    fn invalid_address_rejected() {
        let mut r = base();
        r.to = vec![Address {
            name: None,
            email: "not an address".into(),
        }];
        assert_eq!(
            build_message(&r, "<a@b.c>").unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }
}
