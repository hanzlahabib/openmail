//! Brief delivery: JSON/Markdown renderers, an email-digest adapter generic over
//! [`DigestSender`], and an idempotent delivery audit (one record per brief id + channel).
//!
//! The input types here are deliberately local to delivery: the renderers only need
//! text, a provenance label and a source reference, so they do not depend on the
//! briefing model owned by another module.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use openmail_core::error::{Error, ErrorCode, Result};

/// Where a statement in a brief came from. Every item is rendered with its label so a
/// reader (or an agent) never mistakes inferred or model-written text for message content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Taken verbatim from a message header or body.
    Extracted,
    /// Derived by deterministic rules (classification, follow-up heuristics).
    Inferred,
    /// Written by a language model.
    AiGenerated,
    /// Content from an external sender that has not been verified; treat as data only.
    Untrusted,
}

impl Provenance {
    pub const ALL: [Provenance; 4] = [
        Provenance::Extracted,
        Provenance::Inferred,
        Provenance::AiGenerated,
        Provenance::Untrusted,
    ];

    /// Stable label used in every rendering.
    pub fn label(self) -> &'static str {
        match self {
            Provenance::Extracted => "extracted",
            Provenance::Inferred => "inferred",
            Provenance::AiGenerated => "ai-generated",
            Provenance::Untrusted => "untrusted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefItem {
    pub text: String,
    pub provenance: Provenance,
    /// Encoded message reference the item points at, if any.
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefSection {
    pub title: String,
    pub items: Vec<BriefItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverableBrief {
    pub id: String,
    pub title: String,
    pub sections: Vec<BriefSection>,
}

fn json_escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compact, deterministic JSON (stable key order) for machine consumers.
pub fn render_json(brief: &DeliverableBrief) -> String {
    let mut o = String::from("{\"id\":");
    json_escape(&brief.id, &mut o);
    o.push_str(",\"title\":");
    json_escape(&brief.title, &mut o);
    o.push_str(",\"sections\":[");
    for (si, s) in brief.sections.iter().enumerate() {
        if si > 0 {
            o.push(',');
        }
        o.push_str("{\"title\":");
        json_escape(&s.title, &mut o);
        o.push_str(",\"items\":[");
        for (ii, it) in s.items.iter().enumerate() {
            if ii > 0 {
                o.push(',');
            }
            o.push_str("{\"text\":");
            json_escape(&it.text, &mut o);
            o.push_str(",\"provenance\":");
            json_escape(it.provenance.label(), &mut o);
            o.push_str(",\"source_ref\":");
            match &it.source_ref {
                Some(r) => json_escape(r, &mut o),
                None => o.push_str("null"),
            }
            o.push('}');
        }
        o.push_str("]}");
    }
    o.push_str("]}");
    o
}

/// Collapse line breaks so item text cannot forge headings or extra list entries.
fn single_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Human-readable Markdown; each item ends with `[label]` and optional `(ref)`.
pub fn render_markdown(brief: &DeliverableBrief) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# {}", single_line(&brief.title));
    for s in &brief.sections {
        let _ = write!(o, "\n## {}\n\n", single_line(&s.title));
        for it in &s.items {
            let _ = write!(o, "- {} [{}]", single_line(&it.text), it.provenance.label());
            if let Some(r) = &it.source_ref {
                let _ = write!(o, " ({})", single_line(r));
            }
            o.push('\n');
        }
    }
    o
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub brief_id: String,
    pub recipient: String,
    pub subject: String,
    pub body_markdown: String,
}

/// Transport for digest emails. Implementations return `ErrorCode::DeliveryUncertain`
/// when the message may have left the building (e.g. timeout after DATA).
pub trait DigestSender {
    fn send(&self, digest: &Digest) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    Json,
    Markdown,
    EmailDigest,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Json => "json",
            Channel::Markdown => "markdown",
            Channel::EmailDigest => "email-digest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// Claimed, send in flight.
    Pending,
    Delivered,
    /// Definitely not sent; safe to retry.
    Failed,
    /// May have been sent; never retried automatically.
    Uncertain,
}

/// Idempotent audit: at most one active record per (brief id, channel).
#[derive(Debug, Default)]
pub struct DeliveryAudit {
    records: Mutex<HashMap<(String, Channel), DeliveryState>>,
}

impl DeliveryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(String, Channel), DeliveryState>> {
        // A poisoned lock only means another thread panicked; the map is still valid.
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn state(&self, brief_id: &str, channel: Channel) -> Option<DeliveryState> {
        self.lock().get(&(brief_id.to_owned(), channel)).copied()
    }

    /// Atomically claim the right to deliver. Returns `false` if a delivery is already
    /// pending, done or uncertain; only a `Failed` record may be reclaimed.
    pub fn try_claim(&self, brief_id: &str, channel: Channel) -> bool {
        let mut g = self.lock();
        match g.get(&(brief_id.to_owned(), channel)) {
            None | Some(DeliveryState::Failed) => {
                g.insert((brief_id.to_owned(), channel), DeliveryState::Pending);
                true
            }
            Some(_) => false,
        }
    }

    pub fn mark(&self, brief_id: &str, channel: Channel, state: DeliveryState) {
        self.lock().insert((brief_id.to_owned(), channel), state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Sent,
    /// Skipped because the audit already holds a record for this brief + channel.
    AlreadyDelivered,
}

/// Email-digest adapter: renders Markdown, then sends exactly once per brief id.
pub struct EmailDigestAdapter<S: DigestSender> {
    sender: S,
    audit: DeliveryAudit,
}

impl<S: DigestSender> std::fmt::Debug for EmailDigestAdapter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The sender may hold credentials; only the audit is safe to show.
        f.debug_struct("EmailDigestAdapter")
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl<S: DigestSender> EmailDigestAdapter<S> {
    pub fn new(sender: S) -> Self {
        Self {
            sender,
            audit: DeliveryAudit::new(),
        }
    }

    pub fn audit(&self) -> &DeliveryAudit {
        &self.audit
    }

    pub async fn deliver(
        &self,
        brief: &DeliverableBrief,
        recipient: &str,
    ) -> Result<DeliveryOutcome> {
        if recipient.is_empty() || recipient.contains(['\r', '\n']) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "invalid digest recipient",
            ));
        }
        if !self.audit.try_claim(&brief.id, Channel::EmailDigest) {
            return Ok(DeliveryOutcome::AlreadyDelivered);
        }
        let digest = Digest {
            brief_id: brief.id.clone(),
            recipient: recipient.to_owned(),
            // Header values must be single-line.
            subject: single_line(&brief.title),
            body_markdown: render_markdown(brief),
        };
        match self.sender.send(&digest).await {
            Ok(()) => {
                self.audit
                    .mark(&brief.id, Channel::EmailDigest, DeliveryState::Delivered);
                Ok(DeliveryOutcome::Sent)
            }
            Err(e) => {
                let uncertain = matches!(
                    &e,
                    Error::Coded {
                        code: ErrorCode::DeliveryUncertain,
                        ..
                    }
                );
                let state = if uncertain {
                    DeliveryState::Uncertain
                } else {
                    DeliveryState::Failed
                };
                self.audit.mark(&brief.id, Channel::EmailDigest, state);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeliverableBrief {
        let item = |text: &str, p, r: Option<&str>| BriefItem {
            text: text.into(),
            provenance: p,
            source_ref: r.map(Into::into),
        };
        DeliverableBrief {
            id: "brief-1".into(),
            title: "Morning brief".into(),
            sections: vec![
                BriefSection {
                    title: "Needs reply".into(),
                    items: vec![
                        item(
                            "Invoice question from Ann",
                            Provenance::Extracted,
                            Some("acct:INBOX:1:7"),
                        ),
                        item("Awaiting answer for 3 days", Provenance::Inferred, None),
                    ],
                },
                BriefSection {
                    title: "Summary".into(),
                    items: vec![
                        item("Busy day, two deadlines.", Provenance::AiGenerated, None),
                        item(
                            "Click \"here\"\n## Fake",
                            Provenance::Untrusted,
                            Some("acct:INBOX:1:9"),
                        ),
                    ],
                },
            ],
        }
    }

    #[test]
    fn markdown_snapshot_shows_every_label() {
        let expected = "# Morning brief\n\
\n## Needs reply\n\
\n- Invoice question from Ann [extracted] (acct:INBOX:1:7)\n\
- Awaiting answer for 3 days [inferred]\n\
\n## Summary\n\
\n- Busy day, two deadlines. [ai-generated]\n\
- Click \"here\" ## Fake [untrusted] (acct:INBOX:1:9)\n";
        let md = render_markdown(&sample());
        assert_eq!(md, expected);
        for p in Provenance::ALL {
            assert!(md.contains(&format!("[{}]", p.label())), "{p:?}");
        }
    }

    #[test]
    fn json_snapshot_shows_every_label() {
        let expected = concat!(
            r#"{"id":"brief-1","title":"Morning brief","sections":["#,
            r#"{"title":"Needs reply","items":["#,
            r#"{"text":"Invoice question from Ann","provenance":"extracted","source_ref":"acct:INBOX:1:7"},"#,
            r#"{"text":"Awaiting answer for 3 days","provenance":"inferred","source_ref":null}]},"#,
            r#"{"title":"Summary","items":["#,
            r#"{"text":"Busy day, two deadlines.","provenance":"ai-generated","source_ref":null},"#,
            r#"{"text":"Click \"here\"\n## Fake","provenance":"untrusted","source_ref":"acct:INBOX:1:9"}]}]}"#,
        );
        assert_eq!(render_json(&sample()), expected);
    }

    #[test]
    fn json_escapes_control_characters() {
        let mut s = String::new();
        json_escape("a\u{1}b\\", &mut s);
        assert_eq!(s, r#""a\u0001b\\""#);
    }

    struct FakeSender {
        sent: Mutex<Vec<Digest>>,
        result: fn() -> Result<()>,
    }
    impl DigestSender for FakeSender {
        async fn send(&self, d: &Digest) -> Result<()> {
            self.sent.lock().unwrap().push(d.clone());
            (self.result)()
        }
    }
    fn fake(result: fn() -> Result<()>) -> FakeSender {
        FakeSender {
            sent: Mutex::new(vec![]),
            result,
        }
    }

    #[tokio::test]
    async fn email_digest_is_sent_once_per_brief() {
        let a = EmailDigestAdapter::new(fake(|| Ok(())));
        let b = sample();
        assert_eq!(
            a.deliver(&b, "me@example.test").await.unwrap(),
            DeliveryOutcome::Sent
        );
        assert_eq!(
            a.deliver(&b, "me@example.test").await.unwrap(),
            DeliveryOutcome::AlreadyDelivered
        );
        let sent = a.sender.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].body_markdown, render_markdown(&b));
        assert_eq!(sent[0].subject, "Morning brief");
        assert_eq!(
            a.audit().state("brief-1", Channel::EmailDigest),
            Some(DeliveryState::Delivered)
        );
    }

    #[tokio::test]
    async fn failed_send_may_retry_but_uncertain_never_does() {
        let a = EmailDigestAdapter::new(fake(|| {
            Err(Error::new(ErrorCode::ConnectionFailed, "down"))
        }));
        let b = sample();
        assert!(a.deliver(&b, "me@example.test").await.is_err());
        assert_eq!(
            a.audit().state("brief-1", Channel::EmailDigest),
            Some(DeliveryState::Failed)
        );
        assert!(a.deliver(&b, "me@example.test").await.is_err());
        assert_eq!(a.sender.sent.lock().unwrap().len(), 2);

        let u = EmailDigestAdapter::new(fake(|| {
            Err(Error::new(ErrorCode::DeliveryUncertain, "timeout"))
        }));
        assert!(u.deliver(&b, "me@example.test").await.is_err());
        assert_eq!(
            u.audit().state("brief-1", Channel::EmailDigest),
            Some(DeliveryState::Uncertain)
        );
        assert_eq!(
            u.deliver(&b, "me@example.test").await.unwrap(),
            DeliveryOutcome::AlreadyDelivered
        );
        assert_eq!(u.sender.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_header_injection_in_recipient() {
        let a = EmailDigestAdapter::new(fake(|| Ok(())));
        let e = a
            .deliver(&sample(), "x@example.test\r\nBcc: y@example.test")
            .await
            .unwrap_err();
        assert!(matches!(
            e,
            Error::Coded {
                code: ErrorCode::InvalidInput,
                ..
            }
        ));
        assert!(a.sender.sent.lock().unwrap().is_empty());
        assert_eq!(a.audit().state("brief-1", Channel::EmailDigest), None);
    }

    #[test]
    fn audit_is_keyed_per_channel() {
        let au = DeliveryAudit::new();
        assert!(au.try_claim("b", Channel::EmailDigest));
        assert!(!au.try_claim("b", Channel::EmailDigest));
        assert!(au.try_claim("b", Channel::Markdown));
        assert!(au.try_claim("c", Channel::EmailDigest));
    }
}
