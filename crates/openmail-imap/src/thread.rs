//! Threading helpers. Relationships established by Message-ID / In-Reply-To /
//! References headers are `Exact`; same-normalized-subject matches are `Heuristic`
//! and are always labelled as such, never merged silently.
use openmail_core::model::MessageSummary;

use crate::mime::HeaderInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadRelation {
    /// The message the caller asked about.
    Anchor,
    /// Linked to the thread through Message-ID/In-Reply-To/References headers.
    Exact,
    /// Matched only by normalized subject; may be unrelated.
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadEntry {
    pub summary: MessageSummary,
    pub relation: ThreadRelation,
    /// Message-ID of the parent according to the headers (In-Reply-To, else the last Reference).
    pub parent_message_id: Option<String>,
}

/// Lowercased subject without leading `re:`/`fwd:`/`fw:` markers.
pub fn normalize_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_ascii_lowercase();
        let stripped = ["re:", "fwd:", "fw:"]
            .iter()
            .find(|p| lower.starts_with(**p))
            .map(|p| p.len());
        match stripped {
            Some(n) => s = s[n..].trim_start(),
            None => break,
        }
    }
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub fn parent_of(h: &HeaderInfo) -> Option<String> {
    h.in_reply_to.last().or(h.references.last()).cloned()
}

/// `OR a OR b c` nesting for an arbitrary number of keys (IMAP OR is binary).
pub fn or_chain(keys: &[String]) -> Option<String> {
    match keys {
        [] => None,
        [one] => Some(one.clone()),
        [first, rest @ ..] => Some(format!("OR {first} {}", or_chain(rest)?)),
    }
}

/// Oldest first, undated last; ties broken by UID so the order is deterministic.
pub fn sort_entries(entries: &mut [ThreadEntry]) {
    entries.sort_by(|a, b| {
        let key = |e: &ThreadEntry| {
            (
                e.summary.date.is_none(),
                e.summary.date.clone(),
                e.summary.reference.uid,
            )
        };
        key(a).cmp(&key(b))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_normalization() {
        assert_eq!(
            normalize_subject("RE: Re:  Fwd: Hello   World "),
            "hello world"
        );
        assert_eq!(normalize_subject("Regarding re: x"), "regarding re: x");
        assert_eq!(normalize_subject("fw:Plan"), "plan");
    }

    #[test]
    fn or_chain_nests() {
        let k = |s: &str| s.to_owned();
        assert_eq!(or_chain(&[]), None);
        assert_eq!(or_chain(&[k("A")]).unwrap(), "A");
        assert_eq!(or_chain(&[k("A"), k("B"), k("C")]).unwrap(), "OR A OR B C");
    }

    #[test]
    fn parent_prefers_in_reply_to() {
        let h = HeaderInfo {
            in_reply_to: vec!["p".into()],
            references: vec!["r1".into(), "r2".into()],
            ..Default::default()
        };
        assert_eq!(parent_of(&h).as_deref(), Some("p"));
        let h = HeaderInfo {
            references: vec!["r1".into(), "r2".into()],
            ..Default::default()
        };
        assert_eq!(parent_of(&h).as_deref(), Some("r2"));
        assert_eq!(parent_of(&HeaderInfo::default()), None);
    }
}
