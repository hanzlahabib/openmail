//! Follow-up detection: which of our sent messages never got an answer, and which
//! inbound messages we never answered.
//!
//! Pure logic over plain input structs; no I/O. Time comes from an injected [`Clock`].
//! Every finding says how sure we are via [`LinkBasis`]:
//! - `Exact`: the decision rests on `Message-ID` / `In-Reply-To` / `References` headers
//!   (or the IMAP `\Answered` flag) only.
//! - `Heuristic`: it depended on subject matching, or on messages that lack threading
//!   headers, so a reply may exist that we could not prove.
//!
//! Forwards (`Fwd:`/`Fw:` subjects) are never treated as replies and are never tracked as
//! needing a follow-up. Automated senders (`noreply@`, `mailer-daemon@`, ...) are never
//! reported as needing our reply.

use std::collections::HashSet;

const SECS_PER_DAY: i64 = 86_400;

/// Local parts of automated senders; a reply to these is never expected.
const AUTOMATED_LOCAL_PARTS: &[&str] = &[
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "mailer-daemon",
    "postmaster",
    "notifications",
];

/// Injected time source so detection is deterministic in tests.
pub trait Clock {
    /// Seconds since the Unix epoch, UTC.
    fn now_unix(&self) -> i64;
}

/// Wall-clock implementation for production use.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
}

/// One message of a thread, reduced to what follow-up detection needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadMessage {
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub subject: String,
    pub from: String,
    pub to: Vec<String>,
    /// Sent/received time (Unix seconds, UTC); `None` when the Date header is missing/unparseable.
    pub date_unix: Option<i64>,
    /// IMAP `\Answered` flag on this message.
    pub answered_flag: bool,
}

/// Messages the caller believes belong together (e.g. one IMAP THREAD result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub id: String,
    pub messages: Vec<ThreadMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowUpConfig {
    /// Our own addresses; compared case-insensitively.
    pub own_addresses: Vec<String>,
    /// Report our sent message as unanswered after this many days.
    pub awaiting_reply_after_days: u32,
    /// Report an inbound message we never answered after this many days.
    pub needs_reply_after_days: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowUpKind {
    /// We sent it; nobody answered.
    AwaitingReply,
    /// Someone sent it to us; we never answered.
    NeedsReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkBasis {
    Exact,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowUp {
    pub kind: FollowUpKind,
    pub thread_id: String,
    pub message_id: Option<String>,
    pub subject: String,
    /// The other party: first recipient for `AwaitingReply`, the sender for `NeedsReply`.
    pub counterpart: String,
    pub date_unix: i64,
    pub age_days: u32,
    pub basis: LinkBasis,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FollowUpReport {
    /// Oldest first.
    pub items: Vec<FollowUp>,
    /// Messages ignored because they had no usable date (their age is unknowable).
    pub skipped_undated: usize,
}

/// Detect follow-ups across `threads` as of `clock.now_unix()`.
pub fn detect_followups(
    threads: &[Thread],
    config: &FollowUpConfig,
    clock: &impl Clock,
) -> FollowUpReport {
    let now = clock.now_unix();
    let own: HashSet<String> = config
        .own_addresses
        .iter()
        .map(|a| normalize_address(a))
        .collect();
    let mut report = FollowUpReport::default();
    for thread in threads {
        let (msgs, undated) = prepare(thread);
        report.skipped_undated += undated;
        if let Some(f) = awaiting_reply(thread, &msgs, &own, config, now) {
            report.items.push(f);
        }
        if let Some(f) = needs_reply(thread, &msgs, &own, config, now) {
            report.items.push(f);
        }
    }
    report.items.sort_by_key(|f| f.date_unix);
    report
}

/// A dated, de-duplicated, normalized view of one message.
struct Prepared<'a> {
    raw: &'a ThreadMessage,
    date: i64,
    id: Option<String>,
    parents: Vec<String>,
    subject: String,
    is_forward: bool,
    from: String,
    to: Vec<String>,
}

fn prepare(thread: &Thread) -> (Vec<Prepared<'_>>, usize) {
    let mut seen_ids = HashSet::new();
    let mut seen_fallback = HashSet::new();
    let mut undated = 0;
    let mut out = Vec::new();
    for raw in &thread.messages {
        let id = raw
            .message_id
            .as_deref()
            .map(normalize_id)
            .filter(|s| !s.is_empty());
        let from = normalize_address(&raw.from);
        let dup = match (&id, raw.date_unix) {
            (Some(id), _) => !seen_ids.insert(id.clone()),
            // Without a Message-ID the best identity is sender + time + subject.
            (None, d) => {
                !seen_fallback.insert((from.clone(), d, raw.subject.trim().to_lowercase()))
            }
        };
        if dup {
            continue;
        }
        let Some(date) = raw.date_unix else {
            undated += 1;
            continue;
        };
        let mut parents: Vec<String> = raw.references.iter().map(|r| normalize_id(r)).collect();
        if let Some(irt) = &raw.in_reply_to {
            parents.push(normalize_id(irt));
        }
        parents.retain(|p| !p.is_empty());
        out.push(Prepared {
            raw,
            date,
            id,
            parents,
            subject: strip_subject(&raw.subject),
            is_forward: is_forward(&raw.subject),
            from,
            to: raw.to.iter().map(|a| normalize_address(a)).collect(),
        });
    }
    out.sort_by_key(|m| m.date);
    (out, undated)
}

fn awaiting_reply(
    thread: &Thread,
    msgs: &[Prepared<'_>],
    own: &HashSet<String>,
    cfg: &FollowUpConfig,
    now: i64,
) -> Option<FollowUp> {
    // Only the latest tracked outbound message matters; earlier ones are superseded.
    let (idx, sent) = msgs.iter().enumerate().rev().find(|(_, m)| {
        own.contains(&m.from) && !m.is_forward && m.to.iter().any(|t| !own.contains(t))
    })?;
    if age_days(now, sent.date) < i64::from(cfg.awaiting_reply_after_days) {
        return None;
    }
    let mut exact_decision = sent.id.is_some();
    for later in &msgs[idx + 1..] {
        if own.contains(&later.from) {
            continue;
        }
        if later.is_forward {
            continue;
        }
        if links_exact(later, sent) {
            return None;
        }
        if later.parents.is_empty() {
            // A header-less inbound message may be a reply we cannot prove.
            exact_decision = false;
            if links_heuristic(later, sent) {
                return None;
            }
        }
    }
    let counterpart = sent.to.iter().find(|t| !own.contains(*t))?.clone();
    Some(FollowUp {
        kind: FollowUpKind::AwaitingReply,
        thread_id: thread.id.clone(),
        message_id: sent.raw.message_id.clone(),
        subject: sent.raw.subject.clone(),
        counterpart,
        date_unix: sent.date,
        age_days: clamp_days(now, sent.date),
        basis: basis(exact_decision),
    })
}

fn needs_reply(
    thread: &Thread,
    msgs: &[Prepared<'_>],
    own: &HashSet<String>,
    cfg: &FollowUpConfig,
    now: i64,
) -> Option<FollowUp> {
    let (idx, inbound) = msgs.iter().enumerate().rev().find(|(_, m)| {
        !own.contains(&m.from)
            && !m.is_forward
            && !is_automated(&m.from)
            && m.to.iter().any(|t| own.contains(t))
    })?;
    if age_days(now, inbound.date) < i64::from(cfg.needs_reply_after_days) {
        return None;
    }
    if inbound.raw.answered_flag {
        return None;
    }
    let mut exact_decision = inbound.id.is_some();
    for later in &msgs[idx + 1..] {
        if !own.contains(&later.from) || later.is_forward {
            continue;
        }
        if links_exact(later, inbound) {
            return None;
        }
        if later.parents.is_empty() {
            exact_decision = false;
        }
        if later.parents.is_empty() && links_heuristic(later, inbound) {
            return None;
        }
    }
    Some(FollowUp {
        kind: FollowUpKind::NeedsReply,
        thread_id: thread.id.clone(),
        message_id: inbound.raw.message_id.clone(),
        subject: inbound.raw.subject.clone(),
        counterpart: inbound.from.clone(),
        date_unix: inbound.date,
        age_days: clamp_days(now, inbound.date),
        basis: basis(exact_decision),
    })
}

fn basis(exact: bool) -> LinkBasis {
    if exact {
        LinkBasis::Exact
    } else {
        LinkBasis::Heuristic
    }
}

/// `reply` names `target` in its threading headers.
fn links_exact(reply: &Prepared<'_>, target: &Prepared<'_>) -> bool {
    target
        .id
        .as_ref()
        .is_some_and(|id| reply.parents.contains(id))
}

/// Same normalized subject, replying after the target, between the same parties.
fn links_heuristic(reply: &Prepared<'_>, target: &Prepared<'_>) -> bool {
    !reply.subject.is_empty()
        && reply.subject == target.subject
        && reply.date >= target.date
        && (target.to.contains(&reply.from) || reply.to.contains(&target.from))
}

fn age_days(now: i64, then: i64) -> i64 {
    (now - then).div_euclid(SECS_PER_DAY)
}

fn clamp_days(now: i64, then: i64) -> u32 {
    u32::try_from(age_days(now, then).max(0)).unwrap_or(u32::MAX)
}

fn normalize_id(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_lowercase()
}

fn normalize_address(a: &str) -> String {
    a.trim().to_lowercase()
}

fn is_automated(addr: &str) -> bool {
    let local = addr.split('@').next().unwrap_or(addr);
    AUTOMATED_LOCAL_PARTS.contains(&local)
}

fn is_forward(subject: &str) -> bool {
    let s = subject.trim_start().to_lowercase();
    s.starts_with("fwd:") || s.starts_with("fw:")
}

/// Subject without leading `Re:`/`Fwd:`/`Fw:` markers, lowercased, whitespace-collapsed.
fn strip_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_ascii_lowercase();
        let rest = ["re:", "fwd:", "fw:"]
            .iter()
            .find(|p| lower.starts_with(**p))
            .map(|p| s[p.len()..].trim_start());
        match rest {
            Some(r) => s = r,
            None => break,
        }
    }
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            self.0
        }
    }

    const DAY: i64 = SECS_PER_DAY;
    const NOW: i64 = 100 * DAY;
    const ME: &str = "me@example.test";
    const BOB: &str = "bob@example.test";

    fn cfg() -> FollowUpConfig {
        FollowUpConfig {
            own_addresses: vec!["ME@example.test".into()],
            awaiting_reply_after_days: 3,
            needs_reply_after_days: 2,
        }
    }

    fn msg(id: Option<&str>, from: &str, to: &str, subject: &str, days_ago: i64) -> ThreadMessage {
        ThreadMessage {
            message_id: id.map(str::to_owned),
            in_reply_to: None,
            references: vec![],
            subject: subject.into(),
            from: from.into(),
            to: vec![to.into()],
            date_unix: Some(NOW - days_ago * DAY),
            answered_flag: false,
        }
    }

    fn reply_to(mut m: ThreadMessage, parent: &str) -> ThreadMessage {
        m.in_reply_to = Some(parent.into());
        m
    }

    fn run(messages: Vec<ThreadMessage>) -> FollowUpReport {
        let t = Thread {
            id: "t1".into(),
            messages,
        };
        detect_followups(&[t], &cfg(), &FixedClock(NOW))
    }

    #[test]
    fn sent_without_reply_is_awaiting_exact() {
        let r = run(vec![msg(Some("<a@x>"), ME, BOB, "Quote", 5)]);
        assert_eq!(r.items.len(), 1);
        let f = &r.items[0];
        assert_eq!(f.kind, FollowUpKind::AwaitingReply);
        assert_eq!(f.counterpart, BOB);
        assert_eq!(f.age_days, 5);
        assert_eq!(f.basis, LinkBasis::Exact);
    }

    #[test]
    fn too_recent_is_not_reported() {
        assert!(
            run(vec![msg(Some("<a@x>"), ME, BOB, "Quote", 2)])
                .items
                .is_empty()
        );
    }

    #[test]
    fn exact_header_reply_clears_it() {
        let r = run(vec![
            msg(Some("<a@x>"), ME, BOB, "Quote", 5),
            reply_to(msg(Some("<b@x>"), BOB, ME, "Quote", 4), "<A@x>"),
        ]);
        // Bob's reply is itself unanswered by us, but 4 days old, so that is the only item.
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].kind, FollowUpKind::NeedsReply);
        assert_eq!(r.items[0].basis, LinkBasis::Exact);
    }

    #[test]
    fn headerless_subject_match_clears_as_heuristic_reply() {
        let r = run(vec![
            msg(Some("<a@x>"), ME, BOB, "Quote", 5),
            msg(None, BOB, ME, "RE: quote", 4),
        ]);
        assert!(
            r.items
                .iter()
                .all(|f| f.kind != FollowUpKind::AwaitingReply)
        );
    }

    #[test]
    fn headerless_unrelated_inbound_downgrades_to_heuristic() {
        let r = run(vec![
            msg(Some("<a@x>"), ME, BOB, "Quote", 5),
            msg(None, BOB, ME, "Lunch?", 1),
        ]);
        let f = r
            .items
            .iter()
            .find(|f| f.kind == FollowUpKind::AwaitingReply);
        assert_eq!(f.map(|f| f.basis), Some(LinkBasis::Heuristic));
    }

    #[test]
    fn missing_own_message_id_is_heuristic() {
        let r = run(vec![msg(None, ME, BOB, "Quote", 5)]);
        assert_eq!(r.items[0].basis, LinkBasis::Heuristic);
    }

    #[test]
    fn inbound_without_our_reply_needs_reply() {
        let r = run(vec![msg(Some("<a@x>"), BOB, ME, "Invoice", 4)]);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].kind, FollowUpKind::NeedsReply);
        assert_eq!(r.items[0].counterpart, BOB);
    }

    #[test]
    fn our_exact_reply_clears_needs_reply() {
        let r = run(vec![
            msg(Some("<a@x>"), BOB, ME, "Invoice", 4),
            reply_to(msg(Some("<b@x>"), ME, BOB, "Re: Invoice", 3), "<a@x>"),
        ]);
        assert!(r.items.iter().all(|f| f.kind != FollowUpKind::NeedsReply));
    }

    #[test]
    fn answered_flag_clears_needs_reply() {
        let mut m = msg(Some("<a@x>"), BOB, ME, "Invoice", 4);
        m.answered_flag = true;
        assert!(run(vec![m]).items.is_empty());
    }

    #[test]
    fn duplicates_are_counted_once() {
        let m = msg(Some("<a@x>"), ME, BOB, "Quote", 5);
        let r = run(vec![m.clone(), m]);
        assert_eq!(r.items.len(), 1);
    }

    #[test]
    fn duplicates_without_message_id_are_collapsed() {
        let m = msg(None, BOB, ME, "Invoice", 4);
        let r = run(vec![m.clone(), m]);
        assert_eq!(r.items.len(), 1);
    }

    #[test]
    fn forward_is_not_a_reply_and_not_tracked() {
        // We forwarded Bob's mail to Carol: that must not mark Bob's mail answered.
        let r = run(vec![
            msg(Some("<a@x>"), BOB, ME, "Invoice", 4),
            msg(Some("<f@x>"), ME, "carol@example.test", "Fwd: Invoice", 3),
        ]);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].kind, FollowUpKind::NeedsReply);
    }

    #[test]
    fn forward_with_threading_headers_still_not_a_reply() {
        let fwd = reply_to(
            msg(Some("<f@x>"), ME, "carol@example.test", "Fw: Invoice", 3),
            "<a@x>",
        );
        let r = run(vec![msg(Some("<a@x>"), BOB, ME, "Invoice", 4), fwd]);
        assert_eq!(r.items[0].kind, FollowUpKind::NeedsReply);
    }

    #[test]
    fn missing_dates_are_skipped_and_counted() {
        let mut m = msg(Some("<a@x>"), ME, BOB, "Quote", 5);
        m.date_unix = None;
        let r = run(vec![m]);
        assert!(r.items.is_empty());
        assert_eq!(r.skipped_undated, 1);
    }

    #[test]
    fn automated_senders_never_need_reply() {
        assert!(
            run(vec![msg(
                Some("<a@x>"),
                "noreply@example.test",
                ME,
                "Receipt",
                9
            )])
            .items
            .is_empty()
        );
    }

    #[test]
    fn only_latest_unanswered_outbound_is_reported() {
        let r = run(vec![
            msg(Some("<a@x>"), ME, BOB, "Quote", 9),
            msg(Some("<b@x>"), ME, BOB, "Re: Quote", 6),
        ]);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].message_id.as_deref(), Some("<b@x>"));
    }

    #[test]
    fn messages_sent_only_to_ourselves_are_ignored() {
        assert!(
            run(vec![msg(Some("<a@x>"), ME, ME, "Note to self", 9)])
                .items
                .is_empty()
        );
    }

    #[test]
    fn items_are_sorted_oldest_first_across_threads() {
        let t1 = Thread {
            id: "new".into(),
            messages: vec![msg(Some("<n@x>"), ME, BOB, "N", 4)],
        };
        let t2 = Thread {
            id: "old".into(),
            messages: vec![msg(Some("<o@x>"), ME, BOB, "O", 8)],
        };
        let r = detect_followups(&[t1, t2], &cfg(), &FixedClock(NOW));
        assert_eq!(r.items[0].thread_id, "old");
        assert_eq!(r.items[1].thread_id, "new");
    }

    #[test]
    fn strip_subject_handles_stacked_prefixes() {
        assert_eq!(
            strip_subject("  RE: Fwd:  re:  Hello   World "),
            "hello world"
        );
    }

    #[test]
    fn system_clock_is_after_2024() {
        assert!(SystemClock.now_unix() > 1_700_000_000);
    }
}
