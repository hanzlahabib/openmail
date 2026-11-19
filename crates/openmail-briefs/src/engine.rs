//! `BriefEngine`: one run = aggregate -> classify -> follow-up -> persist.
//!
//! Guarantees (each is covered by a test):
//! - every item carries the `MessageRef` of the message it came from and a provenance label;
//! - an account that failed or timed out is reported as such, never as an empty account;
//! - messages already reported (cursor per account, folder and UIDVALIDITY) are not reported
//!   again unless the caller asks for them, and the cursor only advances after the brief is
//!   saved, so a run that dies midway is repeated rather than lost;
//! - mail text only ever reaches the classifier as data (keyword tables, user rules), and
//!   reaches an AI provider only when the owner's [`AiPolicy`] allows it.
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use openmail_core::backend::MailBackend;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{Message, MessageBody, MessageSummary, Untrusted};
use openmail_core::{Error, ErrorCode, Result};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::aggregate::{AccountResult, AccountStatus, AggregateConfig, NoCursors, aggregate};
use crate::ai::{AiPolicy, ContentField, Summarizer};
use crate::classify::{Category, Classification, ClassificationSource, Classifier};
use crate::config::BriefsConfig;
use crate::followup::{
    FollowUpConfig, FollowUpKind, FollowUpReport, LinkBasis, SystemClock, Thread, ThreadMessage,
    detect_followups, strip_subject,
};
use crate::model::{
    AccountRunStatus, ActionItem, AiSummary, Brief, BriefItem, Evidence, FollowUp, Provenance,
};
use crate::store::{BriefStore, RunRecord};

/// The store is a single SQLite connection; every use is a short synchronous block and the
/// guard is never held across an await.
pub type SharedStore = Arc<Mutex<BriefStore>>;

/// Follow-up detection needs older mail than the brief window: a reply to something sent
/// last week is what makes it "answered". 14 days covers the default thresholds with margin.
const FOLLOWUP_MIN_LOOKBACK: Duration = Duration::from_secs(14 * 24 * 3600);
/// Per-section cap so one noisy mailbox cannot produce an unreadable brief.
const MAX_ITEMS_PER_SECTION: usize = 100;
/// Body bytes fetched per message for an AI summary. The adapter truncates to its own
/// character cap again; fetching more would only move bytes we then drop.
const AI_BODY_FETCH_BYTES: usize = 16 * 1024;

/// An account a brief may cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefAccount {
    pub id: AccountId,
    /// The mailbox owner's address; follow-up detection tells "mine" from "theirs" with it.
    pub email: String,
    /// Configured Sent folder name, when the owner set one; else found through RFC 6154.
    pub sent_folder: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowUpDays {
    pub awaiting_reply_after: u32,
    pub needs_reply_after: u32,
}

#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub folder: String,
    pub max_messages_per_account: usize,
    pub per_account_timeout: Duration,
    pub max_concurrency: usize,
    pub follow_up: FollowUpDays,
}

impl EngineSettings {
    pub fn from_config(c: &BriefsConfig) -> Self {
        Self {
            folder: c.folder.clone(),
            max_messages_per_account: c.max_messages_per_account,
            per_account_timeout: Duration::from_secs(c.per_account_timeout_secs),
            max_concurrency: c.max_concurrency,
            follow_up: FollowUpDays {
                awaiting_reply_after: c.awaiting_reply_after_days,
                needs_reply_after: c.needs_reply_after_days,
            },
        }
    }
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self::from_config(&BriefsConfig::default())
    }
}

#[derive(Debug, Clone)]
pub struct GenerateRequest {
    pub accounts: Vec<BriefAccount>,
    pub lookback: Duration,
    /// Report mail an earlier brief already covered (the cursor still advances).
    pub include_processed: bool,
}

type SummarizeFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;
type SummarizeFn = dyn Fn(Vec<Message>) -> SummarizeFuture + Send + Sync;

/// The optional AI step: a provider adapter plus the policy that gates what it may see.
/// Type-erased so the engine (and the MCP server holding it) does not become generic over
/// the provider.
#[derive(Clone)]
pub struct AiStage {
    policy: AiPolicy,
    summarize: Arc<SummarizeFn>,
}

impl std::fmt::Debug for AiStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiStage")
            .field("allowed_accounts", &self.policy.allowed_accounts)
            .finish_non_exhaustive()
    }
}

impl AiStage {
    /// `summarizer` must enforce the same `policy` itself (`HttpSummarizer` does); the engine
    /// additionally refuses to even hand it mail from accounts the policy does not allow.
    pub fn new<Z>(summarizer: Z, policy: AiPolicy) -> Self
    where
        Z: Summarizer + Send + Sync + 'static,
    {
        let summarizer = Arc::new(summarizer);
        Self {
            policy,
            summarize: Arc::new(move |messages| {
                let summarizer = Arc::clone(&summarizer);
                Box::pin(async move { summarizer.summarize(&messages).await })
            }),
        }
    }
}

#[derive(Debug)]
pub struct BriefEngine<B: MailBackend> {
    backend: Arc<B>,
    store: SharedStore,
    settings: EngineSettings,
    classifier: Classifier,
    ai: Option<AiStage>,
}

fn internal(msg: &str) -> Error {
    Error::new(ErrorCode::Internal, msg)
}

fn lock(store: &SharedStore) -> Result<MutexGuard<'_, BriefStore>> {
    store
        .lock()
        .map_err(|_| internal("brief store lock poisoned"))
}

fn rfc3339(t: OffsetDateTime) -> Result<String> {
    t.format(&Rfc3339)
        .map_err(|_| internal("timestamp formatting failed"))
}

/// Stable, secret-free reason for an account that could not be read. Server text is not
/// forwarded: it can echo banners or addresses (security review F3).
fn failure_reason(status: &AccountStatus) -> Option<String> {
    match status {
        AccountStatus::Ok => None,
        AccountStatus::TimedOut => Some("timed_out".to_owned()),
        AccountStatus::Failed { code, .. } => Some(format!("{code:?}")),
    }
}

fn normalize_id(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_lowercase()
}

fn unix_of(date: Option<&str>) -> Option<i64> {
    OffsetDateTime::parse(date?, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

impl<B: MailBackend> BriefEngine<B> {
    pub fn new(
        backend: Arc<B>,
        store: SharedStore,
        settings: EngineSettings,
        classifier: Classifier,
    ) -> Self {
        Self {
            backend,
            store,
            settings,
            classifier,
            ai: None,
        }
    }

    #[must_use]
    pub fn with_ai(mut self, ai: AiStage) -> Self {
        self.ai = Some(ai);
        self
    }

    pub fn store(&self) -> &SharedStore {
        &self.store
    }

    pub fn ai_enabled(&self) -> bool {
        self.ai.is_some()
    }

    fn aggregate_config(
        &self,
        folder: &str,
        lookback: Duration,
        now: OffsetDateTime,
    ) -> AggregateConfig {
        AggregateConfig {
            folder: folder.to_owned(),
            lookback,
            now,
            max_concurrency: self.settings.max_concurrency,
            per_account_timeout: self.settings.per_account_timeout,
            max_messages_per_account: self.settings.max_messages_per_account,
        }
    }

    /// Run the pipeline for `req.accounts` and persist the result.
    pub async fn generate(&self, req: &GenerateRequest) -> Result<Brief> {
        if req.accounts.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a brief needs at least one account",
            ));
        }
        let started = OffsetDateTime::now_utc();
        let ids: Vec<AccountId> = req.accounts.iter().map(|a| a.id.clone()).collect();
        // Fetch back far enough for follow-ups; items are narrowed to the window below.
        let fetch_lookback = req.lookback.max(FOLLOWUP_MIN_LOOKBACK);
        let results = aggregate(
            &*self.backend,
            &NoCursors,
            &ids,
            &self.aggregate_config(&self.settings.folder, fetch_lookback, started),
        )
        .await;

        let window_start = started - req.lookback;
        let mut build = Build::default();
        for (account, result) in req.accounts.iter().zip(results.accounts) {
            self.collect_account(account, result, window_start, req, &mut build)
                .await?;
        }
        self.summarize(&mut build).await;

        let cursors = std::mem::take(&mut build.cursors);
        let brief = build.into_brief(started, window_start)?;
        // Cursors move only once the brief is stored: a run that dies earlier is repeated.
        self.persist(&brief, &cursors, started)?;
        Ok(brief)
    }

    async fn collect_account(
        &self,
        account: &BriefAccount,
        result: AccountResult,
        window_start: OffsetDateTime,
        req: &GenerateRequest,
        build: &mut Build,
    ) -> Result<()> {
        if let Some(reason) = failure_reason(&result.status) {
            build
                .accounts
                .insert(account.id.clone(), AccountRunStatus::Failed { reason });
            return Ok(());
        }
        build
            .accounts
            .insert(account.id.clone(), AccountRunStatus::Ok);
        if result.messages.len() >= self.settings.max_messages_per_account {
            build.notes.push(format!(
                "{}: more than {} messages in range; the oldest were not examined",
                account.id, self.settings.max_messages_per_account
            ));
        }

        let processed = self.processed_cursors(&account.id, &result.messages)?;
        for m in &result.messages {
            let r = &m.reference;
            let slot = build
                .cursors
                .entry((r.account.clone(), r.folder.clone(), r.uid_validity))
                .or_insert(r.uid);
            *slot = (*slot).max(r.uid);
        }
        let fresh: Vec<&MessageSummary> = result
            .messages
            .iter()
            .filter(|m| in_window(m, window_start))
            .filter(|m| {
                req.include_processed
                    || processed
                        .get(&m.reference.uid_validity)
                        .is_none_or(|last| m.reference.uid > *last)
            })
            .filter(|m| !m.flags.draft && !m.flags.deleted)
            .collect();

        for m in &fresh {
            if let Some((section, score, item)) = self.item_for(m) {
                match section {
                    Section::Highlight => build.highlights.push((score, item)),
                    Section::Action => build.actions.push((score, ActionItem { item, due: None })),
                }
            }
        }
        build
            .ai_candidates
            .extend(fresh.iter().map(|m| (*m).clone()));
        self.follow_ups(account, &result.messages, build).await;
        Ok(())
    }

    /// Last processed UID per UIDVALIDITY seen in `messages`.
    fn processed_cursors(
        &self,
        account: &AccountId,
        messages: &[MessageSummary],
    ) -> Result<HashMap<u32, u32>> {
        let store = lock(&self.store)?;
        let mut out = HashMap::new();
        for m in messages {
            let r = &m.reference;
            if let std::collections::hash_map::Entry::Vacant(v) = out.entry(r.uid_validity)
                && let Some(last) = store.cursor(account, &r.folder, r.uid_validity)?
            {
                v.insert(last);
            }
        }
        Ok(out)
    }

    /// Classification is a pure function of header fields: nothing in the mail can do more
    /// than match or fail to match a keyword.
    fn item_for(&self, m: &MessageSummary) -> Option<(Section, u32, BriefItem)> {
        if let Some(c) = self.classifier.classify_summary(m)
            && let Some(section) = section_of(c.category)
        {
            return Some((section, c.score, classified_item(m, &c)));
        }
        m.flags.flagged.then(|| {
            (
                Section::Highlight,
                0,
                BriefItem {
                    source: m.reference.clone(),
                    title: m.subject.clone(),
                    evidence: vec![Evidence {
                        reason: "flagged in the mailbox".to_owned(),
                        excerpt: None,
                    }],
                    provenance: Provenance::Fact,
                },
            )
        })
    }

    async fn follow_ups(
        &self,
        account: &BriefAccount,
        inbox: &[MessageSummary],
        build: &mut Build,
    ) {
        let Some(sent_folder) = self.sent_folder(account).await else {
            build.notes.push(format!(
                "{}: no Sent folder found, follow-ups were not checked",
                account.id
            ));
            return;
        };
        let now = OffsetDateTime::now_utc();
        let sent = aggregate(
            &*self.backend,
            &NoCursors,
            std::slice::from_ref(&account.id),
            &self.aggregate_config(&sent_folder, FOLLOWUP_MIN_LOOKBACK, now),
        )
        .await;
        let Some(sent) = sent.accounts.into_iter().next() else {
            return;
        };
        if let Some(reason) = failure_reason(&sent.status) {
            build.notes.push(format!(
                "{}: Sent folder not readable ({reason}), follow-ups were not checked",
                account.id
            ));
            return;
        }
        let all: Vec<&MessageSummary> = inbox.iter().chain(sent.messages.iter()).collect();
        let report = detect_followups(
            &threads_of(&all),
            &FollowUpConfig {
                own_addresses: vec![account.email.clone()],
                awaiting_reply_after_days: self.settings.follow_up.awaiting_reply_after,
                needs_reply_after_days: self.settings.follow_up.needs_reply_after,
            },
            &SystemClock,
        );
        apply_followups(&report, &all, build);
    }

    async fn sent_folder(&self, account: &BriefAccount) -> Option<String> {
        if let Some(name) = &account.sent_folder {
            return Some(name.clone());
        }
        let folders = tokio::time::timeout(
            self.settings.per_account_timeout,
            self.backend.list_folders(&account.id),
        )
        .await
        .ok()?
        .ok()?;
        folders
            .into_iter()
            .find(|f| {
                f.selectable
                    && f.role
                        .as_deref()
                        .is_some_and(|r| r.trim_start_matches('\\').eq_ignore_ascii_case("sent"))
            })
            .map(|f| f.name)
    }

    /// The only place mail leaves for a provider. Skipped unless the owner configured it, and
    /// only accounts the policy names are ever handed over.
    async fn summarize(&self, build: &mut Build) {
        let Some(ai) = &self.ai else { return };
        let eligible: Vec<MessageSummary> = build
            .ai_candidates
            .iter()
            .filter(|m| ai.policy.allowed_accounts.contains(&m.reference.account))
            .take(ai.policy.max_messages)
            .cloned()
            .collect();
        if eligible.is_empty() {
            build
                .notes
                .push("ai summary skipped: no messages from accounts the AI policy allows".into());
            return;
        }
        let with_body = ai.policy.allowed_fields.contains(&ContentField::Body);
        let mut messages = Vec::with_capacity(eligible.len());
        for summary in eligible {
            // Bodies are fetched only when the policy lists them; the adapter still applies
            // its own off-machine rule before anything is serialised.
            let fetched = if with_body {
                tokio::time::timeout(
                    self.settings.per_account_timeout,
                    self.backend
                        .get_message(&summary.reference, AI_BODY_FETCH_BYTES),
                )
                .await
                .ok()
                .and_then(std::result::Result::ok)
            } else {
                None
            };
            messages.push(fetched.unwrap_or_else(|| bodyless(summary)));
        }
        let shown = messages.len();
        match tokio::time::timeout(self.settings.per_account_timeout, (ai.summarize)(messages))
            .await
        {
            Ok(Ok(text)) => {
                build.ai_summary = Some(AiSummary {
                    text: Untrusted(text),
                    provenance: Provenance::Ai,
                    messages: shown,
                });
            }
            Ok(Err(e)) => build
                .notes
                .push(format!("ai summary unavailable ({:?})", e.code())),
            Err(_) => build
                .notes
                .push("ai summary unavailable (timed out)".to_owned()),
        }
    }

    fn persist(
        &self,
        brief: &Brief,
        cursors: &BTreeMap<(AccountId, String, u32), u32>,
        started: OffsetDateTime,
    ) -> Result<()> {
        let finished = rfc3339(OffsetDateTime::now_utc())?;
        let started = rfc3339(started)?;
        let store = lock(&self.store)?;
        store.save_brief(brief)?;
        for ((account, folder, validity), uid) in cursors {
            store.advance_cursor(account, folder, *validity, *uid)?;
            store.prune_stale_cursors(account, folder, *validity)?;
        }
        for (account, status) in &brief.accounts {
            store.record_run(&RunRecord {
                account: account.clone(),
                started_at: started.clone(),
                finished_at: finished.clone(),
                status: status.clone(),
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Section {
    Highlight,
    Action,
}

fn section_of(c: Category) -> Option<Section> {
    match c {
        Category::PaymentRelated | Category::ClientInquiry | Category::ReplyToSent => {
            Some(Section::Action)
        }
        Category::NewLead | Category::PartnershipRequest => Some(Section::Highlight),
        Category::Newsletter => None,
    }
}

fn category_name(c: Category) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn classified_item(m: &MessageSummary, c: &Classification) -> BriefItem {
    BriefItem {
        source: m.reference.clone(),
        title: m.subject.clone(),
        evidence: vec![Evidence {
            reason: format!(
                "looks like {} (matched: {})",
                category_name(c.category),
                c.matched_rules.join(", ")
            ),
            excerpt: None,
        }],
        provenance: match c.source {
            ClassificationSource::Heuristic => Provenance::Heuristic,
            ClassificationSource::UserRule => Provenance::UserRule,
        },
    }
}

fn bodyless(summary: MessageSummary) -> Message {
    Message {
        summary,
        cc: Vec::new(),
        in_reply_to: None,
        references: Vec::new(),
        body: MessageBody {
            text: None,
            html_sanitized: None,
            truncated: false,
        },
        attachments: Vec::new(),
    }
}

/// Messages without a parsable date are kept: dropping them would hide mail silently.
fn in_window(m: &MessageSummary, start: OffsetDateTime) -> bool {
    match unix_of(m.date.as_deref()) {
        Some(t) => t >= start.unix_timestamp(),
        None => true,
    }
}

/// Group by normalised subject. Summaries carry no threading headers, so the grouping is a
/// heuristic and `detect_followups` labels its findings accordingly.
fn threads_of(messages: &[&MessageSummary]) -> Vec<Thread> {
    let mut groups: BTreeMap<String, Vec<&MessageSummary>> = BTreeMap::new();
    for m in messages {
        groups
            .entry(strip_subject(&m.subject.0))
            .or_default()
            .push(m);
    }
    groups
        .into_values()
        .map(|group| {
            let newest = group
                .iter()
                .max_by_key(|m| unix_of(m.date.as_deref()).unwrap_or(i64::MIN))
                .map(|m| m.reference.encode())
                .unwrap_or_default();
            Thread {
                id: newest,
                messages: group.iter().map(|m| thread_message(m)).collect(),
            }
        })
        .collect()
}

fn thread_message(m: &MessageSummary) -> ThreadMessage {
    ThreadMessage {
        message_id: m.message_id.clone(),
        in_reply_to: None,
        references: Vec::new(),
        subject: m.subject.0.clone(),
        from: m.from.first().map(|a| a.email.clone()).unwrap_or_default(),
        to: m.to.iter().map(|a| a.email.clone()).collect(),
        date_unix: unix_of(m.date.as_deref()),
        answered_flag: m.flags.answered,
    }
}

fn apply_followups(report: &FollowUpReport, all: &[&MessageSummary], build: &mut Build) {
    if report.skipped_undated > 0 {
        build.notes.push(format!(
            "{} message(s) without a usable date were ignored by follow-up detection",
            report.skipped_undated
        ));
    }
    let by_id: HashMap<String, &MessageSummary> = all
        .iter()
        .filter_map(|m| Some((normalize_id(m.message_id.as_deref()?), *m)))
        .collect();
    for f in &report.items {
        let source = f
            .message_id
            .as_deref()
            .and_then(|id| by_id.get(&normalize_id(id)))
            .map(|m| m.reference.clone())
            .or_else(|| MessageRef::decode(&f.thread_id).ok());
        let Some(source) = source else { continue };
        let basis = match f.basis {
            LinkBasis::Exact => "matched by message headers",
            LinkBasis::Heuristic => "matched by subject, a reply may exist",
        };
        let (reason, provenance) = match (f.kind, f.basis) {
            (FollowUpKind::AwaitingReply, b) => (
                format!("no reply after {} day(s); {basis}", f.age_days),
                prov_of(b),
            ),
            (FollowUpKind::NeedsReply, b) => (
                format!("not answered after {} day(s); {basis}", f.age_days),
                prov_of(b),
            ),
        };
        let item = BriefItem {
            source,
            title: Untrusted(f.subject.clone()),
            evidence: vec![Evidence {
                reason,
                excerpt: Some(Untrusted(f.counterpart.clone())),
            }],
            provenance,
        };
        match f.kind {
            FollowUpKind::AwaitingReply => {
                let since = OffsetDateTime::from_unix_timestamp(f.date_unix)
                    .ok()
                    .and_then(|t| t.format(&Rfc3339).ok())
                    .unwrap_or_default();
                build.follow_ups.push(FollowUp {
                    item,
                    waiting_since: since,
                });
            }
            FollowUpKind::NeedsReply => {
                build
                    .actions
                    .push((f.age_days, ActionItem { item, due: None }));
            }
        }
    }
}

fn prov_of(b: LinkBasis) -> Provenance {
    match b {
        LinkBasis::Exact => Provenance::Fact,
        LinkBasis::Heuristic => Provenance::Heuristic,
    }
}

/// Accumulates one run's output.
#[derive(Default)]
struct Build {
    accounts: BTreeMap<AccountId, AccountRunStatus>,
    highlights: Vec<(u32, BriefItem)>,
    actions: Vec<(u32, ActionItem)>,
    follow_ups: Vec<FollowUp>,
    notes: Vec<String>,
    /// Newest UID per (account, folder, UIDVALIDITY) seen this run; becomes the cursor.
    cursors: BTreeMap<(AccountId, String, u32), u32>,
    ai_candidates: Vec<MessageSummary>,
    ai_summary: Option<AiSummary>,
}

impl Build {
    fn into_brief(
        mut self,
        generated: OffsetDateTime,
        window_start: OffsetDateTime,
    ) -> Result<Brief> {
        // Highest score first; the sort is stable so ties keep arrival (newest-first) order.
        self.highlights
            .sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        self.actions
            .sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        let mut notes = std::mem::take(&mut self.notes);
        for (kind, len) in [
            ("highlights", self.highlights.len()),
            ("actions", self.actions.len()),
            ("follow_ups", self.follow_ups.len()),
        ] {
            if len > MAX_ITEMS_PER_SECTION {
                notes.push(format!(
                    "{kind}: {len} items found, showing the first {MAX_ITEMS_PER_SECTION}"
                ));
            }
        }
        Ok(Brief {
            generated_at: rfc3339(generated)?,
            window_start: rfc3339(window_start)?,
            window_end: rfc3339(generated)?,
            accounts: self.accounts,
            highlights: self
                .highlights
                .into_iter()
                .take(MAX_ITEMS_PER_SECTION)
                .map(|(_, i)| i)
                .collect(),
            actions: self
                .actions
                .into_iter()
                .take(MAX_ITEMS_PER_SECTION)
                .map(|(_, i)| i)
                .collect(),
            follow_ups: self
                .follow_ups
                .into_iter()
                .take(MAX_ITEMS_PER_SECTION)
                .collect(),
            ai_summary: self.ai_summary,
            notes,
        })
    }
}
