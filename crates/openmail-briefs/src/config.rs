//! Optional `[briefs]` configuration, read from a `briefs.toml` that sits next to the main
//! config file (`<config dir>/briefs.toml`). It is deliberately a separate file so the core
//! `Config` stays untouched: a deployment that never writes `briefs.toml` gets the defaults
//! below (heuristics only, no AI, no schedules, no digests).
//!
//! ```toml
//! [briefs]
//! lookback = "24h"
//! folder = "INBOX"
//!
//! [[briefs.rules]]            # same shape as classify::UserRuleSpec
//! name = "vip"
//! category = "client_inquiry"
//! sender_domains = ["bigclient.example"]
//!
//! [briefs.digest]             # opt-in: email the brief to this account's OWN address
//! account = "work"
//!
//! [[briefs.schedule]]         # opt-in: nothing runs unless enabled = true
//! id = "morning"
//! cron = "0 8 * * 1-5"
//! timezone = "Europe/Berlin"
//! enabled = true
//! accounts = ["work", "home"] # default: every configured account
//! digest = true
//!
//! [briefs.ai]                 # opt-in: metadata-only unless the policy says otherwise
//! endpoint = "http://127.0.0.1:11434/v1/chat/completions"
//! model = "llama3"
//! api_key_env = "OPENMAIL_BRIEFS_AI_KEY"
//! allowed_accounts = ["work"]
//! allowed_hosts = ["127.0.0.1"]
//! ```
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use serde::Deserialize;

use crate::ai::AiPolicy;
use crate::classify::UserRuleSpec;
use crate::scheduler::{JobSpec, MissedPolicy, Schedule};

/// File name looked up next to the main config.
pub const BRIEFS_FILE: &str = "briefs.toml";

/// Longest lookback a brief may cover. Past this the per-account message cap makes the result
/// a sample, not a summary, so it is refused rather than silently truncated.
pub const MAX_LOOKBACK: Duration = Duration::from_secs(90 * 24 * 3600);

const DEFAULT_LOOKBACK: &str = "24h";
const DEFAULT_FOLDER: &str = "INBOX";
/// Mid-sized mailbox day: enough for a busy inbox, small enough to classify and render quickly.
const DEFAULT_MAX_MESSAGES: usize = 200;
const DEFAULT_ACCOUNT_TIMEOUT_SECS: u64 = 30;
/// Below the default IMAP per-process connection cap so a brief never starves interactive tools.
const DEFAULT_CONCURRENCY: usize = 4;
/// Reply expectations people actually have for business mail; both tunable.
const DEFAULT_AWAITING_DAYS: u32 = 3;
const DEFAULT_NEEDS_REPLY_DAYS: u32 = 2;
/// A scheduled run missed by more than this (machine asleep) is skipped, not replayed hours
/// later as a stale "morning" brief.
const SCHEDULE_GRACE: Duration = Duration::from_secs(6 * 3600);

/// Top-level file: the `[briefs]` table is optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefsFile {
    #[serde(default)]
    pub briefs: BriefsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BriefsConfig {
    /// `30m`, `24h`, `7d`.
    pub lookback: String,
    pub folder: String,
    pub max_messages_per_account: usize,
    pub per_account_timeout_secs: u64,
    pub max_concurrency: usize,
    pub awaiting_reply_after_days: u32,
    pub needs_reply_after_days: u32,
    pub rules: Vec<UserRuleSpec>,
    pub ai: Option<AiConfig>,
    pub digest: Option<DigestConfig>,
    pub schedule: Vec<ScheduleConfig>,
}

impl Default for BriefsConfig {
    fn default() -> Self {
        Self {
            lookback: DEFAULT_LOOKBACK.to_owned(),
            folder: DEFAULT_FOLDER.to_owned(),
            max_messages_per_account: DEFAULT_MAX_MESSAGES,
            per_account_timeout_secs: DEFAULT_ACCOUNT_TIMEOUT_SECS,
            max_concurrency: DEFAULT_CONCURRENCY,
            awaiting_reply_after_days: DEFAULT_AWAITING_DAYS,
            needs_reply_after_days: DEFAULT_NEEDS_REPLY_DAYS,
            rules: Vec::new(),
            ai: None,
            digest: None,
            schedule: Vec::new(),
        }
    }
}

/// `[briefs.ai]`. The policy fields are flattened so the owner writes one table.
#[derive(Debug, Clone, Deserialize)]
pub struct AiConfig {
    pub endpoint: String,
    pub model: String,
    /// Environment variable holding the provider key; the key itself never lives in a file.
    pub api_key_env: String,
    #[serde(flatten)]
    pub policy: AiPolicy,
}

/// `[briefs.digest]`: the account whose own address receives digests. There is no recipient
/// field on purpose; a digest can only ever go to this account's owner.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestConfig {
    pub account: AccountId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    pub id: String,
    /// Standard 5-field cron expression.
    pub cron: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Opt-in: a schedule never runs unless this is true.
    #[serde(default)]
    pub enabled: bool,
    /// Empty = every configured account.
    #[serde(default)]
    pub accounts: Vec<AccountId>,
    pub lookback: Option<String>,
    /// Email the result through `[briefs.digest]`.
    #[serde(default)]
    pub digest: bool,
}

fn default_timezone() -> String {
    "UTC".to_owned()
}

impl ScheduleConfig {
    pub fn job_spec(&self, created_at: DateTime<Utc>) -> JobSpec {
        JobSpec {
            id: self.id.clone(),
            schedule: Schedule::Cron(self.cron.clone()),
            timezone: self.timezone.clone(),
            enabled: self.enabled,
            created_at,
            missed: MissedPolicy::SkipOlderThan(SCHEDULE_GRACE),
        }
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::ConfigInvalid, msg)
}

impl BriefsConfig {
    /// `<dir of main config>/briefs.toml`.
    pub fn path_next_to(main_config: &Path) -> PathBuf {
        main_config.with_file_name(BRIEFS_FILE)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let file: BriefsFile =
            toml::from_str(text).map_err(|e| invalid(format!("briefs.toml: {}", e.message())))?;
        file.briefs.validate()?;
        Ok(file.briefs)
    }

    /// A missing file is the default configuration; an unreadable or invalid one is an error
    /// (silently ignoring a broken file would hide a mistyped schedule or AI policy).
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(invalid(format!("reading {}: {}", path.display(), e.kind()))),
        }
    }

    pub fn lookback(&self) -> Result<Duration> {
        parse_lookback(&self.lookback)
    }

    pub fn validate(&self) -> Result<()> {
        self.lookback()?;
        if self.folder.is_empty() {
            return Err(invalid("briefs.folder must not be empty"));
        }
        if self.max_messages_per_account == 0 || self.max_concurrency == 0 {
            return Err(invalid(
                "briefs.max_messages_per_account and max_concurrency must be at least 1",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.schedule {
            if s.id.is_empty() || !seen.insert(s.id.as_str()) {
                return Err(invalid(format!(
                    "briefs.schedule ids must be unique and non-empty (`{}`)",
                    s.id
                )));
            }
            if let Some(l) = &s.lookback {
                parse_lookback(l)?;
            }
            if s.digest && self.digest.is_none() {
                return Err(invalid(format!(
                    "schedule `{}` wants a digest but [briefs.digest] is not configured",
                    s.id
                )));
            }
            // Compiles cron + timezone now so a typo fails at startup, not at 08:00.
            crate::scheduler::CompiledJob::compile(s.job_spec(Utc::now()))
                .map_err(|e| invalid(format!("schedule `{}`: {e}", s.id)))?;
        }
        crate::classify::Classifier::with_user_rules(self.rules.clone())
            .map_err(|e| invalid(format!("briefs.rules: {e}")))?;
        Ok(())
    }

    pub fn has_enabled_schedules(&self) -> bool {
        self.schedule.iter().any(|s| s.enabled)
    }
}

/// `90s`, `30m`, `24h`, `7d`; bounded by [`MAX_LOOKBACK`].
pub fn parse_lookback(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let split = raw
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| invalid(format!("lookback `{raw}` needs a unit (s, m, h or d)")))?;
    let (digits, unit) = raw.split_at(split);
    let n: u64 = digits
        .parse()
        .map_err(|_| invalid(format!("lookback `{raw}` must start with a number")))?;
    let unit_secs: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => {
            return Err(invalid(format!(
                "lookback unit `{unit}` must be s, m, h or d"
            )));
        }
    };
    let secs = n
        .checked_mul(unit_secs)
        .ok_or_else(|| invalid("lookback is too large"))?;
    let d = Duration::from_secs(secs);
    if d.is_zero() || d > MAX_LOOKBACK {
        return Err(invalid(format!(
            "lookback `{raw}` must be between 1s and {} days",
            MAX_LOOKBACK.as_secs() / 86_400
        )));
    }
    Ok(d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_and_empty_file_give_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = BriefsConfig::load(&dir.path().join("briefs.toml")).unwrap();
        assert_eq!(c.lookback().unwrap(), Duration::from_secs(86_400));
        assert!(c.ai.is_none() && c.schedule.is_empty() && c.digest.is_none());
        assert!(!c.has_enabled_schedules());
        assert!(BriefsConfig::from_toml("").unwrap().rules.is_empty());
    }

    #[test]
    fn path_sits_next_to_the_main_config() {
        assert_eq!(
            BriefsConfig::path_next_to(Path::new("/etc/om/config.toml")),
            PathBuf::from("/etc/om/briefs.toml")
        );
    }

    #[test]
    fn lookback_parses_units_and_rejects_nonsense() {
        assert_eq!(parse_lookback("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_lookback("7d").unwrap(), Duration::from_secs(604_800));
        for bad in [
            "",
            "h",
            "10",
            "0h",
            "5w",
            "-3h",
            "91d",
            "99999999999999999999h",
        ] {
            assert!(parse_lookback(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn full_example_parses_and_validates() {
        let c = BriefsConfig::from_toml(
            r#"
[briefs]
lookback = "12h"
[[briefs.rules]]
name = "vip"
category = "client_inquiry"
sender_domains = ["big.example"]
[briefs.digest]
account = "work"
[[briefs.schedule]]
id = "morning"
cron = "0 8 * * 1-5"
timezone = "Europe/Berlin"
enabled = true
digest = true
[briefs.ai]
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
model = "m"
api_key_env = "K"
allowed_accounts = ["work"]
allowed_hosts = ["127.0.0.1"]
"#,
        )
        .unwrap();
        assert!(c.has_enabled_schedules());
        let ai = c.ai.unwrap();
        assert_eq!(ai.policy.allowed_accounts.len(), 1);
        // Metadata-only default survives flattening.
        assert!(!ai.policy.allow_bodies_off_machine);
    }

    #[test]
    fn broken_settings_fail_at_load_time() {
        for bad in [
            "[briefs]\nlookback = \"soon\"",
            "[briefs]\nunknown = 1",
            "[[briefs.schedule]]\nid = \"a\"\ncron = \"not cron\"",
            "[[briefs.schedule]]\nid = \"a\"\ncron = \"0 8 * * *\"\ntimezone = \"Mars/Base\"",
            "[[briefs.schedule]]\nid = \"a\"\ncron = \"0 8 * * *\"\ndigest = true",
            "[[briefs.schedule]]\nid = \"a\"\ncron = \"0 8 * * *\"\n[[briefs.schedule]]\nid = \"a\"\ncron = \"0 9 * * *\"",
            "[[briefs.rules]]\nname = \"r\"\ncategory = \"newsletter\"\nsubject_regex = \"(\"",
        ] {
            assert!(BriefsConfig::from_toml(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn schedules_are_opt_in() {
        let c = BriefsConfig::from_toml("[[briefs.schedule]]\nid = \"a\"\ncron = \"0 8 * * *\"")
            .unwrap();
        assert!(!c.schedule[0].enabled);
        assert!(!c.has_enabled_schedules());
    }
}
