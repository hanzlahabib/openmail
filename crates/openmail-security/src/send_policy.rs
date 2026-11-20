//! Who decides whether a send may proceed: the server OWNER chooses, in server configuration
//! only (never through an MCP tool, so an agent cannot change it).
//!
//! * [`ApprovalMode::OwnerOnly`] (default): every send needs a single-use approval a human granted
//!   out of band (`openmail-mcp approvals grant`). Nothing is delegated.
//! * [`ApprovalMode::Rules`]: the owner pre-authorizes narrow standing rules ("allow always" for
//!   one account and one recipient address or domain, with a daily cap and an expiry). A send that
//!   matches a live rule goes ahead; everything else still needs a human.
//! * [`ApprovalMode::Delegated`]: the connected client's own confirmation (for example ChatGPT's
//!   "allow this action" prompt) is trusted as the gate. The server only enforces a per-account
//!   daily cap. This removes the server-side human check, so it is opt-in and loudly documented.
//!
//! In every mode a valid human-granted token still works, and every automatic decision is
//! counted and logged. Recipient patterns are exact addresses or `@domain`; "everyone" cannot be
//! expressed.
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};
use openmail_smtp::{ApprovalConsumer, SendRequestDescriptor};
use rusqlite::{Connection, params};

use crate::clock::Clock;

/// A standing rule may not outlive this, so "allow always" is never forever.
pub const MAX_RULE_DAYS: u32 = 90;
/// Per-day send ceiling a rule may grant.
pub const MAX_RULE_PER_DAY: u32 = 500;
/// Recipients per message a rule will approve (bulk blasts need a human).
pub const MAX_RULE_RECIPIENTS: usize = 10;
/// Default ceiling for `Delegated` mode per account and day.
pub const DEFAULT_DELEGATED_DAILY_LIMIT: u32 = 25;
/// Per message in delegated mode. Mass mailing is a human decision; a prompt-injected agent that
/// can reach 100 recipients in one call defeats the daily cap.
pub const DEFAULT_DELEGATED_MAX_RECIPIENTS: usize = 5;
/// Appended to the principal by tools whose automatic approval must never apply (forwarding
/// existing mail is the exfiltration path of a prompt injection). Such sends need a human token.
pub const HUMAN_ONLY_SUFFIX: &str = "#human-only";
const DAY_SECS: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    OwnerOnly,
    Rules,
    Delegated,
}

impl ApprovalMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "owner_only" | "owner" => Ok(Self::OwnerOnly),
            "rules" => Ok(Self::Rules),
            "delegated" => Ok(Self::Delegated),
            other => Err(Error::new(
                ErrorCode::ConfigInvalid,
                format!("unknown approval mode `{other}` (owner_only, rules or delegated)"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnerOnly => "owner_only",
            Self::Rules => "rules",
            Self::Delegated => "delegated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub account: AccountId,
    /// `person@example.com` or `@example.com`.
    pub pattern: String,
    pub max_per_day: u32,
    pub expires_at: u64,
    pub note: String,
}

fn db(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Internal, format!("send policy store: {e}"))
}

/// SQLite integers are signed; clock values never get near the limit.
fn i(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn matches(pattern: &str, recipient: &str) -> bool {
    let r = recipient.trim().to_ascii_lowercase();
    if let Some(domain) = pattern.strip_prefix('@') {
        r.rsplit_once('@').is_some_and(|(_, d)| d == domain)
    } else {
        r == pattern
    }
}

/// Validate and normalise a pattern. Rejects anything that could mean "everyone".
pub fn normalize_pattern(raw: &str) -> Result<String> {
    let p = raw.trim().to_ascii_lowercase();
    let bad = || {
        Error::new(
            ErrorCode::InvalidInput,
            "pattern must be user@domain or @domain",
        )
    };
    if p.contains(['*', ' ', ',', ';']) || p.matches('@').count() != 1 {
        return Err(bad());
    }
    let (local, domain) = p.split_once('@').ok_or_else(bad)?;
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(bad());
    }
    let _ = local;
    Ok(p)
}

#[derive(Debug)]
pub struct SendPolicyStore {
    conn: Mutex<Connection>,
}

impl SendPolicyStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(db)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, pattern TEXT NOT NULL,
                max_per_day INTEGER NOT NULL, expires_at INTEGER NOT NULL, note TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS send_log (
                account TEXT NOT NULL, at INTEGER NOT NULL, via TEXT NOT NULL, rule_id INTEGER);
             CREATE INDEX IF NOT EXISTS send_log_account ON send_log (account, at);",
        )
        .map_err(db)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn add_rule(
        &self,
        account: &AccountId,
        pattern: &str,
        max_per_day: u32,
        days: u32,
        note: &str,
        now: u64,
    ) -> Result<i64> {
        let pattern = normalize_pattern(pattern)?;
        if max_per_day == 0 || max_per_day > MAX_RULE_PER_DAY {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                format!("per-day limit must be 1 to {MAX_RULE_PER_DAY}"),
            ));
        }
        if days == 0 || days > MAX_RULE_DAYS {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                format!("a rule lasts 1 to {MAX_RULE_DAYS} days"),
            ));
        }
        let c = self.lock();
        c.execute(
            "INSERT INTO rules (account, pattern, max_per_day, expires_at, note) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account.as_str(),
                pattern,
                max_per_day,
                i(now + u64::from(days) * DAY_SECS),
                note.chars().take(200).collect::<String>()
            ],
        )
        .map_err(db)?;
        Ok(c.last_insert_rowid())
    }

    pub fn revoke(&self, id: i64) -> Result<bool> {
        Ok(self
            .lock()
            .execute(
                "UPDATE rules SET revoked = 1 WHERE id = ?1 AND revoked = 0",
                [id],
            )
            .map_err(db)?
            > 0)
    }

    pub fn list(&self, now: u64) -> Result<Vec<Rule>> {
        let c = self.lock();
        let mut st = c
            .prepare("SELECT id, account, pattern, max_per_day, expires_at, note FROM rules WHERE revoked = 0 AND expires_at > ?1 ORDER BY id")
            .map_err(db)?;
        let rows = st
            .query_map([i(now)], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(db)?;
        rows.map(|r| {
            let (id, account, pattern, max_per_day, expires_at, note) = r.map_err(db)?;
            let expires_at = u64::try_from(expires_at).unwrap_or(0);
            Ok(Rule {
                id,
                account: AccountId::new(account)?,
                pattern,
                max_per_day,
                expires_at,
                note,
            })
        })
        .collect()
    }

    fn sent_today(&self, account: &str, rule: Option<i64>, now: u64) -> Result<u32> {
        let since = i(now.saturating_sub(DAY_SECS));
        let c = self.lock();
        let n: u32 = match rule {
            Some(id) => c.query_row(
                "SELECT COUNT(*) FROM send_log WHERE rule_id = ?1 AND at > ?2",
                params![id, since],
                |r| r.get(0),
            ),
            None => c.query_row(
                "SELECT COUNT(*) FROM send_log WHERE account = ?1 AND at > ?2",
                params![account, since],
                |r| r.get(0),
            ),
        }
        .map_err(db)?;
        Ok(n)
    }

    fn record(&self, account: &str, via: &str, rule: Option<i64>, now: u64) -> Result<()> {
        self.lock()
            .execute(
                "INSERT INTO send_log (account, at, via, rule_id) VALUES (?1, ?2, ?3, ?4)",
                params![account, i(now), via, rule],
            )
            .map_err(db)?;
        Ok(())
    }

    /// A live rule for `account` that covers every recipient and still has quota today.
    fn rule_for(
        &self,
        account: &AccountId,
        recipients: &[String],
        now: u64,
    ) -> Result<Option<Rule>> {
        if recipients.is_empty() || recipients.len() > MAX_RULE_RECIPIENTS {
            return Ok(None);
        }
        for rule in self
            .list(now)?
            .into_iter()
            .filter(|r| &r.account == account)
        {
            if recipients.iter().all(|rcpt| matches(&rule.pattern, rcpt))
                && self.sent_today(account.as_str(), Some(rule.id), now)? < rule.max_per_day
            {
                return Ok(Some(rule));
            }
        }
        Ok(None)
    }

    /// Atomically check the account's daily ceiling (counted in RECIPIENTS) and reserve the send.
    /// Check and insert share one write transaction, so parallel calls cannot overspend the cap.
    fn reserve_delegated(
        &self,
        account: &AccountId,
        recipients: u32,
        limit: u32,
        now: u64,
    ) -> Result<bool> {
        let mut c = self.lock();
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM send_log WHERE account = ?1 AND at > ?2",
                params![account.as_str(), i(now.saturating_sub(DAY_SECS))],
                |r| r.get(0),
            )
            .map_err(db)?;
        if used.saturating_add(recipients) > limit {
            return Ok(false);
        }
        for _ in 0..recipients {
            tx.execute(
                "INSERT INTO send_log (account, at, via, rule_id) VALUES (?1, ?2, 'delegated', NULL)",
                params![account.as_str(), i(now)],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(true)
    }

    /// Same, for a standing rule's per-day quota (counted in messages).
    fn reserve_rule(&self, rule: &Rule, now: u64) -> Result<bool> {
        let mut c = self.lock();
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let used: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM send_log WHERE rule_id = ?1 AND at > ?2",
                params![rule.id, i(now.saturating_sub(DAY_SECS))],
                |r| r.get(0),
            )
            .map_err(db)?;
        if used >= rule.max_per_day {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO send_log (account, at, via, rule_id) VALUES (?1, ?2, 'rule', ?3)",
            params![rule.account.as_str(), i(now), rule.id],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(true)
    }
}

/// Wraps the human-approval verifier with the owner's chosen mode.
pub struct PolicyConsumer<V, C> {
    mode: ApprovalMode,
    store: Arc<SendPolicyStore>,
    inner: V,
    clock: C,
    delegated_daily_limit: u32,
    delegated_max_recipients: usize,
}

impl<V, C> std::fmt::Debug for PolicyConsumer<V, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyConsumer")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl<V, C> PolicyConsumer<V, C> {
    pub fn new(
        mode: ApprovalMode,
        store: Arc<SendPolicyStore>,
        inner: V,
        clock: C,
        delegated_daily_limit: u32,
    ) -> Self {
        Self {
            mode,
            store,
            inner,
            clock,
            delegated_daily_limit,
            delegated_max_recipients: DEFAULT_DELEGATED_MAX_RECIPIENTS,
        }
    }

    #[must_use]
    pub fn with_delegated_max_recipients(mut self, n: usize) -> Self {
        self.delegated_max_recipients = n.max(1);
        self
    }
}

impl<V: ApprovalConsumer, C: Clock> ApprovalConsumer for PolicyConsumer<V, C> {
    fn consume(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
        token: Option<&str>,
    ) -> Result<()> {
        let now = self.clock.unix_secs();
        let account = descriptor.account();
        // A human-granted token always wins and is always consumed; automatic paths only apply
        // when the caller presented none, and never for human-only actions (forwarding).
        if token.is_some() || principal.ends_with(HUMAN_ONLY_SUFFIX) {
            self.inner.consume(principal, descriptor, token)?;
            self.store.record(account.as_str(), "human", None, now)?;
            return Ok(());
        }
        match self.mode {
            ApprovalMode::OwnerOnly => self.inner.consume(principal, descriptor, None),
            ApprovalMode::Rules => {
                if let Some(rule) = self.store.rule_for(account, descriptor.recipients(), now)?
                    && self.store.reserve_rule(&rule, now)?
                {
                    tracing::info!(account = %account, rule = rule.id, "send allowed by standing rule");
                    Ok(())
                } else {
                    self.inner.consume(principal, descriptor, None)
                }
            }
            ApprovalMode::Delegated => {
                let n = descriptor.recipients().len();
                if n == 0 || n > self.delegated_max_recipients {
                    // Mass mailing is never delegated: it needs a human token.
                    return self.inner.consume(principal, descriptor, None);
                }
                let n32 = u32::try_from(n).unwrap_or(u32::MAX);
                if self
                    .store
                    .reserve_delegated(account, n32, self.delegated_daily_limit, now)?
                {
                    tracing::info!(account = %account, recipients = n, "send allowed by delegated approval");
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorCode::LimitExceeded,
                        "the daily send limit for this account was reached",
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn patterns_cannot_mean_everyone() {
        assert_eq!(normalize_pattern(" @Example.com ").unwrap(), "@example.com");
        assert_eq!(normalize_pattern("a@b.co").unwrap(), "a@b.co");
        for bad in [
            "*",
            "@",
            "@com",
            "*@x.com",
            "a@b.com, c@d.com",
            "",
            "a@@b.com",
            "x",
        ] {
            assert!(normalize_pattern(bad).is_err(), "{bad}");
        }
        assert!(matches("@example.com", "Bob@EXAMPLE.com"));
        assert!(!matches("@example.com", "bob@evilexample.com"));
        assert!(!matches("@example.com", "bob@sub.example.com"));
        assert!(matches("bob@example.com", "BOB@example.com"));
    }

    #[test]
    fn rules_expire_cap_per_day_and_revoke() {
        let s = SendPolicyStore::open_in_memory().unwrap();
        let acc = AccountId::new("work").unwrap();
        let id = s.add_rule(&acc, "@example.com", 2, 1, "t", 1000).unwrap();
        let rcpt = vec!["a@example.com".to_owned()];
        assert!(s.rule_for(&acc, &rcpt, 1001).unwrap().is_some());
        s.record("work", "rule", Some(id), 1002).unwrap();
        s.record("work", "rule", Some(id), 1003).unwrap();
        assert!(
            s.rule_for(&acc, &rcpt, 1004).unwrap().is_none(),
            "quota used"
        );
        assert!(
            s.rule_for(&acc, &rcpt, 1000 + DAY_SECS * 2)
                .unwrap()
                .is_none(),
            "expired"
        );
        // Other recipients, other accounts and too many recipients never match.
        let s2 = SendPolicyStore::open_in_memory().unwrap();
        s2.add_rule(&acc, "@example.com", 5, 1, "", 0).unwrap();
        assert!(
            s2.rule_for(&acc, &["x@other.com".to_owned()], 1)
                .unwrap()
                .is_none()
        );
        assert!(
            s2.rule_for(&AccountId::new("other").unwrap(), &rcpt, 1)
                .unwrap()
                .is_none()
        );
        let many: Vec<String> = (0..=MAX_RULE_RECIPIENTS)
            .map(|i| format!("u{i}@example.com"))
            .collect();
        assert!(s2.rule_for(&acc, &many, 1).unwrap().is_none());
        let rid = s2.list(1).unwrap()[0].id;
        assert!(s2.revoke(rid).unwrap());
        assert!(s2.rule_for(&acc, &rcpt, 1).unwrap().is_none());
        assert!(s.add_rule(&acc, "@example.com", 0, 1, "", 0).is_err());
        assert!(
            s.add_rule(&acc, "@example.com", 1, MAX_RULE_DAYS + 1, "", 0)
                .is_err()
        );
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(ApprovalMode::parse("").unwrap(), ApprovalMode::OwnerOnly);
        assert_eq!(ApprovalMode::parse("Rules").unwrap(), ApprovalMode::Rules);
        assert_eq!(
            ApprovalMode::parse("delegated").unwrap(),
            ApprovalMode::Delegated
        );
        assert!(ApprovalMode::parse("yolo").is_err());
    }
}
