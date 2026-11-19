//! Token-bucket rate limiting per account plus a global bucket. Time comes from an
//! injected monotonic clock, so tests are deterministic and wall-clock jumps cannot
//! refill buckets.
use std::collections::HashMap;
use std::sync::Mutex;

use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};

use crate::clock::Clock;

/// Hard cap on tracked accounts so unbounded distinct ids cannot grow memory.
/// Matches the configured-account ceiling in `openmail-core`.
const MAX_TRACKED_ACCOUNTS: usize = openmail_core::config::MAX_CONFIGURED_ACCOUNTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Burst size (bucket capacity).
    pub capacity: u32,
    /// Sustained refill rate in tokens per second.
    pub refill_per_sec: u32,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens scaled by 1000 so refill is exact in milliseconds.
    milli_tokens: u64,
    last_ms: u64,
}

impl Bucket {
    fn full(cfg: RateLimitConfig, now_ms: u64) -> Self {
        Self {
            milli_tokens: u64::from(cfg.capacity) * 1000,
            last_ms: now_ms,
        }
    }
    fn refill(&mut self, cfg: RateLimitConfig, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        let cap = u64::from(cfg.capacity) * 1000;
        self.milli_tokens = self
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(u64::from(cfg.refill_per_sec)))
            .min(cap);
        self.last_ms = self.last_ms.max(now_ms);
    }
}

#[derive(Debug)]
struct State {
    global: Bucket,
    per_account: HashMap<AccountId, Bucket>,
}

pub struct RateLimiter<C> {
    clock: C,
    global: RateLimitConfig,
    per_account: RateLimitConfig,
    state: Mutex<State>,
}

impl<C> std::fmt::Debug for RateLimiter<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("global", &self.global)
            .field("per_account", &self.per_account)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> RateLimiter<C> {
    pub fn new(clock: C, global: RateLimitConfig, per_account: RateLimitConfig) -> Self {
        let now = clock.monotonic_ms();
        let state = State {
            global: Bucket::full(global, now),
            per_account: HashMap::new(),
        };
        Self {
            clock,
            global,
            per_account,
            state: Mutex::new(state),
        }
    }

    /// Spends one token from both the account and global bucket, atomically: if
    /// either is empty nothing is spent. Poisoned state fails closed.
    pub fn check(&self, account: &AccountId) -> Result<()> {
        let now = self.clock.monotonic_ms();
        let mut st = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "rate limiter unavailable"))?;
        if !st.per_account.contains_key(account) && st.per_account.len() >= MAX_TRACKED_ACCOUNTS {
            return Err(Error::new(
                ErrorCode::RateLimited,
                "too many distinct accounts tracked",
            ));
        }
        let acct_cfg = self.per_account;
        let mut acct = st
            .per_account
            .get(account)
            .copied()
            .unwrap_or_else(|| Bucket::full(acct_cfg, now));
        acct.refill(acct_cfg, now);
        let mut glob = st.global;
        glob.refill(self.global, now);
        let ok = acct.milli_tokens >= 1000 && glob.milli_tokens >= 1000;
        if ok {
            acct.milli_tokens -= 1000;
            glob.milli_tokens -= 1000;
        }
        // Refill progress is kept even when denied so time is never lost.
        st.per_account.insert(account.clone(), acct);
        st.global = glob;
        if ok {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::RateLimited,
                format!("rate limit exceeded for account '{account}'"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::clock::testing::ManualClock;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }
    fn limiter(
        clock: Arc<ManualClock>,
        g: u32,
        a: u32,
        refill: u32,
    ) -> RateLimiter<Arc<ManualClock>> {
        RateLimiter::new(
            clock,
            RateLimitConfig {
                capacity: g,
                refill_per_sec: refill,
            },
            RateLimitConfig {
                capacity: a,
                refill_per_sec: refill,
            },
        )
    }
    impl Clock for Arc<ManualClock> {
        fn unix_secs(&self) -> u64 {
            (**self).unix_secs()
        }
        fn monotonic_ms(&self) -> u64 {
            (**self).monotonic_ms()
        }
    }

    #[test]
    fn burst_then_deny_then_refill() {
        let clk = Arc::new(ManualClock::new(1_000));
        let l = limiter(clk.clone(), 100, 3, 1);
        for _ in 0..3 {
            l.check(&id("a")).unwrap();
        }
        assert_eq!(
            l.check(&id("a")).unwrap_err().code(),
            ErrorCode::RateLimited
        );
        clk.advance_ms(999);
        assert!(l.check(&id("a")).is_err());
        clk.advance_ms(1);
        assert!(l.check(&id("a")).is_ok());
        assert!(l.check(&id("a")).is_err());
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let clk = Arc::new(ManualClock::new(0));
        let l = limiter(clk.clone(), 100, 2, 10);
        clk.advance_secs(3600);
        assert!(l.check(&id("a")).is_ok());
        assert!(l.check(&id("a")).is_ok());
        assert!(l.check(&id("a")).is_err());
    }

    #[test]
    fn accounts_are_independent_but_share_global() {
        let clk = Arc::new(ManualClock::new(0));
        let l = limiter(clk, 3, 2, 0);
        l.check(&id("a")).unwrap();
        l.check(&id("a")).unwrap();
        assert!(l.check(&id("a")).is_err()); // account bucket empty
        l.check(&id("b")).unwrap(); // other account unaffected; global now 0
        assert!(l.check(&id("c")).is_err()); // global exhausted
    }

    #[test]
    fn denied_by_global_does_not_spend_account_tokens() {
        let clk = Arc::new(ManualClock::new(0));
        let l = limiter(clk.clone(), 1, 5, 1);
        l.check(&id("a")).unwrap();
        assert!(l.check(&id("a")).is_err());
        clk.advance_secs(1);
        assert!(l.check(&id("a")).is_ok()); // account still had 4 tokens
    }

    #[test]
    fn wall_clock_jump_does_not_refill() {
        let clk = Arc::new(ManualClock::new(1_000));
        let l = limiter(clk.clone(), 10, 1, 1);
        l.check(&id("a")).unwrap();
        clk.set_unix(9_999_999);
        assert!(l.check(&id("a")).is_err());
    }

    #[test]
    fn id_flooding_cannot_bypass_or_grow_unbounded() {
        let clk = Arc::new(ManualClock::new(0));
        let l = limiter(clk, 1_000_000, 1, 0);
        let mut denied = 0;
        for i in 0..(MAX_TRACKED_ACCOUNTS + 10) {
            if l.check(&id(&format!("acct-{i}"))).is_err() {
                denied += 1;
            }
        }
        assert_eq!(denied, 10);
        // Existing accounts keep their own bucket (already spent).
        assert!(l.check(&id("acct-0")).is_err());
    }
}
