//! Injected time source so expiry and rate limiting are deterministic in tests.

/// Two clocks on purpose: approvals expire on wall-clock time (they are
/// persisted across processes), while rate limiting must not be fooled by
/// wall-clock jumps and uses a monotonic reading.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn unix_secs(&self) -> u64;
    /// Milliseconds since an arbitrary fixed origin; never goes backwards.
    fn monotonic_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self { origin: std::time::Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        // A clock before 1970 means the host is broken; 0 makes every approval
        // look unexpired only if its expiry is 0, which issuance never produces.
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }

    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::Clock;

    /// Manually advanced clock for tests.
    #[derive(Debug, Default)]
    pub struct ManualClock {
        unix: AtomicU64,
        mono: AtomicU64,
    }

    impl ManualClock {
        pub fn new(unix_secs: u64) -> Self {
            Self { unix: AtomicU64::new(unix_secs), mono: AtomicU64::new(0) }
        }
        pub fn advance_ms(&self, ms: u64) {
            self.mono.fetch_add(ms, Ordering::SeqCst);
            self.unix.fetch_add(ms / 1000, Ordering::SeqCst);
        }
        pub fn advance_secs(&self, s: u64) {
            self.advance_ms(s * 1000);
        }
        /// Simulates a wall-clock jump that must not affect the monotonic reading.
        pub fn set_unix(&self, s: u64) {
            self.unix.store(s, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn unix_secs(&self) -> u64 {
            self.unix.load(Ordering::SeqCst)
        }
        fn monotonic_ms(&self) -> u64 {
            self.mono.load(Ordering::SeqCst)
        }
    }
}
