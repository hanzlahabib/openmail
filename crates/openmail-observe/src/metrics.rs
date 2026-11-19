//! In-process metrics registry with a Prometheus text exporter. Nothing is
//! sent anywhere: the host decides whether to expose the rendered text.

use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Monotonic counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    ImapConnectionFailures,
    AuthFailures,
    McpRequestFailures,
    RateLimitRejections,
    SmtpAttempts,
    SmtpUncertain,
    FailedMailboxScans,
    Retries,
}

impl Counter {
    pub const ALL: [Counter; 8] = [
        Counter::ImapConnectionFailures,
        Counter::AuthFailures,
        Counter::McpRequestFailures,
        Counter::RateLimitRejections,
        Counter::SmtpAttempts,
        Counter::SmtpUncertain,
        Counter::FailedMailboxScans,
        Counter::Retries,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Counter::ImapConnectionFailures => "imap_connection_failures",
            Counter::AuthFailures => "auth_failures",
            Counter::McpRequestFailures => "mcp_request_failures",
            Counter::RateLimitRejections => "rate_limit_rejections",
            Counter::SmtpAttempts => "smtp_attempts",
            Counter::SmtpUncertain => "smtp_uncertain",
            Counter::FailedMailboxScans => "failed_mailbox_scans",
            Counter::Retries => "retries",
        }
    }

    const fn help(self) -> &'static str {
        match self {
            Counter::ImapConnectionFailures => "IMAP connection attempts that failed",
            Counter::AuthFailures => "Authentication failures",
            Counter::McpRequestFailures => "MCP requests that returned an error",
            Counter::RateLimitRejections => "Requests rejected by rate limiting",
            Counter::SmtpAttempts => "SMTP send attempts",
            Counter::SmtpUncertain => "SMTP sends with an uncertain outcome",
            Counter::FailedMailboxScans => "Mailbox scans that failed",
            Counter::Retries => "Operation retries",
        }
    }
}

/// Latency histograms (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Histogram {
    SearchLatency,
    ToolLatency,
    BriefDuration,
}

impl Histogram {
    pub const ALL: [Histogram; 3] = [
        Histogram::SearchLatency,
        Histogram::ToolLatency,
        Histogram::BriefDuration,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Histogram::SearchLatency => "search_latency_seconds",
            Histogram::ToolLatency => "tool_latency_seconds",
            Histogram::BriefDuration => "brief_duration_seconds",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Bucket upper bounds in seconds: sub-10ms cache hits up to a 60s brief.
pub const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0, 60.0,
];

#[derive(Debug, Default)]
struct HistState {
    /// Per-bucket (non-cumulative) counts; last slot is the +Inf overflow.
    buckets: [u64; BUCKETS.len() + 1],
    sum: f64,
    count: u64,
}

/// Thread-safe registry. Cheap to share behind an `Arc`.
#[derive(Debug, Default)]
pub struct Metrics {
    counters: [AtomicU64; Counter::ALL.len()],
    hists: [Mutex<HistState>; Histogram::ALL.len()],
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self, c: Counter) {
        self.add(c, 1);
    }

    pub fn add(&self, c: Counter, n: u64) {
        self.counters[c as usize].fetch_add(n, Ordering::Relaxed);
    }

    pub fn counter(&self, c: Counter) -> u64 {
        self.counters[c as usize].load(Ordering::Relaxed)
    }

    pub fn observe(&self, h: Histogram, d: Duration) {
        let secs = d.as_secs_f64();
        // A poisoned lock only means another observer panicked; the data is
        // plain numbers, so keep recording.
        let mut s = self.hists[h.index()]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let slot = BUCKETS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS.len());
        s.buckets[slot] += 1;
        s.sum += secs;
        s.count += 1;
    }

    /// (count, sum seconds) for a histogram.
    pub fn histogram_totals(&self, h: Histogram) -> (u64, f64) {
        let s = self.hists[h.index()]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        (s.count, s.sum)
    }

    /// Renders Prometheus text exposition format (all metrics prefixed `openmail_`).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        for c in Counter::ALL {
            let name = format!("openmail_{}_total", c.name());
            let _ = writeln!(out, "# HELP {name} {}", c.help());
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {}", self.counter(c));
        }
        for h in Histogram::ALL {
            let name = format!("openmail_{}", h.name());
            let s = self.hists[h.index()]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(out, "# TYPE {name} histogram");
            let mut cumulative = 0u64;
            for (i, bound) in BUCKETS.iter().enumerate() {
                cumulative += s.buckets[i];
                let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {cumulative}");
            }
            let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {}", s.count);
            let _ = writeln!(out, "{name}_sum {}", s.sum);
            let _ = writeln!(out, "{name}_count {}", s.count);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_render() {
        let m = Metrics::new();
        m.inc(Counter::AuthFailures);
        m.add(Counter::Retries, 3);
        assert_eq!(m.counter(Counter::AuthFailures), 1);
        assert_eq!(m.counter(Counter::SmtpUncertain), 0);
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE openmail_auth_failures_total counter"));
        assert!(text.contains("openmail_auth_failures_total 1\n"));
        assert!(text.contains("openmail_retries_total 3\n"));
    }

    #[test]
    fn all_required_names_are_exported() {
        let text = Metrics::new().render_prometheus();
        for n in [
            "imap_connection_failures",
            "auth_failures",
            "search_latency",
            "tool_latency",
            "mcp_request_failures",
            "rate_limit_rejections",
            "smtp_attempts",
            "smtp_uncertain",
            "brief_duration",
            "failed_mailbox_scans",
            "retries",
        ] {
            assert!(text.contains(&format!("openmail_{n}")), "missing {n}");
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let m = Metrics::new();
        m.observe(Histogram::ToolLatency, Duration::from_millis(3));
        m.observe(Histogram::ToolLatency, Duration::from_millis(200));
        m.observe(Histogram::ToolLatency, Duration::from_secs(120));
        let (count, sum) = m.histogram_totals(Histogram::ToolLatency);
        assert_eq!(count, 3);
        assert!((sum - 120.203).abs() < 1e-6);
        let text = m.render_prometheus();
        assert!(text.contains("openmail_tool_latency_seconds_bucket{le=\"0.005\"} 1\n"));
        assert!(text.contains("openmail_tool_latency_seconds_bucket{le=\"0.25\"} 2\n"));
        assert!(text.contains("openmail_tool_latency_seconds_bucket{le=\"60\"} 2\n"));
        assert!(text.contains("openmail_tool_latency_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("openmail_tool_latency_seconds_count 3\n"));
    }

    #[test]
    fn concurrent_increments_are_not_lost() {
        let m = std::sync::Arc::new(Metrics::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let m = m.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        m.inc(Counter::SmtpAttempts);
                    }
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().is_ok());
        }
        assert_eq!(m.counter(Counter::SmtpAttempts), 4000);
    }
}
