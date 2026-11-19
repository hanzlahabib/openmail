//! In-process metrics registry with a Prometheus text exporter. Nothing is
//! sent anywhere: the host decides whether to expose the rendered text.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
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

/// Upper bound on distinct label sets per registry. Account ids come from the config and
/// tool/code names are static, so this is only a guard against a caller feeding unbounded
/// values; series past the cap are folded into the unlabeled one.
pub const MAX_SERIES: usize = 2048;

/// Longest label value kept; anything longer is truncated.
const MAX_LABEL_LEN: usize = 64;

/// Label set of one series. Values are restricted to `[A-Za-z0-9_.:-]` (anything else becomes
/// `_`) and a value containing `@` is replaced wholesale, so an e-mail address can never become a
/// label. Only account ids (never addresses), tool names and error codes are meant to go here.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Labels {
    account: Option<String>,
    tool: Option<String>,
    code: Option<String>,
}

fn clean_label(raw: &str) -> String {
    if raw.contains('@') {
        return "invalid".to_owned();
    }
    raw.chars()
        .take(MAX_LABEL_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl Labels {
    pub fn none() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn account(mut self, id: &str) -> Self {
        self.account = Some(clean_label(id));
        self
    }

    #[must_use]
    pub fn tool(mut self, name: &str) -> Self {
        self.tool = Some(clean_label(name));
        self
    }

    #[must_use]
    pub fn code(mut self, code: &str) -> Self {
        self.code = Some(clean_label(code));
        self
    }

    fn render(&self) -> String {
        let parts: Vec<String> = [
            ("account", &self.account),
            ("tool", &self.tool),
            ("code", &self.code),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}=\"{v}\"")))
        .collect();
        parts.join(",")
    }
}

#[derive(Debug, Default)]
struct HistState {
    /// Per-bucket (non-cumulative) counts; last slot is the +Inf overflow.
    buckets: [u64; BUCKETS.len() + 1],
    sum: f64,
    count: u64,
}

#[derive(Debug, Default)]
struct Inner {
    counters: BTreeMap<(usize, Labels), u64>,
    hists: BTreeMap<(usize, Labels), HistState>,
}

/// Thread-safe registry. Cheap to share behind an `Arc`.
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    // A poisoned lock only means another recorder panicked; the data is plain numbers,
    // so keep recording.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn inc(&self, c: Counter) {
        self.add_labeled(c, &Labels::none(), 1);
    }

    pub fn add(&self, c: Counter, n: u64) {
        self.add_labeled(c, &Labels::none(), n);
    }

    pub fn inc_labeled(&self, c: Counter, labels: &Labels) {
        self.add_labeled(c, labels, 1);
    }

    fn add_labeled(&self, c: Counter, labels: &Labels, n: u64) {
        let mut g = self.lock();
        let key = (c as usize, labels.clone());
        let key = if g.counters.contains_key(&key) || g.counters.len() < MAX_SERIES {
            key
        } else {
            (c as usize, Labels::none())
        };
        let slot = g.counters.entry(key).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// Total across every label set.
    pub fn counter(&self, c: Counter) -> u64 {
        self.lock()
            .counters
            .iter()
            .filter(|((i, _), _)| *i == c as usize)
            .map(|(_, v)| *v)
            .sum()
    }

    /// Value of one exact label set (0 when never recorded).
    pub fn counter_with(&self, c: Counter, labels: &Labels) -> u64 {
        self.lock()
            .counters
            .get(&(c as usize, labels.clone()))
            .copied()
            .unwrap_or(0)
    }

    pub fn observe(&self, h: Histogram, d: Duration) {
        self.observe_labeled(h, &Labels::none(), d);
    }

    pub fn observe_labeled(&self, h: Histogram, labels: &Labels, d: Duration) {
        let secs = d.as_secs_f64();
        let mut g = self.lock();
        let key = (h.index(), labels.clone());
        let key = if g.hists.contains_key(&key) || g.hists.len() < MAX_SERIES {
            key
        } else {
            (h.index(), Labels::none())
        };
        let s = g.hists.entry(key).or_default();
        let slot = BUCKETS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS.len());
        s.buckets[slot] += 1;
        s.sum += secs;
        s.count += 1;
    }

    /// (count, sum seconds) for a histogram across every label set.
    pub fn histogram_totals(&self, h: Histogram) -> (u64, f64) {
        let g = self.lock();
        g.hists
            .iter()
            .filter(|((i, _), _)| *i == h.index())
            .fold((0, 0.0), |(c, t), (_, s)| (c + s.count, t + s.sum))
    }

    /// Observation count of one exact label set.
    pub fn histogram_count_with(&self, h: Histogram, labels: &Labels) -> u64 {
        self.lock()
            .hists
            .get(&(h.index(), labels.clone()))
            .map_or(0, |s| s.count)
    }

    /// Counters as JSON for the diagnostic bundle: `{ name: [{labels, value}] }`.
    pub fn snapshot_json(&self) -> serde_json::Value {
        let g = self.lock();
        let mut out = serde_json::Map::new();
        for c in Counter::ALL {
            let series: Vec<serde_json::Value> = g
                .counters
                .iter()
                .filter(|((i, _), _)| *i == c as usize)
                .map(|((_, l), v)| serde_json::json!({ "labels": l.render(), "value": v }))
                .collect();
            out.insert(c.name().to_owned(), serde_json::Value::Array(series));
        }
        serde_json::Value::Object(out)
    }

    /// Renders Prometheus text exposition format (all metrics prefixed `openmail_`).
    pub fn render_prometheus(&self) -> String {
        let g = self.lock();
        let mut out = String::new();
        for c in Counter::ALL {
            let name = format!("openmail_{}_total", c.name());
            let _ = writeln!(out, "# HELP {name} {}", c.help());
            let _ = writeln!(out, "# TYPE {name} counter");
            let mut any = false;
            for ((_, l), v) in g.counters.iter().filter(|((i, _), _)| *i == c as usize) {
                any = true;
                write_sample(&mut out, &name, &l.render(), v);
            }
            if !any {
                let _ = writeln!(out, "{name} 0");
            }
        }
        for h in Histogram::ALL {
            let name = format!("openmail_{}", h.name());
            let _ = writeln!(out, "# TYPE {name} histogram");
            let mut any = false;
            for ((_, l), s) in g.hists.iter().filter(|((i, _), _)| *i == h.index()) {
                any = true;
                render_hist(&mut out, &name, &l.render(), s);
            }
            if !any {
                render_hist(&mut out, &name, "", &HistState::default());
            }
        }
        out
    }
}

fn write_sample(out: &mut String, name: &str, labels: &str, value: &dyn std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

fn render_hist(out: &mut String, name: &str, labels: &str, s: &HistState) {
    let sep = if labels.is_empty() { "" } else { "," };
    let mut cumulative = 0u64;
    for (i, bound) in BUCKETS.iter().enumerate() {
        cumulative += s.buckets[i];
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{sep}le=\"{bound}\"}} {cumulative}"
        );
    }
    let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {}", s.count);
    write_sample(out, &format!("{name}_sum"), labels, &s.sum);
    write_sample(out, &format!("{name}_count"), labels, &s.count);
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

    #[test]
    fn labeled_series_are_separate_and_totalled() {
        let m = Metrics::new();
        let a = Labels::none().account("work");
        let b = Labels::none().account("home").code("ACCESS_DENIED");
        m.inc_labeled(Counter::McpRequestFailures, &a);
        m.inc_labeled(Counter::McpRequestFailures, &a);
        m.inc_labeled(Counter::McpRequestFailures, &b);
        assert_eq!(m.counter(Counter::McpRequestFailures), 3);
        assert_eq!(m.counter_with(Counter::McpRequestFailures, &a), 2);
        let text = m.render_prometheus();
        assert!(text.contains("openmail_mcp_request_failures_total{account=\"work\"} 2\n"));
        assert!(text.contains(
            "openmail_mcp_request_failures_total{account=\"home\",code=\"ACCESS_DENIED\"} 1\n"
        ));
    }

    #[test]
    fn labeled_histograms_render_buckets_with_labels() {
        let m = Metrics::new();
        let l = Labels::none().tool("mail_search");
        m.observe_labeled(Histogram::ToolLatency, &l, Duration::from_millis(3));
        assert_eq!(m.histogram_count_with(Histogram::ToolLatency, &l), 1);
        let text = m.render_prometheus();
        assert!(text.contains(
            "openmail_tool_latency_seconds_bucket{tool=\"mail_search\",le=\"0.005\"} 1\n"
        ));
        assert!(text.contains("openmail_tool_latency_seconds_count{tool=\"mail_search\"} 1\n"));
    }

    #[test]
    fn addresses_can_never_become_labels() {
        let l = Labels::none()
            .account("jane.doe@example.invalid")
            .tool("a b\"c");
        let m = Metrics::new();
        m.inc_labeled(Counter::AuthFailures, &l);
        let text = m.render_prometheus();
        assert!(!text.contains("jane"), "{text}");
        assert!(text.contains("tool=\"a_b_c\""));
    }

    #[test]
    fn series_beyond_the_cap_fold_into_the_unlabeled_one() {
        let m = Metrics::new();
        for i in 0..(MAX_SERIES + 10) {
            m.inc_labeled(Counter::Retries, &Labels::none().account(&format!("a{i}")));
        }
        assert_eq!(m.counter(Counter::Retries), (MAX_SERIES + 10) as u64);
        assert!(m.counter_with(Counter::Retries, &Labels::none()) > 0);
    }
}
