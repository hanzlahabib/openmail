//! The instrumentation seam. Library crates (imap, smtp, mcp) take an [`Observer`] handle
//! instead of reaching for a global, so they depend only on this tiny API, tests can hand in a
//! real registry, and the default ([`Observer::noop`]) costs one virtual call that does nothing.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics::{Counter, Histogram, Labels, Metrics};

/// Where measurements go. [`Metrics`] is the production sink.
pub trait Sink: Send + Sync + 'static {
    fn incr(&self, counter: Counter, labels: &Labels);
    fn observe(&self, histogram: Histogram, labels: &Labels, elapsed: Duration);
}

impl Sink for Metrics {
    fn incr(&self, counter: Counter, labels: &Labels) {
        self.inc_labeled(counter, labels);
    }
    fn observe(&self, histogram: Histogram, labels: &Labels, elapsed: Duration) {
        self.observe_labeled(histogram, labels, elapsed);
    }
}

struct NoopSink;

impl Sink for NoopSink {
    fn incr(&self, _: Counter, _: &Labels) {}
    fn observe(&self, _: Histogram, _: &Labels, _: Duration) {}
}

/// Cheap-to-clone handle to a [`Sink`]. `Default` is the no-op.
#[derive(Clone)]
pub struct Observer(Arc<dyn Sink>);

impl Default for Observer {
    fn default() -> Self {
        Self::noop()
    }
}

impl fmt::Debug for Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Observer(..)")
    }
}

impl Observer {
    pub fn noop() -> Self {
        Self(Arc::new(NoopSink))
    }

    /// Records into `metrics`.
    pub fn recording(metrics: Arc<Metrics>) -> Self {
        Self(metrics)
    }

    pub fn with_sink(sink: Arc<dyn Sink>) -> Self {
        Self(sink)
    }

    pub fn incr(&self, counter: Counter, labels: &Labels) {
        self.0.incr(counter, labels);
    }

    /// Increments `counter` labeled with an account id only.
    pub fn incr_account(&self, counter: Counter, account: &str) {
        self.0.incr(counter, &Labels::none().account(account));
    }

    pub fn observe(&self, histogram: Histogram, labels: &Labels, elapsed: Duration) {
        self.0.observe(histogram, labels, elapsed);
    }

    /// Records the time since `started` into `histogram`.
    pub fn observe_since(&self, histogram: Histogram, labels: &Labels, started: Instant) {
        self.0.observe(histogram, labels, started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_records_nothing_and_recording_does() {
        let m = Arc::new(Metrics::new());
        Observer::noop().incr_account(Counter::AuthFailures, "a");
        assert_eq!(m.counter(Counter::AuthFailures), 0);
        let o = Observer::recording(Arc::clone(&m));
        o.incr_account(Counter::AuthFailures, "a");
        o.observe_since(Histogram::SearchLatency, &Labels::none(), Instant::now());
        assert_eq!(
            m.counter_with(Counter::AuthFailures, &Labels::none().account("a")),
            1
        );
        assert_eq!(m.histogram_totals(Histogram::SearchLatency).0, 1);
    }
}
