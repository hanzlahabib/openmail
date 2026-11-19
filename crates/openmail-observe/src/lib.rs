//! Structured logging, in-process metrics and safe diagnostics. Nothing leaves the process on
//! its own: no external telemetry, no network listeners.
pub mod diagnostics;
pub mod metrics;
pub mod observer;
pub mod tracing_init;
