//! openmail-briefs: heuristic mailbox briefs. `engine` runs the pipeline, `config` reads the
//! optional `briefs.toml`, `runner` drives schedules, `digest` mails a brief to its owner.
pub mod aggregate;
pub mod ai;
pub mod classify;
pub mod config;
pub mod delivery;
pub mod digest;
pub mod engine;
pub mod followup;
pub mod model;
pub mod present;
pub mod runner;
pub mod scheduler;
pub mod store;
