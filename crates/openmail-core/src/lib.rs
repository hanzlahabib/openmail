//! Domain models, configuration, errors and backend contracts shared by every
//! OpenMail crate. No network I/O lives here.
pub mod backend;
pub mod config;
pub mod error;
pub mod ids;
pub mod model;

pub use error::{Error, ErrorCode, Result};
