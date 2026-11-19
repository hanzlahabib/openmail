//! owned by T36: out-of-band approval commands.
use anyhow::{Result, bail};

use crate::cli::ApprovalsArgs;

pub fn run(_args: ApprovalsArgs) -> Result<()> {
    bail!("approvals command is not implemented yet")
}
