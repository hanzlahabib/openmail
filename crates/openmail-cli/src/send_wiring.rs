//! Turns sending on for `serve`: SMTP client, approval verifier, pending-approval queue and the
//! owner's approval mode. Skipped entirely when no account can send, so a read-only deployment
//! never builds any of it.
//!
//! The mode is chosen ONLY here, from the operator's environment (`OPENMAIL_SEND_APPROVAL`:
//! `owner_only` (default), `rules`, `delegated`; `OPENMAIL_SEND_DELEGATED_DAILY_LIMIT`). No MCP tool
//! can read-write it, so an agent cannot widen its own sending rights.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use openmail_core::config::Config;
use openmail_imap::ImapBackend;
use openmail_mcp::{OpenMailServer, SmtpOutgoing};
use openmail_security::send_policy::DEFAULT_DELEGATED_DAILY_LIMIT;
use openmail_security::{
    ApprovalMode, ApprovalVerifier, EnvKeyringSecretSource, PendingApprovals, PolicyConsumer,
    SendPolicyStore, SqliteApprovalStore, SystemClock,
};
use openmail_smtp::{SmtpClient, SmtpOptions, SqliteOutbox};

use crate::brief_cmd::BriefsPaths;

pub const ENV_MODE: &str = "OPENMAIL_SEND_APPROVAL";
pub const ENV_DELEGATED_LIMIT: &str = "OPENMAIL_SEND_DELEGATED_DAILY_LIMIT";
/// Upper bound accepted for the delegated daily cap (recipients per account per day).
const MAX_DELEGATED_DAILY_LIMIT: u32 = 500;

fn can_send(config: &Config) -> bool {
    config
        .accounts
        .iter()
        .any(|a| !a.read_only && a.permissions.send && a.smtp.is_some())
}

pub fn attach(
    server: OpenMailServer<ImapBackend>,
    config: &Config,
    paths: &BriefsPaths,
) -> Result<OpenMailServer<ImapBackend>> {
    if !can_send(config) {
        return Ok(server);
    }
    let Some(dir) = paths.state_dir.as_ref() else {
        tracing::warn!("sending disabled: no state directory (set OPENMAIL_STATE_DIR)");
        return Ok(server);
    };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Standing rules and counters live here: nobody but the service user may write them.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing {}", dir.display()))?;
    }
    let mode = ApprovalMode::parse(&std::env::var(ENV_MODE).unwrap_or_default())
        .map_err(|e| anyhow!("{ENV_MODE}: {e}"))?;
    let limit = match std::env::var(ENV_DELEGATED_LIMIT) {
        Ok(v) => v
            .trim()
            .parse::<u32>()
            .map_err(|_| anyhow!("{ENV_DELEGATED_LIMIT} must be a number"))?,
        Err(_) => DEFAULT_DELEGATED_DAILY_LIMIT,
    };
    // A typo such as 25000 would silently remove the one limit delegated mode has.
    if mode == ApprovalMode::Delegated && !(1..=MAX_DELEGATED_DAILY_LIMIT).contains(&limit) {
        bail!("{ENV_DELEGATED_LIMIT} must be between 1 and {MAX_DELEGATED_DAILY_LIMIT}");
    }
    tracing::info!(
        mode = mode.as_str(),
        daily_limit = limit,
        "send approval policy"
    );
    let approvals_db = dir.join("approvals.db");
    let store = Arc::new(SqliteApprovalStore::open(&approvals_db).map_err(|e| anyhow!("{e}"))?);
    let verifier = ApprovalVerifier::new(store, SystemClock::new());
    let policy =
        Arc::new(SendPolicyStore::open(&dir.join("send-policy.db")).map_err(|e| anyhow!("{e}"))?);
    let consumer = PolicyConsumer::new(mode, policy, verifier, SystemClock::new(), limit);
    let pending =
        PendingApprovals::open(&approvals_db, SystemClock::new()).map_err(|e| anyhow!("{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            dir.join("send-policy.db"),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    let outbox = SqliteOutbox::open(&dir.join("outbox.db")).map_err(|e| anyhow!("{e}"))?;
    let smtp = SmtpClient::new(
        outbox,
        EnvKeyringSecretSource::new(),
        SmtpOptions::default(),
    );
    tracing::info!(mode = mode.as_str(), "sending enabled");
    Ok(server.with_outgoing(Arc::new(SmtpOutgoing::new(smtp, consumer, pending))))
}
