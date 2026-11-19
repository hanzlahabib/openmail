//! `approvals list|show|grant|deny`: the out-of-band human side of send approvals.
//!
//! The MCP server can only *request* a send; nothing it exposes can mint an
//! approval. A person runs `grant` here, sees the exact recipients, subject and
//! content hash, and types the short request id back. The resulting single-use
//! token is printed for them to hand to the agent.
//!
//! State: the CLI and the server share one SQLite file, `approvals.db`, in the
//! state directory (`--state-dir`, `$OPENMAIL_STATE_DIR`, else
//! `$XDG_STATE_HOME/openmail-mcp`, else `~/.local/state/openmail-mcp`). The file
//! is created with mode 0600 and the directory with 0700.
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Subcommand;
use openmail_security::{
    Clock, HumanConfirmation, PendingApproval, PendingApprovals, PendingId, SystemClock,
};

use crate::cli::ApprovalsArgs;

const STATE_APP_DIR: &str = "openmail-mcp";
const DB_FILE: &str = "approvals.db";

#[derive(Debug, Subcommand)]
pub enum ApprovalsAction {
    /// List requests waiting for a human decision.
    List,
    /// Show every detail of one request.
    Show {
        /// Request id from `approvals list`.
        id: String,
    },
    /// Approve a request and print its single-use token.
    Grant {
        /// Request id from `approvals list`.
        id: String,
        /// DANGEROUS: skip the type-the-id confirmation. Only for scripts a
        /// human wrote; anything an agent can invoke must never use this.
        #[arg(long)]
        yes: bool,
    },
    /// Reject a request.
    Deny {
        /// Request id from `approvals list`.
        id: String,
    },
}

pub fn run(args: ApprovalsArgs) -> Result<()> {
    let db = db_path(args.state_dir.as_deref(), &StateEnv::from_process());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    execute(
        &db,
        args.action,
        &mut stdin.lock(),
        &mut stdout.lock(),
        SystemClock::new(),
    )
}

struct StateEnv {
    xdg_state: Option<PathBuf>,
    home: Option<PathBuf>,
}

impl StateEnv {
    fn from_process() -> Self {
        Self {
            xdg_state: std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }
}

/// Explicit dir wins; otherwise XDG state (relative values ignored per spec).
fn db_path(explicit: Option<&Path>, env: &StateEnv) -> PathBuf {
    let dir = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        env.xdg_state
            .clone()
            .filter(|p| p.is_absolute())
            .or_else(|| env.home.as_ref().map(|h| h.join(".local/state")))
            .unwrap_or_else(|| PathBuf::from(".local/state"))
            .join(STATE_APP_DIR)
    });
    dir.join(DB_FILE)
}

fn ensure_private_dir(db: &Path) -> Result<()> {
    let Some(dir) = db.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Ok(());
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating state directory {}", dir.display()))
}

fn execute<C: Clock + Clone>(
    db: &Path,
    action: ApprovalsAction,
    input: &mut impl BufRead,
    out: &mut impl Write,
    clock: C,
) -> Result<()> {
    ensure_private_dir(db)?;
    let pending = PendingApprovals::open(db, clock.clone())
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("opening approvals database {}", db.display()))?;
    match action {
        ApprovalsAction::List => list(&pending, out, clock.unix_secs()),
        ApprovalsAction::Show { id } => {
            let item = load(&pending, &id)?;
            write_detail(out, &item, clock.unix_secs())?;
            Ok(())
        }
        ApprovalsAction::Grant { id, yes } => {
            grant(&pending, &id, yes, input, out, clock.unix_secs())
        }
        ApprovalsAction::Deny { id } => {
            let id = parse_id(&id)?;
            if pending.deny(&id).map_err(|e| anyhow!("{e}"))? {
                writeln!(out, "Denied {id}.")?;
                Ok(())
            } else {
                bail!("request {id} is not pending (unknown, already decided, or expired)")
            }
        }
    }
}

fn parse_id(raw: &str) -> Result<PendingId> {
    PendingId::parse(raw.trim()).map_err(|e| anyhow!("{e}"))
}

fn load(pending: &PendingApprovals<impl Clock + Clone>, raw: &str) -> Result<PendingApproval> {
    let id = parse_id(raw)?;
    pending
        .get(&id)
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("no request with id {id}"))
}

fn list(
    pending: &PendingApprovals<impl Clock + Clone>,
    out: &mut impl Write,
    now: u64,
) -> Result<()> {
    let items = pending.list_pending().map_err(|e| anyhow!("{e}"))?;
    if items.is_empty() {
        writeln!(out, "No pending approval requests.")?;
        return Ok(());
    }
    for it in items {
        writeln!(
            out,
            "{}  {}  {}  to {}  \"{}\"  (expires in {})",
            it.id,
            it.principal_display(),
            it.account,
            it.recipients.len(),
            truncate(&visible(&it.subject), 60),
            minutes(it.expires_at.saturating_sub(now)),
        )?;
    }
    Ok(())
}

fn grant(
    pending: &PendingApprovals<impl Clock + Clone>,
    raw: &str,
    yes: bool,
    input: &mut impl BufRead,
    out: &mut impl Write,
    now: u64,
) -> Result<()> {
    let item = load(pending, raw)?;
    write_detail(out, &item, now)?;
    let confirmation = if yes {
        HumanConfirmation::assume_yes_dangerous(&item.id)
    } else {
        write!(
            out,
            "\nType the request id ({}) to approve this send: ",
            item.id
        )?;
        out.flush()?;
        let mut typed = String::new();
        input.read_line(&mut typed)?;
        HumanConfirmation::typed_id(&item.id, &typed)
            .map_err(|_| anyhow!("typed id did not match; nothing was approved"))?
    };
    let token = pending
        .grant(&item.id, &confirmation)
        .map_err(|e| anyhow!("{e}"))?;
    writeln!(
        out,
        "\nApproved. Single-use token (give it to the agent; it will not be shown again):"
    )?;
    writeln!(out, "{}", token.as_str())?;
    Ok(())
}

fn write_detail(out: &mut impl Write, it: &PendingApproval, now: u64) -> Result<()> {
    writeln!(out, "Request:      {}", it.id)?;
    writeln!(out, "Status:       {}", status_label(it))?;
    writeln!(out, "Requested by: {}", it.principal_display())?;
    writeln!(out, "Account:      {}", it.account)?;
    writeln!(out, "Subject:      {}", visible(&it.subject))?;
    writeln!(out, "Recipients ({}):", it.recipients.len())?;
    for r in &it.recipients {
        writeln!(out, "  {}", visible(r))?;
    }
    writeln!(out, "Content hash: {}", it.content_hash)?;
    writeln!(
        out,
        "  (SHA-256 over body, html, cc/bcc roles, references and attachments)"
    )?;
    writeln!(
        out,
        "Attachments ({}; sha256, names are not recorded):",
        it.attachment_sha256.len()
    )?;
    for a in &it.attachment_sha256 {
        writeln!(out, "  {a}")?;
    }
    writeln!(
        out,
        "Expires in:   {}",
        minutes(it.expires_at.saturating_sub(now))
    )?;
    Ok(())
}

fn status_label(it: &PendingApproval) -> &'static str {
    use openmail_security::PendingStatus::{Denied, Granted, Pending};
    match it.status {
        Pending => "pending",
        Granted => "granted",
        Denied => "denied",
    }
}

/// Makes control, bidi and zero-width characters visible. The text under review
/// is attacker-influenced; it must not be able to reorder or hide what the
/// human is approving.
fn visible(s: &str) -> String {
    s.chars()
        .map(|c| {
            let hidden = c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}');
            if hidden {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

fn minutes(secs: u64) -> String {
    format!("{}m{:02}s", secs / 60, secs % 60)
}

trait PrincipalDisplay {
    fn principal_display(&self) -> String;
}

impl PrincipalDisplay for PendingApproval {
    fn principal_display(&self) -> String {
        visible(&self.principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)] // POSIX-style absolute paths in the fixtures
    fn explicit_state_dir_wins_then_xdg_then_home() {
        let env = StateEnv {
            xdg_state: Some("/xdg".into()),
            home: Some("/h".into()),
        };
        assert_eq!(
            db_path(Some(Path::new("/s")), &env),
            PathBuf::from("/s/approvals.db")
        );
        assert_eq!(
            db_path(None, &env),
            PathBuf::from("/xdg/openmail-mcp/approvals.db")
        );
        let env = StateEnv {
            xdg_state: Some("rel".into()),
            home: Some("/h".into()),
        };
        assert_eq!(
            db_path(None, &env),
            PathBuf::from("/h/.local/state/openmail-mcp/approvals.db")
        );
    }

    #[test]
    fn hidden_characters_are_made_visible() {
        assert_eq!(visible("a\u{202E}b\nc"), "a\\u{202e}b\\u{000a}c");
        assert_eq!(visible("plain"), "plain");
    }
}
