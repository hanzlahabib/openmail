//! Command-line surface (clap derive). Argument structs defined here are the
//! contract with the command modules (`init`, `doctor`, `accounts`, `serve`,
//! `brief_cmd`); each module exposes `run(args) -> anyhow::Result<()>`.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Directory name used under the XDG config home.
const APP_DIR: &str = "openmail-mcp";
const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Parser)]
#[command(
    name = "openmail-mcp",
    version,
    about = "Local-first, security-first MCP server for email"
)]
pub struct Cli {
    /// Path to the TOML config (default: $XDG_CONFIG_HOME/openmail-mcp/config.toml).
    #[arg(long, global = true, value_name = "PATH", env = "OPENMAIL_CONFIG")]
    pub config: Option<PathBuf>,

    /// Log filter for stderr tracing (e.g. `info`, `openmail=debug`).
    #[arg(
        long,
        global = true,
        value_name = "FILTER",
        env = "OPENMAIL_LOG",
        default_value = "warn"
    )]
    pub log: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a starter config file.
    Init(InitArgs),
    /// Check config, credentials and server connectivity.
    Doctor(DoctorArgs),
    /// Inspect and test configured accounts.
    Accounts(AccountsArgs),
    /// Run the MCP server.
    Serve(ServeArgs),
    /// Daily brief commands.
    Brief(BriefArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Resolved config path to create.
    #[arg(skip)]
    pub config: PathBuf,
    /// Overwrite an existing config file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(skip)]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct AccountsArgs {
    #[arg(skip)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub action: AccountsAction,
}

#[derive(Debug, Subcommand)]
pub enum AccountsAction {
    /// List configured accounts.
    List,
    /// Test IMAP/SMTP connectivity of an account.
    Test {
        /// Account id; all accounts when omitted.
        account: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    Stdio,
    Http,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(skip)]
    pub config: PathBuf,
    /// Transport to serve on.
    #[arg(long, value_enum, default_value_t = Transport::Stdio)]
    pub transport: Transport,
    /// Bind address for the http transport (loopback only by default).
    #[arg(long, default_value = "127.0.0.1:8765")]
    pub bind: String,
}

#[derive(Debug, Args)]
pub struct BriefArgs {
    #[arg(skip)]
    pub config: PathBuf,
    #[command(subcommand)]
    pub action: BriefAction,
}

#[derive(Debug, Subcommand)]
pub enum BriefAction {
    /// Generate a brief now.
    Now,
    /// Manage scheduled briefs.
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScheduleAction {
    /// List scheduled briefs.
    List,
}

/// Config path: explicit flag, else XDG (`$XDG_CONFIG_HOME` or `~/.config`).
pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    resolve_config_with(
        explicit,
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn resolve_config_with(
    explicit: Option<&Path>,
    xdg: Option<PathBuf>,
    home: Option<PathBuf>,
) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    // XDG spec: relative XDG_CONFIG_HOME values must be ignored.
    let base = xdg
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join(APP_DIR).join(CONFIG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_path_wins() {
        let p = resolve_config_with(Some(Path::new("/x/c.toml")), Some("/xdg".into()), None);
        assert_eq!(p, PathBuf::from("/x/c.toml"));
    }

    #[test]
    fn xdg_then_home_then_relative() {
        assert_eq!(
            resolve_config_with(None, Some("/xdg".into()), Some("/h".into())),
            PathBuf::from("/xdg/openmail-mcp/config.toml")
        );
        assert_eq!(
            resolve_config_with(None, Some("rel".into()), Some("/h".into())),
            PathBuf::from("/h/.config/openmail-mcp/config.toml")
        );
        assert_eq!(
            resolve_config_with(None, None, None),
            PathBuf::from(".config/openmail-mcp/config.toml")
        );
    }

    #[test]
    fn parses_nested_subcommands() {
        let cli = Cli::try_parse_from(["openmail-mcp", "brief", "schedule", "list"]);
        assert!(cli.is_ok());
        let cli = Cli::try_parse_from(["openmail-mcp", "serve", "--transport", "http"]);
        assert!(
            matches!(cli.map(|c| c.command), Ok(Command::Serve(a)) if a.transport == Transport::Http)
        );
        assert!(Cli::try_parse_from(["openmail-mcp", "serve", "--transport", "smtp"]).is_err());
    }
}
