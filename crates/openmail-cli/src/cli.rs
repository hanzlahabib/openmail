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
    /// Out-of-band send approvals (never reachable from an MCP tool).
    Approvals(ApprovalsArgs),
    /// Built-in OAuth authorization server helpers.
    Oauth(OauthArgs),
}

#[derive(Debug, Args)]
pub struct OauthArgs {
    #[command(subcommand)]
    pub action: OauthAction,
}

#[derive(Debug, Subcommand)]
pub enum OauthAction {
    /// Read the owner password from stdin and print its Argon2id hash (for
    /// OPENMAIL_OAUTH_OWNER_PASSWORD_HASH_FILE). Example:
    /// `read -rs P; printf %s "$P" | openmail-mcp oauth hash-password > owner.hash`
    HashPassword,
    /// Open or close the short window during which a NEW client (for example a freshly added ChatGPT
    /// connector) may register. After the first successful login registration is closed.
    Registration {
        #[command(subcommand)]
        action: RegistrationAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum RegistrationAction {
    /// Allow new client registrations for a while (default 10 minutes, max 60).
    Open {
        #[arg(long, default_value_t = 10)]
        minutes: u32,
    },
    Close,
}

#[derive(Debug, Args)]
pub struct ApprovalsArgs {
    #[arg(skip)]
    pub config: PathBuf,
    /// Directory holding approvals.db, shared with the server (default:
    /// $XDG_STATE_HOME/openmail-mcp or ~/.local/state/openmail-mcp).
    #[arg(long, value_name = "DIR", env = "OPENMAIL_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: crate::approvals::ApprovalsAction,
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
    /// Add a mailbox (stored in accounts.d/ beside the config; the password goes into a
    /// private secret file, never into the config or the command line).
    Add(AccountAddArgs),
    /// Remove a mailbox that `accounts add` created. Only OpenMail's configuration and its
    /// secret file are deleted: the mailbox and its messages on the mail server are untouched.
    Remove {
        /// Account id.
        id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TlsChoice {
    Implicit,
    StartTls,
}

#[derive(Debug, Args)]
pub struct AccountAddArgs {
    /// Short id (a-z, 0-9, - and _).
    pub id: String,
    /// Mailbox address.
    #[arg(long)]
    pub email: String,
    #[arg(long)]
    pub imap_host: String,
    #[arg(long, default_value_t = 993)]
    pub imap_port: u16,
    #[arg(long, value_enum, default_value_t = TlsChoice::Implicit)]
    pub imap_tls: TlsChoice,
    /// Login name when it differs from the address.
    #[arg(long)]
    pub username: Option<String>,
    /// Sender name recipients see in From (default: the account id, which looks machine-made).
    #[arg(long)]
    pub display_name: Option<String>,
    #[arg(long)]
    pub smtp_host: Option<String>,
    #[arg(long, default_value_t = 465)]
    pub smtp_port: u16,
    #[arg(long, value_enum, default_value_t = TlsChoice::Implicit)]
    pub smtp_tls: TlsChoice,
    /// Grant write permissions (default is read-only): organize, drafts, send, delete.
    #[arg(long, value_delimiter = ',')]
    pub allow: Vec<String>,
    /// Read the password from stdin instead of prompting (for scripts and Docker).
    #[arg(long)]
    pub password_stdin: bool,
    /// Replace an account created earlier by `accounts add` (rotates its password).
    #[arg(long)]
    pub replace: bool,
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
    /// Generate a brief now (heuristic summary of mailbox metadata, not authoritative).
    Now(BriefNowArgs),
    /// Manage scheduled briefs.
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BriefFormat {
    Md,
    Json,
}

#[derive(Debug, Args)]
pub struct BriefNowArgs {
    /// How far back to look (`90m`, `24h`, `7d`); default from briefs.toml, else 24h.
    #[arg(long, value_name = "DURATION")]
    pub lookback: Option<String>,
    /// Account id to include; repeat for several. Default: every configured account.
    #[arg(long = "account", value_name = "ID")]
    pub accounts: Vec<String>,
    #[arg(long, value_enum, default_value_t = BriefFormat::Md)]
    pub format: BriefFormat,
    /// Also report mail an earlier brief already covered.
    #[arg(long)]
    pub include_processed: bool,
    /// Email the brief to the owner of the [briefs.digest] account (never to anyone else).
    #[arg(long)]
    pub email: bool,
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
    #[cfg(unix)] // POSIX-style absolute paths in the fixtures
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
        let cli = Cli::try_parse_from([
            "openmail-mcp",
            "brief",
            "now",
            "--lookback",
            "12h",
            "--account",
            "a",
            "--account",
            "b",
            "--format",
            "json",
        ]);
        assert!(matches!(
            cli.map(|c| c.command),
            Ok(Command::Brief(BriefArgs { action: BriefAction::Now(n), .. }))
                if n.accounts == ["a", "b"] && n.format == BriefFormat::Json
        ));
        assert!(Cli::try_parse_from(["openmail-mcp", "brief", "now", "--format", "xml"]).is_err());
        let cli = Cli::try_parse_from(["openmail-mcp", "serve", "--transport", "http"]);
        assert!(
            matches!(cli.map(|c| c.command), Ok(Command::Serve(a)) if a.transport == Transport::Http)
        );
        assert!(Cli::try_parse_from(["openmail-mcp", "serve", "--transport", "smtp"]).is_err());
    }
}
