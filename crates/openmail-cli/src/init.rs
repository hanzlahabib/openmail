//! `openmail-mcp init`: account wizard that writes a validated config and prints
//! MCP client snippets.
//!
//! The wizard never asks for, reads or prints a secret. It only records *where*
//! the secret lives (env var or OS keyring entry), mirroring `CredentialRef`.
//! Prompts use plain `BufRead`/`Write` so the whole flow is scriptable in tests
//! and there is no terminal-UI dependency to keep patched; the pure logic
//! (presets, rendering, composing, snippets) is separate from the IO shell.
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use openmail_core::config::{AuthMethod, Config, CredentialRef, ServerEndpoint, TlsMode};
use openmail_core::ids::AccountId;

use crate::cli;

/// Keyring service name under which OpenMail credentials are filed.
pub const KEYRING_SERVICE: &str = "openmail-mcp";
/// Name of the MCP server entry in client configs.
pub const MCP_SERVER_NAME: &str = "openmail";
/// Binary name used in client snippets; resolved through the client's PATH.
pub const BINARY_NAME: &str = "openmail-mcp";
/// IMAPS / SMTPS ports, used when the user gives a generic server without a port.
const DEFAULT_IMAP_PORT: u16 = 993;
const DEFAULT_SMTP_PORT: u16 = 465;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Gmail,
    Outlook,
    Fastmail,
    ICloud,
    Yahoo,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetDefaults {
    pub imap: ServerEndpoint,
    pub smtp: ServerEndpoint,
    pub auth: AuthMethod,
    /// Shown to the user: provider-specific credential caveats.
    pub note: &'static str,
}

fn endpoint(host: &str, port: u16, tls: TlsMode) -> ServerEndpoint {
    ServerEndpoint {
        host: host.to_owned(),
        port,
        tls,
    }
}

impl Preset {
    pub const ALL: [Self; 6] = [
        Self::Gmail,
        Self::Outlook,
        Self::Fastmail,
        Self::ICloud,
        Self::Yahoo,
        Self::Generic,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Gmail => "gmail",
            Self::Outlook => "outlook",
            Self::Fastmail => "fastmail",
            Self::ICloud => "icloud",
            Self::Yahoo => "yahoo",
            Self::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|p| p.key() == s || (s == "m365" && *p == Self::Outlook))
    }

    /// `None` for `Generic`: there is nothing safe to guess.
    pub fn defaults(self) -> Option<PresetDefaults> {
        use TlsMode::{Implicit, StartTls};
        Some(match self {
            Self::Gmail => PresetDefaults {
                imap: endpoint("imap.gmail.com", 993, Implicit),
                smtp: endpoint("smtp.gmail.com", 465, Implicit),
                auth: AuthMethod::Password,
                note: "Use a Google app password (needs 2-step verification), not your account password.",
            },
            Self::Outlook => PresetDefaults {
                imap: endpoint("outlook.office365.com", 993, Implicit),
                smtp: endpoint("smtp.office365.com", 587, StartTls),
                auth: AuthMethod::Oauth2,
                note: "Microsoft 365 disables basic auth for most tenants; the variable must hold an OAuth2 access token.",
            },
            Self::Fastmail => PresetDefaults {
                imap: endpoint("imap.fastmail.com", 993, Implicit),
                smtp: endpoint("smtp.fastmail.com", 465, Implicit),
                auth: AuthMethod::Password,
                note: "Create an app password under Settings > Privacy & Security.",
            },
            Self::ICloud => PresetDefaults {
                imap: endpoint("imap.mail.me.com", 993, Implicit),
                smtp: endpoint("smtp.mail.me.com", 587, StartTls),
                auth: AuthMethod::Password,
                note: "Use an app-specific password from appleid.apple.com; the login name is the iCloud address.",
            },
            Self::Yahoo => PresetDefaults {
                imap: endpoint("imap.mail.yahoo.com", 993, Implicit),
                smtp: endpoint("smtp.mail.yahoo.com", 465, Implicit),
                auth: AuthMethod::Password,
                note: "Generate an app password in Yahoo account security.",
            },
            Self::Generic => return None,
        })
    }
}

/// How much the MCP client may change. Send is deliberately not offered here:
/// it needs the approval flow and an explicit hand edit of the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    Drafts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub imap: ServerEndpoint,
    pub smtp: Option<ServerEndpoint>,
    pub auth: AuthMethod,
    pub username: Option<String>,
    pub credential: CredentialRef,
    pub access: Access,
}

/// Pre-supplied values. Anything `None` is prompted for (interactive) or
/// defaulted (non-interactive); `email` is always required.
#[derive(Debug, Clone, Default)]
pub struct InitArgs {
    pub config_path: PathBuf,
    pub interactive: bool,
    pub preset: Option<String>,
    pub email: Option<String>,
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub imap_host: Option<String>,
    pub imap_port: Option<u16>,
    pub smtp_host: Option<String>,
    pub username: Option<String>,
    pub auth: Option<String>,
    /// `env` or `keyring`.
    pub credential_kind: Option<String>,
    /// Env var name when `credential_kind` is `env`.
    pub credential_env: Option<String>,
    /// `read-only` or `drafts`.
    pub access: Option<String>,
}

// ---------------------------------------------------------------- pure logic

fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                // `write!` into a String cannot fail.
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn tls_str(t: TlsMode) -> &'static str {
    match t {
        TlsMode::Implicit => "implicit",
        TlsMode::StartTls => "start_tls",
    }
}

fn endpoint_toml(e: &ServerEndpoint) -> String {
    format!(
        "{{ host = {}, port = {}, tls = \"{}\" }}",
        toml_str(&e.host),
        e.port,
        tls_str(e.tls)
    )
}

/// One `[[account]]` table. Strings are escaped, so user input cannot inject keys.
pub fn render_account(a: &Answers) -> String {
    let mut s = String::from("[[account]]\n");
    let _ = writeln!(s, "id = {}", toml_str(&a.id));
    let _ = writeln!(s, "display_name = {}", toml_str(&a.display_name));
    let _ = writeln!(s, "email = {}", toml_str(&a.email));
    let auth = match a.auth {
        AuthMethod::Password => "password",
        AuthMethod::Oauth2 => "oauth2",
    };
    let _ = writeln!(s, "auth = \"{auth}\"");
    if let Some(u) = &a.username {
        let _ = writeln!(s, "username = {}", toml_str(u));
    }
    match &a.credential {
        CredentialRef::Env { var } => {
            let _ = writeln!(
                s,
                "credential = {{ kind = \"env\", var = {} }}",
                toml_str(var)
            );
        }
        CredentialRef::File { path } => {
            let _ = writeln!(
                s,
                "credential = {{ kind = \"file\", path = {} }}",
                toml_str(path)
            );
        }
        CredentialRef::Keyring { service, user } => {
            let _ = writeln!(
                s,
                "credential = {{ kind = \"keyring\", service = {}, user = {} }}",
                toml_str(service),
                toml_str(user)
            );
        }
    }
    let _ = writeln!(s, "imap = {}", endpoint_toml(&a.imap));
    if let Some(smtp) = &a.smtp {
        let _ = writeln!(s, "smtp = {}", endpoint_toml(smtp));
    }
    match a.access {
        Access::ReadOnly => s.push_str("read_only = true\n"),
        Access::Drafts => {
            s.push_str("read_only = false\npermissions = { organize = true, drafts = true }\n")
        }
    }
    s
}

/// Append the account to `existing` (or a fresh v1 file) and validate the whole
/// result with core's `Config`, so a bad answer or duplicate id never reaches disk.
pub fn compose_config(existing: Option<&str>, a: &Answers) -> Result<String> {
    let mut text = match existing {
        Some(t) if !t.trim().is_empty() => t.trim_end().to_owned(),
        _ => format!("version = {}", openmail_core::config::CONFIG_VERSION),
    };
    text.push_str("\n\n");
    text.push_str(&render_account(a));
    Config::from_toml(&text).map_err(|e| anyhow!("generated config is invalid: {e}"))?;
    Ok(text)
}

/// Lowercase `[a-z0-9_-]` slug of the mailbox local part, valid as an `AccountId`.
pub fn default_account_id(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("");
    let slug: String = local
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if slug.is_empty() {
        "mail".to_owned()
    } else {
        slug
    }
}

pub fn default_env_var(id: &str, auth: AuthMethod) -> String {
    let suffix = if auth == AuthMethod::Oauth2 {
        "TOKEN"
    } else {
        "PASSWORD"
    };
    let id: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("OPENMAIL_{id}_{suffix}")
}

fn valid_env_var(v: &str) -> bool {
    let mut chars = v.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    pub client: &'static str,
    pub location: &'static str,
    pub body: String,
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Ready-to-paste registrations of the stdio server for the common MCP clients.
pub fn mcp_snippets(config_path: &Path) -> Vec<Snippet> {
    let path = config_path.display().to_string();
    let entry = format!(
        "{{ \"command\": {}, \"args\": [\"serve\", \"--config\", {}] }}",
        json_str(BINARY_NAME),
        json_str(&path)
    );
    let wrap =
        |key: &str| format!("{{\n  \"{key}\": {{\n    \"{MCP_SERVER_NAME}\": {entry}\n  }}\n}}");
    vec![
        Snippet {
            client: "Claude Desktop",
            location: "claude_desktop_config.json (merge into existing mcpServers)",
            body: wrap("mcpServers"),
        },
        Snippet {
            client: "Claude Code",
            location: "run in a terminal",
            body: format!(
                "claude mcp add {MCP_SERVER_NAME} -- {BINARY_NAME} serve --config {}",
                shell_quote(&path)
            ),
        },
        Snippet {
            client: "Cursor",
            location: "~/.cursor/mcp.json",
            body: wrap("mcpServers"),
        },
        Snippet {
            client: "VS Code",
            location: ".vscode/mcp.json (note: key is \"servers\")",
            body: wrap("servers"),
        },
    ]
}

/// What the user must do to supply the secret; never contains the secret.
pub fn credential_hint(a: &Answers) -> String {
    match &a.credential {
        CredentialRef::Env { var } => {
            format!(
                "Export {var} in the environment of the MCP client process (it is read at runtime, never stored in the config)."
            )
        }
        CredentialRef::File { path } => {
            format!("Put only the password in {path} (mode 600).")
        }
        CredentialRef::Keyring { service, user } => {
            format!(
                "Store the secret in your OS keyring under service '{service}', user '{user}' (e.g. `secret-tool store` on Linux, Keychain Access on macOS)."
            )
        }
    }
}

// ------------------------------------------------------------------ IO shell

/// Atomic, owner-only write: temp file in the same directory created with mode
/// 0600 from the start (no window where it is world-readable), fsynced, renamed.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("config path has no file name"))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);

    let result = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        // Best effort: don't leave a stray temp file behind; the original error matters more.
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

struct Asker<R, W> {
    input: R,
    out: W,
    interactive: bool,
}

impl<R: BufRead, W: Write> Asker<R, W> {
    /// Provided value wins; otherwise prompt (interactive) or fall back to the
    /// default (non-interactive). Empty answer accepts the default.
    fn field(
        &mut self,
        provided: Option<&str>,
        label: &str,
        default: Option<&str>,
    ) -> Result<String> {
        if let Some(v) = provided {
            return Ok(v.trim().to_owned());
        }
        if !self.interactive {
            return default
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{label} is required in non-interactive mode"));
        }
        match default {
            Some(d) => write!(self.out, "{label} [{d}]: ")?,
            None => write!(self.out, "{label}: ")?,
        }
        self.out.flush()?;
        let mut line = String::new();
        if self.input.read_line(&mut line)? == 0 {
            bail!("input ended while asking for {label}");
        }
        let line = line.trim();
        if line.is_empty() {
            return default
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{label} is required"));
        }
        Ok(line.to_owned())
    }
}

fn parse_port(s: &str, what: &str) -> Result<u16> {
    s.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("{what} must be a port number 1-65535"))
}

/// Port conventionally paired with a TLS mode when the user picks a generic server.
fn tls_for_port(port: u16) -> TlsMode {
    if port == 143 || port == 587 {
        TlsMode::StartTls
    } else {
        TlsMode::Implicit
    }
}

fn collect<R: BufRead, W: Write>(args: &InitArgs, input: R, out: W) -> Result<Answers> {
    let mut q = Asker {
        input,
        out,
        interactive: args.interactive,
    };

    let email = q.field(args.email.as_deref(), "Email address", None)?;
    if q.interactive && args.preset.is_none() {
        let keys: Vec<_> = Preset::ALL.iter().map(|p| p.key()).collect();
        writeln!(q.out, "Providers: {}", keys.join(", "))?;
    }
    let preset_in = q.field(args.preset.as_deref(), "Provider", Some("generic"))?;
    let preset =
        Preset::parse(&preset_in).ok_or_else(|| anyhow!("unknown provider '{preset_in}'"))?;
    let defaults = preset.defaults();
    if q.interactive
        && let Some(d) = &defaults
    {
        writeln!(q.out, "Note: {}", d.note)?;
    }

    let id = q.field(
        args.id.as_deref(),
        "Account id",
        Some(&default_account_id(&email)),
    )?;
    AccountId::new(id.clone()).map_err(|e| anyhow!("{e}"))?;
    let display_name = q.field(args.display_name.as_deref(), "Display name", Some(&email))?;

    let imap_host = q.field(
        args.imap_host.as_deref(),
        "IMAP host",
        defaults.as_ref().map(|d| d.imap.host.as_str()),
    )?;
    let imap_port_default = defaults
        .as_ref()
        .map_or(DEFAULT_IMAP_PORT, |d| d.imap.port)
        .to_string();
    let imap_port = match args.imap_port {
        Some(p) => p,
        None => parse_port(
            &q.field(None, "IMAP port", Some(&imap_port_default))?,
            "IMAP port",
        )?,
    };
    let imap_tls = match &defaults {
        Some(d) if d.imap.port == imap_port => d.imap.tls,
        _ => tls_for_port(imap_port),
    };
    let imap = ServerEndpoint {
        host: imap_host,
        port: imap_port,
        tls: imap_tls,
    };

    let smtp_default = defaults
        .as_ref()
        .map(|d| d.smtp.host.as_str())
        .unwrap_or("none");
    let smtp_host = q.field(
        args.smtp_host.as_deref(),
        "SMTP host (or 'none')",
        Some(smtp_default),
    )?;
    let smtp = if smtp_host.eq_ignore_ascii_case("none") || smtp_host.is_empty() {
        None
    } else {
        let port = defaults.as_ref().map_or(DEFAULT_SMTP_PORT, |d| d.smtp.port);
        let tls = defaults
            .as_ref()
            .map_or_else(|| tls_for_port(port), |d| d.smtp.tls);
        Some(ServerEndpoint {
            host: smtp_host,
            port,
            tls,
        })
    };

    let auth_default = defaults.as_ref().map_or("password", |d| match d.auth {
        AuthMethod::Password => "password",
        AuthMethod::Oauth2 => "oauth2",
    });
    let auth = match q
        .field(
            args.auth.as_deref(),
            "Auth method (password/oauth2)",
            Some(auth_default),
        )?
        .to_ascii_lowercase()
        .as_str()
    {
        "password" => AuthMethod::Password,
        "oauth2" => AuthMethod::Oauth2,
        other => bail!("unknown auth method '{other}'"),
    };

    let username = q.field(args.username.as_deref(), "Login name", Some(&email))?;
    let username = (username != email).then_some(username);

    let kind = q.field(
        args.credential_kind.as_deref(),
        "Credential storage (env/keyring)",
        Some("env"),
    )?;
    let credential = match kind.to_ascii_lowercase().as_str() {
        "env" => {
            let var = q.field(
                args.credential_env.as_deref(),
                "Env var holding the secret",
                Some(&default_env_var(&id, auth)),
            )?;
            if !valid_env_var(&var) {
                bail!("'{var}' is not a valid environment variable name");
            }
            CredentialRef::Env { var }
        }
        "keyring" => CredentialRef::Keyring {
            service: KEYRING_SERVICE.to_owned(),
            user: format!("{id}:{email}"),
        },
        other => bail!("unknown credential storage '{other}' (use env or keyring)"),
    };

    let access = match q
        .field(
            args.access.as_deref(),
            "Access (read-only/drafts)",
            Some("read-only"),
        )?
        .to_ascii_lowercase()
        .as_str()
    {
        "read-only" | "readonly" => Access::ReadOnly,
        "drafts" => Access::Drafts,
        other => bail!("unknown access level '{other}' (use read-only or drafts)"),
    };

    Ok(Answers {
        id,
        display_name,
        email,
        imap,
        smtp,
        auth,
        username,
        credential,
        access,
    })
}

/// CLI entry point. Interactive when stdin is a terminal; otherwise every
/// value must come from defaults (only the email is then unobtainable, so a
/// piped run without flags fails with a clear message instead of hanging).
/// `--force` replaces an existing config instead of appending an account.
pub fn run(args: cli::InitArgs) -> Result<()> {
    let stdin = io::stdin();
    let init = InitArgs {
        config_path: args.config,
        interactive: stdin.is_terminal(),
        ..InitArgs::default()
    };
    run_with(&init, args.force, stdin.lock(), io::stdout().lock())
}

/// Run the wizard, write the config, and print the follow-up instructions to `out`.
pub fn run_with<R: BufRead, W: Write>(
    args: &InitArgs,
    replace: bool,
    input: R,
    mut out: W,
) -> Result<()> {
    let answers = collect(args, input, &mut out)?;
    let existing = match if replace {
        Err(io::ErrorKind::NotFound.into())
    } else {
        fs::read_to_string(&args.config_path)
    } {
        Ok(t) => Some(t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", args.config_path.display())),
    };
    let text = compose_config(existing.as_deref(), &answers)?;
    write_atomic(&args.config_path, &text)?;

    writeln!(
        out,
        "\nWrote {} (mode 0600), account '{}'.",
        args.config_path.display(),
        answers.id
    )?;
    writeln!(out, "{}", credential_hint(&answers))?;
    writeln!(out, "\nRegister the server with your MCP client:")?;
    for s in mcp_snippets(&args.config_path) {
        writeln!(out, "\n# {} - {}\n{}", s.client, s.location, s.body)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // asserting via unwrap is the point in tests
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "openmail-init-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(path: PathBuf) -> InitArgs {
        InitArgs {
            config_path: path,
            email: Some("me@example.com".into()),
            ..InitArgs::default()
        }
    }

    #[test]
    fn every_preset_produces_a_valid_config() {
        for p in Preset::ALL {
            let dir = TempDir::new();
            let mut a = args(dir.0.join("c.toml"));
            a.preset = Some(p.key().into());
            a.imap_host = (p == Preset::Generic).then(|| "imap.example.com".to_owned());
            let mut out = Vec::new();
            run_with(&a, false, Cursor::new(""), &mut out)
                .unwrap_or_else(|e| panic!("{}: {e}", p.key()));
            let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
            assert_eq!(cfg.accounts.len(), 1);
            assert!(
                cfg.accounts[0].read_only,
                "default access must be read-only"
            );
        }
    }

    #[test]
    fn gmail_preset_fills_hosts_and_tls() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("gmail".into());
        run_with(&a, false, Cursor::new(""), Vec::new()).unwrap();
        let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
        let acc = &cfg.accounts[0];
        assert_eq!(acc.imap, endpoint("imap.gmail.com", 993, TlsMode::Implicit));
        assert_eq!(
            acc.smtp,
            Some(endpoint("smtp.gmail.com", 465, TlsMode::Implicit))
        );
        assert_eq!(acc.id.as_str(), "me");
        assert_eq!(
            acc.credential,
            CredentialRef::Env {
                var: "OPENMAIL_ME_PASSWORD".into()
            }
        );
    }

    #[test]
    fn outlook_uses_oauth_and_starttls_smtp() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("outlook".into());
        run_with(&a, false, Cursor::new(""), Vec::new()).unwrap();
        let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
        assert_eq!(cfg.accounts[0].auth, AuthMethod::Oauth2);
        assert_eq!(
            cfg.accounts[0].smtp.as_ref().unwrap().tls,
            TlsMode::StartTls
        );
    }

    #[test]
    fn non_interactive_requires_email_and_generic_host() {
        let dir = TempDir::new();
        let mut a = InitArgs {
            config_path: dir.0.join("c.toml"),
            ..InitArgs::default()
        };
        assert!(run_with(&a, false, Cursor::new(""), Vec::new()).is_err());
        a.email = Some("me@example.com".into());
        let err = run_with(&a, false, Cursor::new(""), Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("IMAP host"), "{err}");
        assert!(
            !a.config_path.exists(),
            "failed run must not create the config"
        );
    }

    #[test]
    fn interactive_flow_reads_scripted_answers() {
        let dir = TempDir::new();
        let a = InitArgs {
            config_path: dir.0.join("c.toml"),
            interactive: true,
            ..InitArgs::default()
        };
        // email, provider, id, name, imap host, imap port, smtp, auth, login, cred storage, env var, access
        let script =
            "dev@fastmail.com\nfastmail\nwork\nWork Mail\n\n\n\n\n\nenv\nWORK_SECRET\ndrafts\n";
        let mut out = Vec::new();
        run_with(&a, false, Cursor::new(script), &mut out).unwrap();
        let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
        let acc = &cfg.accounts[0];
        assert_eq!(acc.id.as_str(), "work");
        assert_eq!(acc.display_name, "Work Mail");
        assert!(
            !acc.read_only
                && acc.permissions.drafts
                && acc.permissions.organize
                && !acc.permissions.send
        );
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("WORK_SECRET") && shown.contains("claude mcp add"));
    }

    #[test]
    fn interactive_eof_is_an_error_not_a_hang() {
        let dir = TempDir::new();
        let a = InitArgs {
            config_path: dir.0.join("c.toml"),
            interactive: true,
            ..InitArgs::default()
        };
        assert!(run_with(&a, false, Cursor::new("me@example.com\n"), Vec::new()).is_err());
    }

    #[test]
    fn second_account_is_appended_and_duplicates_rejected() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("gmail".into());
        run_with(&a, false, Cursor::new(""), Vec::new()).unwrap();
        let mut b = a.clone();
        b.email = Some("other@example.com".into());
        run_with(&b, false, Cursor::new(""), Vec::new()).unwrap();
        assert_eq!(
            Config::from_toml(&fs::read_to_string(&a.config_path).unwrap())
                .unwrap()
                .accounts
                .len(),
            2
        );

        let before = fs::read_to_string(&a.config_path).unwrap();
        assert!(
            run_with(&a, false, Cursor::new(""), Vec::new()).is_err(),
            "same id twice"
        );
        assert_eq!(
            before,
            fs::read_to_string(&a.config_path).unwrap(),
            "config untouched on failure"
        );
    }

    #[test]
    fn hostile_input_cannot_inject_toml_keys() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("gmail".into());
        a.display_name = Some("x\"\nread_only = false\npermissions = { send = true }\n#".into());
        run_with(&a, false, Cursor::new(""), Vec::new()).unwrap();
        let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
        assert!(cfg.accounts[0].read_only);
        assert!(cfg.accounts[0].display_name.contains("read_only = false"));
    }

    #[test]
    fn invalid_answers_are_rejected() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("gmail".into());
        a.credential_env = Some("BAD NAME".into());
        assert!(run_with(&a, false, Cursor::new(""), Vec::new()).is_err());
        a.credential_env = None;
        a.id = Some("Bad Id".into());
        assert!(run_with(&a, false, Cursor::new(""), Vec::new()).is_err());
        a.id = None;
        a.preset = Some("nope".into());
        assert!(run_with(&a, false, Cursor::new(""), Vec::new()).is_err());
        a.preset = Some("gmail".into());
        a.email = Some("not-an-email".into());
        assert!(run_with(&a, false, Cursor::new(""), Vec::new()).is_err());
    }

    #[test]
    fn keyring_credential_is_a_reference_only() {
        let dir = TempDir::new();
        let mut a = args(dir.0.join("c.toml"));
        a.preset = Some("gmail".into());
        a.credential_kind = Some("keyring".into());
        let mut out = Vec::new();
        run_with(&a, false, Cursor::new(""), &mut out).unwrap();
        let cfg = Config::from_toml(&fs::read_to_string(&a.config_path).unwrap()).unwrap();
        assert!(
            matches!(&cfg.accounts[0].credential, CredentialRef::Keyring { service, .. } if service == KEYRING_SERVICE)
        );
        assert!(String::from_utf8(out).unwrap().contains("OS keyring"));
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_is_0600_replaces_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let p = dir.0.join("nested/config.toml");
        write_atomic(&p, "one").unwrap();
        write_atomic(&p, "two").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn snippets_cover_clients_and_escape_paths() {
        let s = mcp_snippets(Path::new("/home/a b/it's \"x\".toml"));
        let clients: Vec<_> = s.iter().map(|x| x.client).collect();
        assert_eq!(
            clients,
            ["Claude Desktop", "Claude Code", "Cursor", "VS Code"]
        );
        assert!(s[0].body.contains("\"mcpServers\"") && s[3].body.contains("\"servers\""));
        assert!(s[0].body.contains(r#"\"x\".toml"#));
        assert!(s[1].body.contains(r"'/home/a b/it'\''s"));
    }

    #[test]
    fn default_ids_and_env_vars_are_valid() {
        assert_eq!(
            default_account_id("First.Last+tag@example.com"),
            "first_last_tag"
        );
        assert_eq!(default_account_id("@example.com"), "mail");
        assert!(AccountId::new(default_account_id("ünï@x.com")).is_ok());
        assert_eq!(
            default_env_var("my-box", AuthMethod::Oauth2),
            "OPENMAIL_MY_BOX_TOKEN"
        );
        assert!(
            valid_env_var("A_1")
                && !valid_env_var("1A")
                && !valid_env_var("A B")
                && !valid_env_var("")
        );
    }
}
