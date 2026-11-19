//! `accounts add` / `accounts remove`: mailbox registry on disk.
//!
//! Layout beside the main config: `accounts.d/<id>.toml` (one account, same format as the main
//! file) and `secrets/<id>` (only the password, mode 600 in a 700 directory). The server merges
//! `accounts.d/` at startup (`Config::with_dropins`), so mailboxes survive restarts, upgrades and
//! container recreation as long as the config directory is a volume.
//!
//! Removing deletes only these two files. It never touches the mail server.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use openmail_core::config::Config;
use openmail_core::ids::AccountId;

use crate::cli::{AccountAddArgs, TlsChoice};

const WRITE_PERMISSIONS: [&str; 4] = ["organize", "drafts", "send", "delete"];

pub struct Layout {
    pub dropins: PathBuf,
    pub secrets: PathBuf,
}

impl Layout {
    pub fn beside(main_config: &Path) -> Self {
        Self {
            dropins: Config::dropin_dir(main_config),
            secrets: main_config.with_file_name("secrets"),
        }
    }

    fn account_file(&self, id: &str) -> PathBuf {
        self.dropins.join(format!("{id}.toml"))
    }

    fn secret_file(&self, id: &str) -> PathBuf {
        self.secrets.join(id)
    }
}

fn tls(t: TlsChoice) -> &'static str {
    match t {
        TlsChoice::Implicit => "implicit",
        TlsChoice::StartTls => "start_tls",
    }
}

fn toml_str(s: &str) -> String {
    // A TOML basic string; the inputs are validated below, this only has to be safe for them.
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The drop-in file text for `args`. Pure so it can be tested without touching disk.
pub fn render(args: &AccountAddArgs, secret_path: &Path) -> Result<String> {
    for p in &args.allow {
        if !WRITE_PERMISSIONS.contains(&p.as_str()) {
            bail!("unknown permission `{p}` (choose from organize, drafts, send, delete)");
        }
    }
    let writable = !args.allow.is_empty();
    let mut out = String::from("version = 1\n\n[[account]]\n");
    out.push_str(&format!("id = {}\n", toml_str(&args.id)));
    out.push_str(&format!("display_name = {}\n", toml_str(&args.id)));
    out.push_str(&format!("email = {}\n", toml_str(&args.email)));
    out.push_str("auth = \"password\"\n");
    if let Some(u) = &args.username {
        out.push_str(&format!("username = {}\n", toml_str(u)));
    }
    out.push_str(&format!(
        "credential = {{ kind = \"file\", path = {} }}\n",
        toml_str(&secret_path.to_string_lossy())
    ));
    out.push_str(&format!(
        "imap = {{ host = {}, port = {}, tls = \"{}\" }}\n",
        toml_str(&args.imap_host),
        args.imap_port,
        tls(args.imap_tls)
    ));
    if let Some(h) = &args.smtp_host {
        out.push_str(&format!(
            "smtp = {{ host = {}, port = {}, tls = \"{}\" }}\n",
            toml_str(h),
            args.smtp_port,
            tls(args.smtp_tls)
        ));
    }
    out.push_str(&format!("read_only = {}\n", !writable));
    if writable {
        let on = |name: &str| args.allow.iter().any(|a| a == name);
        out.push_str(&format!(
            "permissions = {{ organize = {}, drafts = {}, send = {}, delete = {} }}\n",
            on("organize"),
            on("drafts"),
            on("send"),
            on("delete")
        ));
    }
    Ok(out)
}

fn private_dir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Write `contents` to `path` atomically with owner-only permissions from the first byte.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// Validates, then stores the password and the account file. `main_config_text` is only used to
/// check the combined configuration (duplicate ids, limits) before anything is written.
pub fn add(
    layout: &Layout,
    existing: &Config,
    args: &AccountAddArgs,
    password: &str,
) -> Result<()> {
    AccountId::new(args.id.clone()).map_err(|e| anyhow!("{e}"))?;
    if password.is_empty() {
        bail!("the password is empty");
    }
    let file = layout.account_file(&args.id);
    let is_dropin = file.exists();
    if existing.accounts.iter().any(|a| a.id.as_str() == args.id) && !(args.replace && is_dropin) {
        bail!(
            "account `{}` already exists{}",
            args.id,
            if is_dropin {
                " (use --replace to rotate it)"
            } else {
                " in the main config; edit it there"
            }
        );
    }
    let text = render(args, &layout.secret_file(&args.id))?;
    // Validate exactly what the server will load, without this account's old definition.
    let mut probe: Config = toml::from_str(&text)
        .map_err(|e| anyhow!("generated account is invalid: {}", e.message()))?;
    for a in existing
        .accounts
        .iter()
        .filter(|a| a.id.as_str() != args.id)
    {
        probe.accounts.push(a.clone());
    }
    probe.validate().map_err(|e| anyhow!("{e}"))?;

    private_dir(&layout.dropins)?;
    private_dir(&layout.secrets)?;
    write_private(&layout.secret_file(&args.id), password)?;
    write_private(&file, &text)?;
    Ok(())
}

/// Delete the drop-in and its secret. Never contacts the mail server.
pub fn remove(layout: &Layout, id: &str) -> Result<()> {
    AccountId::new(id.to_owned()).map_err(|e| anyhow!("{e}"))?;
    let file = layout.account_file(id);
    if !file.exists() {
        bail!(
            "no account `{id}` in {} (accounts defined in the main config must be removed there)",
            layout.dropins.display()
        );
    }
    std::fs::remove_file(&file).with_context(|| format!("removing {}", file.display()))?;
    match std::fs::remove_file(layout.secret_file(id)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing the secret file"),
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(id: &str) -> AccountAddArgs {
        AccountAddArgs {
            id: id.into(),
            email: "me@example.com".into(),
            imap_host: "imap.example.com".into(),
            imap_port: 993,
            imap_tls: TlsChoice::Implicit,
            username: None,
            smtp_host: None,
            smtp_port: 465,
            smtp_tls: TlsChoice::Implicit,
            allow: vec![],
            password_stdin: true,
            replace: false,
        }
    }

    fn base() -> Config {
        Config::from_toml("version = 1\n").unwrap()
    }

    #[test]
    fn added_accounts_survive_a_reload_and_the_password_never_enters_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config.toml");
        std::fs::write(&main, "version = 1\n").unwrap();
        let l = Layout::beside(&main);
        add(&l, &base(), &args("work"), "s3cret-pw").unwrap();
        let mut a2 = args("home");
        a2.smtp_host = Some("smtp.example.com".into());
        a2.allow = vec!["drafts".into()];
        add(&l, &base(), &a2, "other-pw").unwrap();

        // "Restart": a fresh load from disk sees both, with the right shape.
        let cfg = Config::from_toml(&std::fs::read_to_string(&main).unwrap())
            .unwrap()
            .with_dropins(&Config::dropin_dir(&main))
            .unwrap();
        let ids: Vec<_> = cfg.accounts.iter().map(|a| a.id.to_string()).collect();
        assert_eq!(ids, ["home", "work"]);
        let home = &cfg.accounts[0];
        assert!(!home.read_only && home.permissions.drafts && !home.permissions.send);
        assert!(home.smtp.is_some());
        assert!(cfg.accounts[1].read_only);

        let text = std::fs::read_to_string(l.account_file("work")).unwrap();
        assert!(!text.contains("s3cret-pw"), "{text}");
        assert_eq!(
            std::fs::read_to_string(l.secret_file("work")).unwrap(),
            "s3cret-pw"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [
                l.secret_file("work"),
                l.account_file("work"),
                l.secrets.clone(),
            ] {
                assert_eq!(
                    std::fs::metadata(p).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
        }
    }

    #[test]
    fn duplicates_bad_permissions_and_replace_rules() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config.toml");
        let l = Layout::beside(&main);
        add(&l, &base(), &args("work"), "pw1").unwrap();
        let cfg = base().with_dropins(&l.dropins).unwrap();
        assert!(
            add(&l, &cfg, &args("work"), "pw2").is_err(),
            "duplicate without --replace"
        );
        let mut r = args("work");
        r.replace = true;
        add(&l, &cfg, &r, "pw2").unwrap();
        assert_eq!(
            std::fs::read_to_string(l.secret_file("work")).unwrap(),
            "pw2"
        );
        let mut bad = args("x");
        bad.allow = vec!["root".into()];
        assert!(add(&l, &base(), &bad, "p").is_err());
        assert!(add(&l, &base(), &args("Bad Id"), "p").is_err());
        assert!(add(&l, &base(), &args("y"), "").is_err());
    }

    #[test]
    fn remove_deletes_only_openmails_files() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config.toml");
        let l = Layout::beside(&main);
        add(&l, &base(), &args("work"), "pw").unwrap();
        remove(&l, "work").unwrap();
        assert!(!l.account_file("work").exists() && !l.secret_file("work").exists());
        assert!(
            remove(&l, "work").is_err(),
            "second removal reports it is gone"
        );
    }

    #[test]
    fn a_broken_dropin_fails_loudly_instead_of_hiding_a_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config.toml");
        let l = Layout::beside(&main);
        add(&l, &base(), &args("work"), "pw").unwrap();
        std::fs::write(
            l.dropins.join("broken.toml"),
            "version = 1\n[[account]]\nid = 1\n",
        )
        .unwrap();
        let err = base().with_dropins(&l.dropins).unwrap_err().to_string();
        assert!(err.contains("broken.toml"), "{err}");
        // Same id in two files is rejected too.
        std::fs::remove_file(l.dropins.join("broken.toml")).unwrap();
        std::fs::copy(l.account_file("work"), l.dropins.join("work-copy.toml")).unwrap();
        assert!(
            base()
                .with_dropins(&l.dropins)
                .unwrap_err()
                .to_string()
                .contains("already defined")
        );
    }
}
