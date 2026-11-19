//! TOML configuration. Secrets are never stored inline: an account only holds a
//! `CredentialRef` (env var or OS keyring entry). Unknown keys are rejected so a
//! typo like `read_onyl = false` cannot silently loosen security.
use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ids::AccountId;
use crate::{Error, ErrorCode, Result};

/// Current on-disk schema. Bump with a migration; older files must keep loading.
pub const CONFIG_VERSION: u32 = 1;
/// IMAP sessions kept per account unless configured; small because 100 configured
/// mailboxes must not mean 100 live sessions.
pub const DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT: u8 = 2;
/// Global cap on simultaneously open IMAP sessions across all accounts.
pub const DEFAULT_MAX_GLOBAL_CONNECTIONS: u16 = 8;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_CONFIGURED_ACCOUNTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS from the first byte (IMAPS 993 / SMTPS 465).
    Implicit,
    /// Upgrade via STARTTLS; connection is refused if the upgrade fails.
    StartTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    /// SASL XOAUTH2 / OAUTHBEARER.
    Oauth2,
}

/// Where a secret lives. Never the secret itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialRef {
    Env { var: String },
    Keyring { service: String, user: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEndpoint {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
}

/// Capabilities granted per account. Everything beyond reading is opt-in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Permissions {
    pub organize: bool,
    pub drafts: bool,
    pub send: bool,
    /// Separately gated, never part of any default profile.
    pub delete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FolderMap {
    pub inbox: Option<String>,
    pub sent: Option<String>,
    pub drafts: Option<String>,
    pub archive: Option<String>,
    pub trash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub id: AccountId,
    pub display_name: String,
    pub email: String,
    pub imap: ServerEndpoint,
    pub smtp: Option<ServerEndpoint>,
    pub auth: AuthMethod,
    pub username: Option<String>,
    pub credential: CredentialRef,
    #[serde(default = "yes")]
    pub read_only: bool,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub folders: FolderMap,
    #[serde(default = "default_conns")]
    pub max_connections: u8,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn yes() -> bool {
    true
}
fn default_conns() -> u8 {
    DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT
}
fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

impl AccountConfig {
    pub fn login_name(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.email)
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_global_connections: u16,
    pub max_body_bytes: usize,
    pub max_page_size: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_global_connections: DEFAULT_MAX_GLOBAL_CONNECTIONS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_page_size: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default, rename = "account")]
    pub accounts: Vec<AccountConfig>,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)
            .map_err(|e| Error::new(ErrorCode::ConfigInvalid, e.message().to_owned()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn account(&self, id: &AccountId) -> Result<&AccountConfig> {
        self.accounts.iter().find(|a| &a.id == id).ok_or_else(|| {
            Error::new(
                ErrorCode::AccountNotFound,
                format!("unknown account '{id}'"),
            )
        })
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::new(ErrorCode::ConfigInvalid, m));
        if self.version > CONFIG_VERSION {
            return bad(format!(
                "config version {} is newer than supported {CONFIG_VERSION}",
                self.version
            ));
        }
        if self.accounts.len() > MAX_CONFIGURED_ACCOUNTS {
            return bad(format!(
                "more than {MAX_CONFIGURED_ACCOUNTS} accounts configured"
            ));
        }
        let mut seen = BTreeSet::new();
        for a in &self.accounts {
            if !seen.insert(&a.id) {
                return bad(format!("duplicate account id '{}'", a.id));
            }
            if !a.email.contains('@') || a.email.starts_with('@') || a.email.ends_with('@') {
                return bad(format!("account '{}': invalid email address", a.id));
            }
            if a.imap.host.trim().is_empty() || a.imap.port == 0 {
                return bad(format!("account '{}': imap host/port required", a.id));
            }
            if let Some(s) = &a.smtp
                && (s.host.trim().is_empty() || s.port == 0)
            {
                return bad(format!("account '{}': smtp host/port required", a.id));
            }
            if a.max_connections == 0 || a.max_connections > 10 {
                return bad(format!("account '{}': max_connections must be 1-10", a.id));
            }
            if a.timeout_secs == 0 || a.timeout_secs > 300 {
                return bad(format!("account '{}': timeout_secs must be 1-300", a.id));
            }
            if a.read_only
                && (a.permissions.organize
                    || a.permissions.drafts
                    || a.permissions.send
                    || a.permissions.delete)
            {
                return bad(format!(
                    "account '{}': read_only = true conflicts with write permissions",
                    a.id
                ));
            }
            if a.permissions.send && a.smtp.is_none() {
                return bad(format!(
                    "account '{}': send permission requires an [account.smtp] section",
                    a.id
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
version = 1
[[account]]
id = "personal"
display_name = "Personal"
email = "me@example.com"
auth = "password"
credential = { kind = "env", var = "OPENMAIL_PERSONAL_PASSWORD" }
imap = { host = "imap.example.com", port = 993, tls = "implicit" }
"#;

    #[test]
    fn minimal_config_defaults_to_read_only() {
        let c = Config::from_toml(GOOD).unwrap();
        let a = &c.accounts[0];
        assert!(a.read_only);
        assert_eq!(a.permissions, Permissions::default());
        assert_eq!(a.max_connections, DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT);
    }

    #[test]
    fn unknown_keys_rejected() {
        let t = GOOD.replace(
            "auth = \"password\"",
            "auth = \"password\"\nread_onyl = false",
        );
        assert_eq!(
            Config::from_toml(&t).unwrap_err().code(),
            ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn inline_password_field_rejected() {
        let t = GOOD.replace(
            "auth = \"password\"",
            "auth = \"password\"\npassword = \"hunter2\"",
        );
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn read_only_conflicts_with_write_permissions() {
        let t = format!("{GOOD}permissions = {{ drafts = true }}\n");
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn send_requires_smtp() {
        let t = format!("{GOOD}read_only = false\npermissions = {{ send = true }}\n");
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn duplicate_ids_rejected() {
        let t = format!("{GOOD}{}", GOOD.replace("version = 1", ""));
        assert!(Config::from_toml(&t).is_err());
    }

    #[test]
    fn future_version_rejected() {
        assert!(Config::from_toml(&GOOD.replace("version = 1", "version = 99")).is_err());
    }
}
