//! Authorization: deny by default. A request is allowed only if the principal
//! may touch the account, holds the scope, the account is not read-only and the
//! account's own `Permissions` grant the action.
use std::collections::BTreeSet;

use openmail_core::config::{AccountConfig, Config};
use openmail_core::ids::AccountId;
use openmail_core::{Error, ErrorCode, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    Read,
    Organize,
    Draft,
    Send,
    Delete,
}

/// An authenticated MCP client. Accounts and scopes are explicit allowlists;
/// there is no wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    client_id: String,
    accounts: BTreeSet<AccountId>,
    scopes: BTreeSet<Action>,
}

impl Principal {
    pub fn new(client_id: impl Into<String>, accounts: impl IntoIterator<Item = AccountId>, scopes: impl IntoIterator<Item = Action>) -> Self {
        Self { client_id: client_id.into(), accounts: accounts.into_iter().collect(), scopes: scopes.into_iter().collect() }
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Authorizer<'a> {
    config: &'a Config,
}

impl<'a> Authorizer<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    /// Returns the account config when `action` is allowed.
    pub fn authorize(&self, principal: &Principal, account: &AccountId, action: Action) -> Result<&'a AccountConfig> {
        // Checked before the config lookup so a principal cannot probe which
        // account ids exist outside its allowlist.
        if !principal.accounts.contains(account) || !principal.scopes.contains(&action) {
            return Err(Error::new(ErrorCode::AccessDenied, format!("access to account '{account}' denied")));
        }
        let cfg = self.config.account(account)?;
        if action == Action::Read {
            return Ok(cfg);
        }
        if cfg.read_only {
            return Err(Error::new(ErrorCode::ReadOnlyAccount, format!("account '{account}' is read-only")));
        }
        let p = &cfg.permissions;
        let granted = match action {
            Action::Read => true,
            Action::Organize => p.organize,
            Action::Draft => p.drafts,
            Action::Send => p.send && cfg.smtp.is_some(),
            Action::Delete => p.delete,
        };
        if granted {
            Ok(cfg)
        } else {
            Err(Error::new(ErrorCode::AccessDenied, format!("{action:?} is not permitted on account '{account}'")))
        }
    }

    /// Accounts the principal may read, so listings never reveal others.
    pub fn visible_accounts(&self, principal: &Principal) -> Vec<&'a AccountConfig> {
        self.config.accounts.iter().filter(|a| self.authorize(principal, &a.id, Action::Read).is_ok()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
version = 1
[[account]]
id = "ro"
display_name = "RO"
email = "ro@example.com"
auth = "password"
credential = { kind = "env", var = "A" }
imap = { host = "i.example.com", port = 993, tls = "implicit" }

[[account]]
id = "rw"
display_name = "RW"
email = "rw@example.com"
auth = "password"
credential = { kind = "env", var = "B" }
imap = { host = "i.example.com", port = 993, tls = "implicit" }
smtp = { host = "s.example.com", port = 465, tls = "implicit" }
read_only = false
permissions = { organize = true, drafts = true, send = true }

[[account]]
id = "secret"
display_name = "S"
email = "s@example.com"
auth = "password"
credential = { kind = "env", var = "C" }
imap = { host = "i.example.com", port = 993, tls = "implicit" }
"#;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }
    fn cfg() -> Config {
        Config::from_toml(CFG).unwrap()
    }
    const ALL: [Action; 5] = [Action::Read, Action::Organize, Action::Draft, Action::Send, Action::Delete];

    #[test]
    fn default_deny_for_empty_principal() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [], []);
        for acct in ["ro", "rw", "secret"] {
            for act in ALL {
                assert_eq!(a.authorize(&p, &id(acct), act).unwrap_err().code(), ErrorCode::AccessDenied);
            }
        }
    }

    #[test]
    fn read_only_account_blocks_writes_even_with_scopes() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("ro")], ALL);
        assert!(a.authorize(&p, &id("ro"), Action::Read).is_ok());
        for act in [Action::Organize, Action::Draft, Action::Send, Action::Delete] {
            assert_eq!(a.authorize(&p, &id("ro"), act).unwrap_err().code(), ErrorCode::ReadOnlyAccount);
        }
    }

    #[test]
    fn account_permissions_gate_actions_and_delete_is_separate() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("rw")], ALL);
        for act in [Action::Read, Action::Organize, Action::Draft, Action::Send] {
            assert!(a.authorize(&p, &id("rw"), act).is_ok(), "{act:?}");
        }
        assert_eq!(a.authorize(&p, &id("rw"), Action::Delete).unwrap_err().code(), ErrorCode::AccessDenied);
    }

    #[test]
    fn principal_scopes_narrow_account_permissions() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("rw")], [Action::Read]);
        assert!(a.authorize(&p, &id("rw"), Action::Read).is_ok());
        assert_eq!(a.authorize(&p, &id("rw"), Action::Send).unwrap_err().code(), ErrorCode::AccessDenied);
    }

    #[test]
    fn cross_account_isolation() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("rw")], ALL);
        assert_eq!(a.authorize(&p, &id("secret"), Action::Read).unwrap_err().code(), ErrorCode::AccessDenied);
        // Existing and non-existing foreign accounts are indistinguishable.
        assert_eq!(a.authorize(&p, &id("nonexistent"), Action::Read).unwrap_err().code(), ErrorCode::AccessDenied);
        let visible: Vec<_> = a.visible_accounts(&p).iter().map(|x| x.id.as_str().to_owned()).collect();
        assert_eq!(visible, ["rw"]);
    }

    #[test]
    fn allowed_but_unconfigured_account_is_not_found() {
        let c = cfg();
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("ghost")], ALL);
        assert_eq!(a.authorize(&p, &id("ghost"), Action::Read).unwrap_err().code(), ErrorCode::AccountNotFound);
    }

    #[test]
    fn unvalidated_config_cannot_bypass_read_only_or_missing_smtp() {
        let mut c = cfg();
        // Hand-built config skipping validate(): read_only must still dominate.
        c.accounts[0].permissions.send = true;
        c.accounts[1].smtp = None;
        let a = Authorizer::new(&c);
        let p = Principal::new("c", [id("ro"), id("rw")], ALL);
        assert_eq!(a.authorize(&p, &id("ro"), Action::Send).unwrap_err().code(), ErrorCode::ReadOnlyAccount);
        assert_eq!(a.authorize(&p, &id("rw"), Action::Send).unwrap_err().code(), ErrorCode::AccessDenied);
    }
}
