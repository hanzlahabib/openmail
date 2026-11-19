//! `SecretSource` backed by environment variables and the OS keyring.
//!
//! Keyring backends (keyring-core 1 plus per-platform stores; keyring 4's own `v1`
//! API is not used because it hard-wires the zbus stack, whose zvariant/zbus_names
//! crates carry unmaintained advisories, see docs/SUPPLY_CHAIN.md):
//! - Linux: the D-Bus Secret Service (GNOME Keyring / KWallet) through libdbus when a
//!   session bus and service are reachable, otherwise the kernel keyutils keyring
//!   (works headless, but is not persisted across reboots).
//! - macOS: Keychain. Windows: Credential Manager. (Not testable on the Linux CI host.)
//!
//! Environment credential refs never touch the keyring. Keyring calls block (D-Bus
//! round trip), so async callers should resolve credentials via `spawn_blocking` or
//! once at connect time.
use std::env::VarError;
use std::fmt;

use openmail_core::backend::SecretSource;
use openmail_core::config::CredentialRef;
use openmail_core::{Error, ErrorCode, Result};
use secrecy::SecretString;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use keyring_core::Entry;

/// Why a keyring lookup failed, without carrying backend text (some keyring
/// error variants embed the raw secret bytes, so they are never formatted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringFailure {
    NoEntry,
    Unavailable,
    BadEncoding,
    Other,
}

pub trait EnvProvider: Send + Sync {
    fn var(&self, name: &str) -> std::result::Result<String, VarError>;
}

pub trait KeyringProvider: Send + Sync {
    fn password(&self, service: &str, user: &str) -> std::result::Result<String, KeyringFailure>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvProvider for ProcessEnv {
    fn var(&self, name: &str) -> std::result::Result<String, VarError> {
        std::env::var(name)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsKeyring;

impl KeyringProvider for OsKeyring {
    fn password(&self, service: &str, user: &str) -> std::result::Result<String, KeyringFailure> {
        os_password(service, user)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn os_password(service: &str, user: &str) -> std::result::Result<String, KeyringFailure> {
    let stores = os_stores();
    if stores.is_empty() {
        return Err(KeyringFailure::Unavailable);
    }
    let mut last = KeyringFailure::Unavailable;
    for store in stores {
        match store
            .build(service, user, None)
            .and_then(|entry: Entry| entry.get_password())
        {
            Ok(v) => return Ok(v),
            // A reachable store that simply lacks the entry is authoritative.
            Err(keyring_core::Error::NoEntry) => return Err(KeyringFailure::NoEntry),
            Err(e) => last = classify(&e),
        }
    }
    Err(last)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn os_password(_: &str, _: &str) -> std::result::Result<String, KeyringFailure> {
    Err(KeyringFailure::Unavailable)
}

/// Stores to try in order, initialised once per process.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn os_stores() -> &'static [std::sync::Arc<keyring_core::api::CredentialStore>] {
    use std::sync::{Arc, OnceLock};
    static STORES: OnceLock<Vec<Arc<keyring_core::api::CredentialStore>>> = OnceLock::new();
    STORES.get_or_init(|| {
        let mut stores: Vec<Arc<keyring_core::api::CredentialStore>> = Vec::new();
        #[cfg(target_os = "linux")]
        {
            // Secret Service first (persistent); keyutils as the headless fallback.
            if let Ok(s) = dbus_secret_service_keyring_store::Store::new() {
                stores.push(s);
            }
            if let Ok(s) = linux_keyutils_keyring_store::Store::new() {
                stores.push(s);
            }
        }
        #[cfg(target_os = "macos")]
        if let Ok(s) = apple_native_keyring_store::keychain::Store::new() {
            stores.push(s);
        }
        #[cfg(target_os = "windows")]
        if let Ok(s) = windows_native_keyring_store::Store::new() {
            stores.push(s);
        }
        stores
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn classify(e: &keyring_core::Error) -> KeyringFailure {
    use keyring_core::Error as Ke;
    match e {
        Ke::NoEntry => KeyringFailure::NoEntry,
        Ke::NoStorageAccess(_) | Ke::NoDefaultStore | Ke::PlatformFailure(_) => {
            KeyringFailure::Unavailable
        }
        Ke::BadEncoding(_) => KeyringFailure::BadEncoding,
        _ => KeyringFailure::Other,
    }
}

pub struct EnvKeyringSecretSource<E = ProcessEnv, K = OsKeyring> {
    env: E,
    keyring: K,
}

impl EnvKeyringSecretSource {
    pub fn new() -> Self {
        Self {
            env: ProcessEnv,
            keyring: OsKeyring,
        }
    }
}

impl Default for EnvKeyringSecretSource {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: EnvProvider, K: KeyringProvider> EnvKeyringSecretSource<E, K> {
    pub fn with_providers(env: E, keyring: K) -> Self {
        Self { env, keyring }
    }
}

impl<E, K> fmt::Debug for EnvKeyringSecretSource<E, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvKeyringSecretSource")
            .finish_non_exhaustive()
    }
}

fn auth_failed(message: String) -> Error {
    Error::new(ErrorCode::AuthFailed, message)
}

impl<E: EnvProvider, K: KeyringProvider> SecretSource for EnvKeyringSecretSource<E, K> {
    fn resolve(&self, reference: &CredentialRef) -> Result<SecretString> {
        match reference {
            CredentialRef::Env { var } => {
                if var.is_empty() || var.contains(['=', '\0']) {
                    return Err(Error::new(ErrorCode::ConfigInvalid, "credential env var name is empty or contains '=' or NUL"));
                }
                match self.env.var(var) {
                    Ok(v) if v.is_empty() => Err(auth_failed(format!("environment variable '{var}' is set but empty"))),
                    Ok(v) => Ok(SecretString::from(v)),
                    Err(VarError::NotPresent) => Err(auth_failed(format!("environment variable '{var}' is not set"))),
                    Err(VarError::NotUnicode(_)) => Err(auth_failed(format!("environment variable '{var}' is not valid UTF-8"))),
                }
            }
            CredentialRef::Keyring { service, user } => match self.keyring.password(service, user) {
                Ok(v) if v.is_empty() => Err(auth_failed(format!("keyring entry '{service}'/'{user}' is empty"))),
                Ok(v) => Ok(SecretString::from(v)),
                Err(KeyringFailure::NoEntry) => Err(auth_failed(format!("no keyring entry for service '{service}', user '{user}'"))),
                Err(KeyringFailure::Unavailable) => Err(auth_failed(
                    "OS keyring is unavailable or locked (no Secret Service or kernel keyring reachable; use kind = \"env\" instead)".to_owned(),
                )),
                Err(KeyringFailure::BadEncoding) => Err(auth_failed(format!("keyring entry '{service}'/'{user}' is not valid UTF-8 text"))),
                Err(KeyringFailure::Other) => Err(auth_failed("keyring backend error".to_owned())),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openmail_core::config::Config;
    use secrecy::ExposeSecret;

    use super::*;

    const CANARY: &str = "CANARY-p4ssw0rd-9f3a";

    struct FakeEnv(HashMap<&'static str, Result<String, VarError>>);
    impl EnvProvider for FakeEnv {
        fn var(&self, name: &str) -> std::result::Result<String, VarError> {
            match self.0.get(name) {
                Some(Ok(v)) => Ok(v.clone()),
                Some(Err(VarError::NotUnicode(s))) => Err(VarError::NotUnicode(s.clone())),
                _ => Err(VarError::NotPresent),
            }
        }
    }
    struct FakeKeyring(Result<String, KeyringFailure>);
    impl KeyringProvider for FakeKeyring {
        fn password(&self, _: &str, _: &str) -> std::result::Result<String, KeyringFailure> {
            self.0.clone()
        }
    }

    fn source(
        env: Vec<(&'static str, Result<String, VarError>)>,
        kr: Result<String, KeyringFailure>,
    ) -> EnvKeyringSecretSource<FakeEnv, FakeKeyring> {
        EnvKeyringSecretSource::with_providers(FakeEnv(env.into_iter().collect()), FakeKeyring(kr))
    }
    fn env_ref(var: &str) -> CredentialRef {
        CredentialRef::Env { var: var.into() }
    }
    fn kr_ref() -> CredentialRef {
        CredentialRef::Keyring {
            service: "openmail".into(),
            user: "me@example.com".into(),
        }
    }

    #[test]
    fn env_resolves_and_secret_debug_is_redacted() {
        let s = source(
            vec![("PW", Ok(CANARY.into()))],
            Err(KeyringFailure::NoEntry),
        );
        let secret = s.resolve(&env_ref("PW")).unwrap();
        assert_eq!(secret.expose_secret(), CANARY);
        assert!(!format!("{secret:?}").contains(CANARY));
        assert!(!format!("{s:?}").contains(CANARY));
    }

    #[test]
    fn missing_env_names_the_var_not_a_value() {
        let s = source(vec![], Err(KeyringFailure::NoEntry));
        let e = s.resolve(&env_ref("OPENMAIL_MISSING")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::AuthFailed);
        assert!(e.to_string().contains("OPENMAIL_MISSING"));
    }

    #[test]
    fn empty_and_non_unicode_env_rejected_without_leaking() {
        let s = source(vec![("E", Ok(String::new()))], Err(KeyringFailure::NoEntry));
        assert_eq!(
            s.resolve(&env_ref("E")).unwrap_err().code(),
            ErrorCode::AuthFailed
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
            let s = source(
                vec![("N", Err(VarError::NotUnicode(bad)))],
                Err(KeyringFailure::NoEntry),
            );
            let e = s.resolve(&env_ref("N")).unwrap_err();
            assert!(e.to_string().contains("not valid UTF-8"));
        }
    }

    #[test]
    fn malformed_env_names_rejected() {
        let s = source(vec![], Err(KeyringFailure::NoEntry));
        for bad in ["", "A=B", "A\0B"] {
            assert_eq!(
                s.resolve(&env_ref(bad)).unwrap_err().code(),
                ErrorCode::ConfigInvalid,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn keyring_success_and_failures_map_to_typed_errors() {
        let ok = source(vec![], Ok(CANARY.into()));
        assert_eq!(ok.resolve(&kr_ref()).unwrap().expose_secret(), CANARY);
        for f in [
            KeyringFailure::NoEntry,
            KeyringFailure::Unavailable,
            KeyringFailure::BadEncoding,
            KeyringFailure::Other,
        ] {
            let e = source(vec![], Err(f)).resolve(&kr_ref()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::AuthFailed);
            assert!(!e.to_string().contains(CANARY));
        }
        assert_eq!(
            source(vec![], Ok(String::new()))
                .resolve(&kr_ref())
                .unwrap_err()
                .code(),
            ErrorCode::AuthFailed
        );
    }

    #[test]
    fn debug_of_account_config_never_contains_the_resolved_secret() {
        let cfg = Config::from_toml(
            r#"
version = 1
[[account]]
id = "p"
display_name = "P"
email = "me@example.com"
auth = "password"
credential = { kind = "env", var = "PW" }
imap = { host = "imap.example.com", port = 993, tls = "implicit" }
"#,
        )
        .unwrap();
        let s = source(
            vec![("PW", Ok(CANARY.into()))],
            Err(KeyringFailure::NoEntry),
        );
        let secret = s.resolve(&cfg.accounts[0].credential).unwrap();
        let dump = format!("{cfg:?} {:?} {secret:?} {s:?}", cfg.accounts[0]);
        assert!(!dump.contains(CANARY));
    }

    /// Keyring provider that fails the test if it is ever consulted.
    struct ForbiddenKeyring;
    impl KeyringProvider for ForbiddenKeyring {
        fn password(&self, _: &str, _: &str) -> std::result::Result<String, KeyringFailure> {
            panic!("keyring must not be consulted for an env credential ref");
        }
    }

    #[test]
    fn env_refs_never_touch_the_keyring() {
        let env = FakeEnv(
            [("PW", Ok(CANARY.to_owned())), ("EMPTY", Ok(String::new()))]
                .into_iter()
                .collect(),
        );
        let s = EnvKeyringSecretSource::with_providers(env, ForbiddenKeyring);
        // Success, empty, missing and malformed names all stay off the keyring.
        assert_eq!(s.resolve(&env_ref("PW")).unwrap().expose_secret(), CANARY);
        for name in ["EMPTY", "MISSING", "", "A=B"] {
            assert!(s.resolve(&env_ref(name)).is_err(), "{name:?}");
        }
    }

    #[test]
    fn real_os_keyring_lookup_of_absent_entry_is_a_typed_failure() {
        // Headless CI may have no Secret Service; both outcomes are typed, neither panics
        // nor leaks. A fresh random user guarantees the entry cannot exist.
        let user = format!("absent-{}", std::process::id());
        let r = OsKeyring.password("openmail-test-nonexistent", &user);
        assert!(matches!(
            r,
            Err(KeyringFailure::NoEntry | KeyringFailure::Unavailable)
        ));
    }

    #[test]
    fn real_process_env_provider_reads_environment() {
        // PATH is set on every supported platform; asserts the real provider is wired.
        let s = EnvKeyringSecretSource::new();
        assert!(s.resolve(&env_ref("PATH")).is_ok());
        assert_eq!(
            s.resolve(&env_ref("OPENMAIL_DEFINITELY_UNSET_VAR_X"))
                .unwrap_err()
                .code(),
            ErrorCode::AuthFailed
        );
    }
}
