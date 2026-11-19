//! Property tests for the frozen core contracts: references, account ids, config parsing.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use openmail_core::config::Config;
use openmail_core::ids::{AccountId, MessageRef};
use proptest::prelude::*;

fn account_id() -> impl Strategy<Value = AccountId> {
    "[a-z0-9_-]{1,64}".prop_map(|s| AccountId::new(s).unwrap())
}

proptest! {
    #[test]
    fn message_ref_roundtrips(
        account in account_id(),
        // Folder names are arbitrary UTF-8 except NUL (the wire separator) and empty.
        folder in "[^\\x00]{1,40}",
        uid_validity in any::<u32>(),
        uid in any::<u32>(),
    ) {
        let r = MessageRef { account, folder, uid_validity, uid };
        prop_assert_eq!(MessageRef::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn message_ref_decode_never_panics(s in any::<String>()) {
        let _ = MessageRef::decode(&s);
    }

    #[test]
    fn message_ref_encoding_is_url_safe(
        account in account_id(),
        folder in "[^\\x00]{1,40}",
        uid in any::<u32>(),
    ) {
        let enc = MessageRef { account, folder, uid_validity: 1, uid }.encode();
        prop_assert!(enc.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn account_id_accepts_exactly_the_documented_alphabet(s in any::<String>()) {
        let expected = !s.is_empty()
            && s.len() <= 64
            && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'));
        prop_assert_eq!(AccountId::new(s).is_ok(), expected);
    }

    #[test]
    fn account_id_rejects_any_string_with_a_foreign_char(
        prefix in "[a-z0-9_-]{0,10}",
        bad in prop::char::any().prop_filter("outside alphabet", |c| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        }),
        suffix in "[a-z0-9_-]{0,10}",
    ) {
        let candidate = format!("{prefix}{bad}{suffix}");
        prop_assert!(AccountId::new(candidate).is_err());
    }

    #[test]
    fn config_from_toml_never_panics(s in any::<String>()) {
        let _ = Config::from_toml(&s);
    }

    #[test]
    fn config_from_toml_never_panics_on_toml_like_input(
        s in "(\\[?[a-z_.]{0,12}\\]?\\]? ?=? ?(\"[^\"\\n]{0,10}\"|[0-9]{0,6}|true|false)?\\n){0,20}",
    ) {
        let _ = Config::from_toml(&s);
    }
}

const VALID: &str = r#"
version = 1

[[account]]
id = "work"
display_name = "Work"
email = "me@example.com"
auth = "password"
credential = { kind = "env", var = "WORK_PW" }
[account.imap]
host = "imap.example.com"
port = 993
tls = "implicit"
"#;

#[test]
fn baseline_config_is_valid() {
    Config::from_toml(VALID)
        .expect("baseline must parse so the unknown-key properties are meaningful");
}

proptest! {
    #[test]
    fn unknown_top_level_key_is_rejected(key in "[a-z_]{1,12}") {
        prop_assume!(!matches!(key.as_str(), "version" | "limits" | "account"));
        let text = format!("{key} = 1\n{VALID}");
        prop_assert!(Config::from_toml(&text).is_err());
    }

    #[test]
    fn unknown_account_key_is_rejected(key in "[a-z_]{1,12}") {
        let known = [
            "id", "display_name", "email", "imap", "smtp", "auth", "username", "credential",
            "read_only", "permissions", "folders", "max_connections", "timeout_secs",
        ];
        prop_assume!(!known.contains(&key.as_str()));
        let text = VALID.replace("[account.imap]", &format!("{key} = true\n[account.imap]"));
        prop_assert!(Config::from_toml(&text).is_err());
    }

    #[test]
    fn unknown_limits_key_is_rejected(key in "[a-z_]{1,12}") {
        prop_assume!(!matches!(key.as_str(), "max_global_connections" | "max_body_bytes" | "max_page_size"));
        let text = format!("version = 1\n[limits]\n{key} = 1\n");
        prop_assert!(Config::from_toml(&text).is_err());
    }
}
