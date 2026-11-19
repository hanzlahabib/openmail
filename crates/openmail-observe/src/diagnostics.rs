//! `safe_diagnostic_export`: produces a JSON document that is safe to attach to
//! a bug report. Secrets, email addresses and message bodies never survive.

use serde_json::{Map, Value};

pub const REDACTED: &str = "[redacted]";
pub const REDACTED_ADDRESS: &str = "[redacted-address]";

/// Object keys whose values are dropped wholesale (case-insensitive substring match).
const SENSITIVE_KEY_PARTS: [&str; 22] = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "credential",
    "cookie",
    "body",
    "html",
    "snippet",
    "subject",
    "attachment",
    "from",
    "to",
    "cc",
    "bcc",
    "address",
    "email",
    "username",
    "user",
];

/// Short keys (`to`, `cc`, `from`, `user`) must match exactly, not as substrings,
/// or `total` / `tokens_used` style keys would be wrongly dropped or missed.
const EXACT_ONLY: [&str; 5] = ["to", "cc", "from", "user", "bcc"];

fn key_is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_KEY_PARTS.iter().any(|p| {
        if EXACT_ONLY.contains(p) {
            k == *p
        } else {
            k.contains(p)
        }
    })
}

/// Prefixes that mark an inline credential; the rest of the token is removed.
const SECRET_PREFIXES: [&str; 4] = ["bearer ", "basic ", "xoauth2 ", "sk-"];

fn is_addr_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

/// Replaces anything shaped like an email address and inline credentials in free text.
pub fn scrub_text(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            // Walk the local part already pushed back and the domain forward.
            let mut start = out.len();
            for (idx, ch) in out.char_indices().rev() {
                if is_addr_char(ch) { start = idx } else { break }
            }
            let mut j = i + 1;
            while j < chars.len()
                && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '.' | '-'))
            {
                j += 1;
            }
            let has_local = start < out.len();
            let has_domain = j > i + 1;
            if has_local && has_domain {
                out.truncate(start);
                out.push_str(REDACTED_ADDRESS);
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    scrub_prefixed_secrets(&out)
}

fn scrub_prefixed_secrets(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while pos < s.len() {
        let hit = SECRET_PREFIXES
            .iter()
            .filter_map(|p| lower[pos..].starts_with(p).then_some(p.len()))
            .next();
        match hit {
            Some(plen) => {
                out.push_str(&s[pos..pos + plen]);
                out.push_str(REDACTED);
                let rest = &s[pos + plen..];
                let skip = rest
                    .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';'))
                    .unwrap_or(rest.len());
                pos += plen + skip;
            }
            None => {
                // Advance one char (not byte) to stay on a boundary.
                let ch_len = s[pos..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&s[pos..pos + ch_len]);
                pos += ch_len;
            }
        }
    }
    out
}

/// Returns a redacted deep copy of `value`.
pub fn safe_diagnostic_export(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if key_is_sensitive(k) {
                    out.insert(k.clone(), Value::String(REDACTED.to_owned()));
                } else {
                    out.insert(k.clone(), safe_diagnostic_export(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(safe_diagnostic_export).collect()),
        Value::String(s) => Value::String(scrub_text(s)),
        other => other.clone(),
    }
}

/// Convenience: pretty-printed redacted JSON text.
pub fn safe_diagnostic_export_string(value: &Value) -> String {
    // Serializing an in-memory `Value` cannot fail; fall back to empty on the impossible.
    serde_json::to_string_pretty(&safe_diagnostic_export(value)).unwrap_or_default()
}

/// The operator's diagnostic bundle (`doctor --export-diagnostics`): version/platform, the
/// caller's config and check summaries, and metric counters, all through the safe export.
/// `details` must already exclude mail content; the scrub is a second line of defence, not a
/// license to pass bodies in.
pub fn diagnostic_bundle(details: &Value, metrics: Option<&crate::metrics::Metrics>) -> String {
    let mut root = Map::new();
    root.insert("version".to_owned(), Value::from(env!("CARGO_PKG_VERSION")));
    root.insert("os".to_owned(), Value::from(std::env::consts::OS));
    root.insert("arch".to_owned(), Value::from(std::env::consts::ARCH));
    root.insert("details".to_owned(), details.clone());
    if let Some(m) = metrics {
        root.insert("metrics".to_owned(), m.snapshot_json());
    }
    safe_diagnostic_export_string(&Value::Object(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CANARY_PASSWORD: &str = "CANARY-pw-7f3a9c";
    const CANARY_TOKEN: &str = "CANARY-tok-91bd22";
    const CANARY_BODY: &str = "CANARY-body-private-text";
    const CANARY_ADDR: &str = "canary.person@example.invalid";

    fn sample() -> Value {
        json!({
            "version": "0.1.0",
            "total": 5,
            "account": {
                "id": "acc_1",
                "username": "canary.person@example.invalid",
                "password": CANARY_PASSWORD,
                "oauth": { "access_token": CANARY_TOKEN },
                "host": "imap.example.invalid"
            },
            "message": {
                "from": CANARY_ADDR,
                "to": [CANARY_ADDR],
                "subject": "CANARY-subject",
                "body": CANARY_BODY,
                "uid": 42
            },
            "last_error": format!(
                "login failed for {CANARY_ADDR}: Authorization: Bearer {CANARY_TOKEN} rejected"
            ),
            "notes": ["retry after 3s", format!("contact {CANARY_ADDR}, thanks")]
        })
    }

    #[test]
    fn canary_secrets_never_leak() {
        let out = safe_diagnostic_export_string(&sample());
        for canary in [
            CANARY_PASSWORD,
            CANARY_TOKEN,
            CANARY_BODY,
            CANARY_ADDR,
            "CANARY-subject",
            "canary.person",
        ] {
            assert!(!out.contains(canary), "leaked {canary}: {out}");
        }
    }

    #[test]
    fn keeps_harmless_diagnostics() {
        let v = safe_diagnostic_export(&sample());
        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["total"], 5);
        assert_eq!(v["account"]["host"], "imap.example.invalid");
        assert_eq!(v["message"]["uid"], 42);
        assert_eq!(v["notes"][0], "retry after 3s");
    }

    #[test]
    fn scrubs_addresses_in_free_text() {
        assert_eq!(
            scrub_text("mail a.b+c@mail.example.invalid failed"),
            format!("mail {REDACTED_ADDRESS} failed")
        );
        assert_eq!(
            scrub_text("user @ home and @handle"),
            "user @ home and @handle"
        );
        assert_eq!(
            scrub_text("naïve é@x.io"),
            format!("naïve {REDACTED_ADDRESS}")
        );
    }

    #[test]
    fn scrubs_inline_credentials() {
        let s = scrub_text("Authorization: Bearer abc.def.ghi next");
        assert!(!s.contains("abc.def.ghi"));
        assert!(s.contains("next"));
    }

    #[test]
    fn bundle_includes_metrics_and_never_leaks_canaries() {
        use crate::metrics::{Counter, Labels, Metrics};
        let m = Metrics::new();
        m.inc_labeled(Counter::AuthFailures, &Labels::none().account("work"));
        let details = json!({
            "accounts": [{ "id": "work", "email": CANARY_ADDR, "password": CANARY_PASSWORD }],
            "note": format!("login as {CANARY_ADDR} with Authorization: Bearer {CANARY_TOKEN} failed"),
        });
        let out = diagnostic_bundle(&details, Some(&m));
        for canary in [CANARY_ADDR, CANARY_PASSWORD, CANARY_TOKEN, "canary.person"] {
            assert!(!out.contains(canary), "leaked {canary}: {out}");
        }
        assert!(out.contains("auth_failures"), "{out}");
        assert!(out.contains("\"version\""), "{out}");
    }
}
