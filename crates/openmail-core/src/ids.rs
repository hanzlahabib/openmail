//! Stable identifiers. IMAP sequence numbers are never persisted; a message is
//! addressed by (account, folder, UIDVALIDITY, UID) so a UIDVALIDITY change makes
//! old references detectably stale instead of silently pointing at another mail.
use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);

impl AccountId {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if ok {
            Ok(Self(s))
        } else {
            Err(Error::new(
                ErrorCode::ConfigInvalid,
                "account id must be 1-64 chars of [a-z0-9_-]",
            ))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for AccountId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}
impl From<AccountId> for String {
    fn from(a: AccountId) -> Self {
        a.0
    }
}
impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque, URL-safe reference handed to MCP clients.
/// Wire form: base64url("v1\0account\0folder\0uidvalidity\0uid").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageRef {
    pub account: AccountId,
    pub folder: String,
    pub uid_validity: u32,
    pub uid: u32,
}

impl MessageRef {
    pub fn encode(&self) -> String {
        let raw = format!(
            "v1\0{}\0{}\0{}\0{}",
            self.account, self.folder, self.uid_validity, self.uid
        );
        URL_SAFE_NO_PAD.encode(raw)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bad = || Error::new(ErrorCode::InvalidInput, "malformed message reference");
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad())?;
        let text = String::from_utf8(bytes).map_err(|_| bad())?;
        let parts: Vec<&str> = text.split('\0').collect();
        let [version, account, folder, validity, uid] = parts[..] else {
            return Err(bad());
        };
        if version != "v1" || folder.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            account: AccountId::new(account).map_err(|_| bad())?,
            folder: folder.to_owned(),
            uid_validity: validity.parse().map_err(|_| bad())?,
            uid: uid.parse().map_err(|_| bad())?,
        })
    }
}

impl Serialize for MessageRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.encode())
    }
}
impl<'de> Deserialize<'de> for MessageRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MessageRef {
        MessageRef {
            account: AccountId::new("work-1").unwrap(),
            folder: "INBOX/Sub é".into(),
            uid_validity: 42,
            uid: 7,
        }
    }

    #[test]
    fn roundtrip() {
        let r = sample();
        assert_eq!(MessageRef::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn rejects_garbage_and_wrong_version() {
        assert!(MessageRef::decode("!!!").is_err());
        let v2 = URL_SAFE_NO_PAD.encode("v2\x00a\x00INBOX\x001\x001");
        assert!(MessageRef::decode(&v2).is_err());
        let short = URL_SAFE_NO_PAD.encode("v1\x00a\x00INBOX\x001");
        assert!(MessageRef::decode(&short).is_err());
    }

    #[test]
    fn account_id_validation() {
        for bad in ["", "Upper", "has space", "a/b", &"x".repeat(65)] {
            assert!(AccountId::new(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(AccountId::new("ok_1-a").is_ok());
    }
}

/// Longest References chain kept on an outgoing message (the newest entries win).
pub const MAX_REFERENCES: usize = 20;

/// An RFC 5322 `<id@host>` token for a Message-ID as parsers hand it over. `mail-parser`
/// returns IDs without angle brackets, headers on the wire carry them; both are accepted.
/// Anything that could break out of the header (whitespace, controls, brackets inside) or
/// has no `@` is rejected, because these values come from mail we did not write.
#[must_use]
pub fn wrap_message_id(id: &str) -> Option<String> {
    let id = id.trim().trim_start_matches('<').trim_end_matches('>');
    let ok = id.len() <= 998
        && id.contains('@')
        && !id
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>');
    ok.then(|| format!("<{id}>"))
}

/// Normalised `(In-Reply-To, References)` for a reply: valid IDs only (a malformed entry is
/// dropped, never allowed to discard the rest of the thread), de-duplicated, capped to the
/// newest [`MAX_REFERENCES`]. `parent` is appended to the chain when it is not already there.
#[must_use]
pub fn reply_threading(
    in_reply_to: Option<&str>,
    references: &[String],
    parent: Option<&str>,
) -> (Option<String>, Vec<String>) {
    let mut refs: Vec<String> = Vec::new();
    for id in references.iter().filter_map(|r| wrap_message_id(r)) {
        if !refs.contains(&id) {
            refs.push(id);
        }
    }
    let parent = parent.and_then(wrap_message_id);
    if let Some(p) = &parent
        && !refs.contains(p)
    {
        refs.push(p.clone());
    }
    let irt = parent
        .or_else(|| in_reply_to.and_then(wrap_message_id))
        .or_else(|| refs.last().cloned());
    let skip = refs.len().saturating_sub(MAX_REFERENCES);
    (irt, refs.split_off(skip))
}

#[cfg(test)]
mod threading_tests {
    use super::*;

    #[test]
    fn wraps_bare_and_bracketed_ids_and_rejects_unsafe_ones() {
        assert_eq!(wrap_message_id("a@x.org").as_deref(), Some("<a@x.org>"));
        assert_eq!(wrap_message_id("<a@x.org>").as_deref(), Some("<a@x.org>"));
        assert_eq!(wrap_message_id("junk"), None);
        assert_eq!(wrap_message_id("a@x.org\r\nBcc: v@evil.test"), None);
        assert_eq!(wrap_message_id("<a@x> <b@x>"), None);
    }

    #[test]
    fn reply_threading_keeps_valid_entries_dedupes_and_caps() {
        let refs: Vec<String> = (0..25).map(|i| format!("m{i}@x.org")).collect();
        let (irt, out) = reply_threading(None, &refs, Some("parent@x.org"));
        assert_eq!(irt.as_deref(), Some("<parent@x.org>"));
        assert_eq!(out.len(), MAX_REFERENCES);
        assert_eq!(out.last().map(String::as_str), Some("<parent@x.org>"));
        let (irt, out) = reply_threading(
            Some("c@x.org"),
            &["junk".into(), "<a@x.org>".into(), "a@x.org".into()],
            None,
        );
        assert_eq!(irt.as_deref(), Some("<c@x.org>"));
        assert_eq!(out, vec!["<a@x.org>"]);
    }
}
