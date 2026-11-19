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
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if ok {
            Ok(Self(s))
        } else {
            Err(Error::new(ErrorCode::ConfigInvalid, "account id must be 1-64 chars of [a-z0-9_-]"))
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
        let raw = format!("v1\0{}\0{}\0{}\0{}", self.account, self.folder, self.uid_validity, self.uid);
        URL_SAFE_NO_PAD.encode(raw)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bad = || Error::new(ErrorCode::InvalidInput, "malformed message reference");
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad())?;
        let text = String::from_utf8(bytes).map_err(|_| bad())?;
        let parts: Vec<&str> = text.split('\0').collect();
        let [version, account, folder, validity, uid] = parts[..] else { return Err(bad()) };
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
        MessageRef { account: AccountId::new("work-1").unwrap(), folder: "INBOX/Sub é".into(), uid_validity: 42, uid: 7 }
    }

    #[test]
    fn roundtrip() {
        let r = sample();
        assert_eq!(MessageRef::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn rejects_garbage_and_wrong_version() {
        assert!(MessageRef::decode("!!!").is_err());
        let v2 = URL_SAFE_NO_PAD.encode("v2\0a\0INBOX\01\01");
        assert!(MessageRef::decode(&v2).is_err());
        let short = URL_SAFE_NO_PAD.encode("v1\0a\0INBOX\01");
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
