//! Pagination cursors: base64url("c1\0folder\0uidvalidity\0last_uid"). Pages walk
//! UIDs downward, so `last_uid` is the lowest UID already returned.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openmail_core::{Error, ErrorCode, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub folder: String,
    pub uid_validity: u32,
    pub last_uid: u32,
}

impl Cursor {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!(
            "c1\0{}\0{}\0{}",
            self.folder, self.uid_validity, self.last_uid
        ))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bad = || Error::new(ErrorCode::InvalidInput, "malformed pagination cursor");
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad())?;
        let text = String::from_utf8(bytes).map_err(|_| bad())?;
        let parts: Vec<&str> = text.split('\0').collect();
        let [version, folder, validity, last] = parts[..] else {
            return Err(bad());
        };
        if version != "c1" || folder.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            folder: folder.to_owned(),
            uid_validity: validity.parse().map_err(|_| bad())?,
            last_uid: last.parse().map_err(|_| bad())?,
        })
    }

    /// Validates against the live folder; a UIDVALIDITY change makes the cursor stale.
    pub fn check(&self, folder: &str, uid_validity: u32) -> Result<()> {
        if self.folder != folder {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "cursor belongs to a different folder",
            ));
        }
        if self.uid_validity != uid_validity {
            return Err(Error::new(
                ErrorCode::StaleReference,
                "mailbox changed since this cursor was issued; restart the listing",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_checks() {
        let c = Cursor {
            folder: "INBOX/é".into(),
            uid_validity: 9,
            last_uid: 120,
        };
        assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);
        assert!(c.check("INBOX/é", 9).is_ok());
        assert_eq!(
            c.check("INBOX/é", 10).unwrap_err().code(),
            ErrorCode::StaleReference
        );
        assert_eq!(
            c.check("Other", 9).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn garbage_rejected() {
        assert_eq!(
            Cursor::decode("%%%").unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let short = URL_SAFE_NO_PAD.encode("c1\0INBOX\x001");
        assert!(Cursor::decode(&short).is_err());
    }
}
