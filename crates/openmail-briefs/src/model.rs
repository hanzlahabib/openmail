//! Brief domain types. Every item points back at a concrete message and says
//! how it was derived, so a reader can always tell fact from guess.
use std::collections::BTreeMap;

use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::Untrusted;
use serde::{Deserialize, Serialize};

/// How a brief item was produced. Ordered from most to least certain-by-construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Read directly from message data (headers, flags).
    Fact,
    /// Deterministic rule of thumb; can be wrong.
    Heuristic,
    /// Model-generated; must be shown as such.
    Ai,
    /// Matched a rule the user wrote.
    UserRule,
}

/// Supporting detail for an item. `excerpt` is mail text and therefore untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Why the item was raised, written by us (e.g. "asks a question", "from VIP rule").
    pub reason: String,
    pub excerpt: Option<Untrusted<String>>,
}

/// One thing in a brief. `source` is mandatory: no item without a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefItem {
    pub source: MessageRef,
    pub title: Untrusted<String>,
    pub evidence: Vec<Evidence>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionItem {
    pub item: BriefItem,
    /// RFC 3339 UTC, when a deadline was detected.
    pub due: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowUp {
    pub item: BriefItem,
    /// RFC 3339 UTC of the sent message still awaiting a reply.
    pub waiting_since: String,
}

/// Outcome of checking one account. Missing data is `NotChecked`/`Failed`,
/// never an empty list that would read as "no activity".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AccountRunStatus {
    Ok,
    Failed { reason: String },
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Brief {
    /// RFC 3339 UTC.
    pub generated_at: String,
    pub window_start: String,
    pub window_end: String,
    pub accounts: BTreeMap<AccountId, AccountRunStatus>,
    pub highlights: Vec<BriefItem>,
    pub actions: Vec<ActionItem>,
    pub follow_ups: Vec<FollowUp>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    pub(crate) fn sample_item(uid: u32) -> BriefItem {
        BriefItem {
            source: MessageRef {
                account: AccountId::new("work").unwrap(),
                folder: "INBOX".into(),
                uid_validity: 9,
                uid,
            },
            title: Untrusted("Invoice due".into()),
            evidence: vec![Evidence {
                reason: "mentions deadline".into(),
                excerpt: None,
            }],
            provenance: Provenance::Heuristic,
        }
    }

    #[test]
    fn status_serializes_tagged() {
        let failed = AccountRunStatus::Failed {
            reason: "auth".into(),
        };
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"status":"failed","reason":"auth"}"#
        );
        assert_eq!(
            serde_json::to_string(&AccountRunStatus::NotChecked).unwrap(),
            r#"{"status":"not_checked"}"#
        );
    }

    #[test]
    fn item_requires_source_on_deserialize() {
        let json = r#"{"title":"x","evidence":[],"provenance":"fact"}"#;
        assert!(serde_json::from_str::<BriefItem>(json).is_err());
        let item = sample_item(1);
        let back: BriefItem = serde_json::from_str(&serde_json::to_string(&item).unwrap()).unwrap();
        assert_eq!(back, item);
        assert_eq!(serde_json::to_value(item.provenance).unwrap(), "heuristic");
    }
}
