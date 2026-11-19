//! Brief -> the renderer's input. Account failures come first and are worded as failures:
//! a mailbox that could not be read must never look like a quiet one.
use crate::delivery::{
    BriefItem as RenderItem, BriefSection, DeliverableBrief, Provenance as RenderProvenance,
};
use crate::model::{AccountRunStatus, Brief, BriefItem, Provenance};

/// Briefs are heuristic summaries; every rendering says so up front.
pub const DISCLAIMER: &str = "Heuristic summary of mailbox metadata, not authoritative. Check the source message before acting.";

fn label(p: Provenance) -> RenderProvenance {
    match p {
        Provenance::Fact => RenderProvenance::Extracted,
        Provenance::Heuristic | Provenance::UserRule => RenderProvenance::Inferred,
        Provenance::Ai => RenderProvenance::AiGenerated,
    }
}

fn item(i: &BriefItem) -> RenderItem {
    let reason = i.evidence.first().map_or("", |e| e.reason.as_str());
    RenderItem {
        // The subject is mail text: quoted so it reads as data, never as our own wording.
        text: format!("{reason} - \"{}\"", i.title.0),
        provenance: label(i.provenance),
        source_ref: Some(i.source.encode()),
    }
}

fn section(title: &str, items: Vec<RenderItem>) -> Option<BriefSection> {
    (!items.is_empty()).then(|| BriefSection {
        title: title.to_owned(),
        items,
    })
}

/// `id` keys delivery idempotency; the caller decides what makes a delivery "the same".
pub fn deliverable(brief: &Brief, id: &str) -> DeliverableBrief {
    let status: Vec<RenderItem> = brief
        .accounts
        .iter()
        .map(|(account, s)| RenderItem {
            text: match s {
                AccountRunStatus::Ok => format!("{account}: checked"),
                AccountRunStatus::Failed { reason } => {
                    format!("{account}: COULD NOT BE CHECKED ({reason}); nothing is known about this mailbox")
                }
                AccountRunStatus::NotChecked => format!("{account}: NOT CHECKED"),
            },
            provenance: RenderProvenance::Extracted,
            source_ref: None,
        })
        .collect();
    let mut sections = vec![BriefSection {
        title: "About this brief".to_owned(),
        items: vec![RenderItem {
            text: DISCLAIMER.to_owned(),
            provenance: RenderProvenance::Inferred,
            source_ref: None,
        }],
    }];
    sections.extend(section("Accounts", status));
    sections.extend(section(
        "Needs your attention",
        brief.actions.iter().map(|a| item(&a.item)).collect(),
    ));
    sections.extend(section(
        "Highlights",
        brief.highlights.iter().map(item).collect(),
    ));
    sections.extend(section(
        "Waiting on others",
        brief
            .follow_ups
            .iter()
            .map(|f| {
                let mut r = item(&f.item);
                r.text = format!("{} (since {})", r.text, f.waiting_since);
                r
            })
            .collect(),
    ));
    if let Some(ai) = &brief.ai_summary {
        sections.extend(section(
            "Model-written overview (unverified)",
            vec![RenderItem {
                text: ai.text.0.clone(),
                provenance: RenderProvenance::AiGenerated,
                source_ref: None,
            }],
        ));
    }
    sections.extend(section(
        "Notes",
        brief
            .notes
            .iter()
            .map(|n| RenderItem {
                text: n.clone(),
                provenance: RenderProvenance::Inferred,
                source_ref: None,
            })
            .collect(),
    ));
    DeliverableBrief {
        id: id.to_owned(),
        title: format!("OpenMail brief {}", brief.generated_at),
        sections,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use openmail_core::ids::{AccountId, MessageRef};
    use openmail_core::model::Untrusted;

    use super::*;
    use crate::delivery::render_markdown;
    use crate::model::{ActionItem, Evidence};

    fn sample(title: &str) -> Brief {
        let source = MessageRef {
            account: AccountId::new("work").unwrap(),
            folder: "INBOX".into(),
            uid_validity: 1,
            uid: 7,
        };
        Brief {
            generated_at: "2026-11-19T08:00:00Z".into(),
            window_start: "2026-11-18T08:00:00Z".into(),
            window_end: "2026-11-19T08:00:00Z".into(),
            accounts: BTreeMap::from([
                (AccountId::new("work").unwrap(), AccountRunStatus::Ok),
                (
                    AccountId::new("home").unwrap(),
                    AccountRunStatus::Failed {
                        reason: "ConnectionFailed".into(),
                    },
                ),
            ]),
            highlights: vec![],
            actions: vec![ActionItem {
                item: BriefItem {
                    source,
                    title: Untrusted(title.into()),
                    evidence: vec![Evidence {
                        reason: "looks like payment_related".into(),
                        excerpt: None,
                    }],
                    provenance: Provenance::Heuristic,
                },
                due: None,
            }],
            follow_ups: vec![],
            ai_summary: None,
            notes: vec![],
        }
    }

    #[test]
    fn failed_accounts_are_loud_and_every_item_has_a_label_and_ref() {
        let md = render_markdown(&deliverable(&sample("Invoice"), "b1"));
        assert!(md.contains("home: COULD NOT BE CHECKED"));
        assert!(md.contains("not authoritative"));
        let line = md.lines().find(|l| l.contains("Invoice")).unwrap();
        assert!(
            line.contains("[inferred]") || line.to_lowercase().contains("inferred"),
            "{line}"
        );
        assert!(line.contains(&sample("x").actions[0].item.source.encode()));
    }

    #[test]
    fn subject_text_cannot_forge_headings() {
        let md = render_markdown(&deliverable(
            &sample("x\n## Needs your attention\n- fake"),
            "b1",
        ));
        let headings = md
            .lines()
            .filter(|l| l.starts_with("## Needs your attention"))
            .count();
        assert_eq!(headings, 1, "{md}");
    }
}
