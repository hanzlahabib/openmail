//! UID-descending cursor pagination shared by list and search.
use openmail_core::ids::AccountId;
use openmail_core::model::{MessageSummary, Page, PageRequest};
use openmail_core::{Error, ErrorCode};

use crate::conn::ImapSession;
use crate::cursor::Cursor;
use crate::error::ImapResult;
use crate::ops::{self, Selected};
use crate::search::Translated;

/// Candidate UIDs inspected at most per request when a client-side filter is active,
/// so a rare attachment filter cannot make one call scan an entire huge mailbox.
const MAX_FILTER_SCAN: usize = 500;
/// Chunk size for filtered scans: big enough to amortize round trips, small enough to
/// stay well under the scan cap.
const FILTER_CHUNK: usize = 50;

pub async fn page(
    s: &mut ImapSession,
    account: &AccountId,
    folder: &str,
    sel: Selected,
    query: &Translated,
    req: &PageRequest,
    max_page: u32,
) -> ImapResult<Page<MessageSummary>> {
    let limit = req.limit.clamp(1, max_page.max(1)) as usize;
    let mut criteria = query.criteria.clone();
    if let Some(c) = &req.cursor {
        let cursor = Cursor::decode(c)?;
        cursor.check(folder, sel.uid_validity)?;
        if cursor.last_uid <= 1 {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        criteria = format!("UID 1:{} {criteria}", cursor.last_uid - 1);
    }
    let candidates = ops::uid_search(s, &criteria, query.needs_utf8).await?;
    let filter = query.has_attachment;
    let chunk = if filter.is_some() {
        FILTER_CHUNK
    } else {
        limit
    };
    let scan_cap = if filter.is_some() {
        MAX_FILTER_SCAN
    } else {
        limit
    };

    let mut items: Vec<MessageSummary> = Vec::new();
    let mut scanned = 0usize;
    while scanned < candidates.len() && scanned < scan_cap && items.len() < limit {
        let end = (scanned + chunk).min(candidates.len()).min(scan_cap);
        let batch = &candidates[scanned..end];
        scanned = end;
        for f in ops::fetch_summaries(s, account, folder, sel.uid_validity, batch).await? {
            if filter.is_none_or(|want| f.summary.has_attachments == want) {
                items.push(f.summary);
            }
        }
    }
    items.truncate(limit);
    // The cursor is the lowest UID we have fully accounted for.
    let boundary = if items.len() >= limit {
        items.last().map(|m| m.reference.uid)
    } else if scanned < candidates.len() {
        candidates.get(scanned - 1).copied()
    } else {
        None
    };
    let next_cursor = boundary
        .filter(|b| candidates.iter().any(|c| c < b))
        .map(|last_uid| {
            Cursor {
                folder: folder.to_owned(),
                uid_validity: sel.uid_validity,
                last_uid,
            }
            .encode()
        });
    Ok(Page { items, next_cursor })
}

pub fn invalid_folder() -> Error {
    Error::new(ErrorCode::InvalidInput, "folder name must not be empty")
}
