//! `ImapBackend`: the `MailBackend` / `MailOrganizer` implementation.
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use futures::TryStreamExt;
use openmail_core::backend::{MailBackend, MailOrganizer, SecretSource};
use openmail_core::config::{AccountConfig, Limits};
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{
    ConnectionReport, Folder, FolderStatus, Message, MessageSummary, Page, PageRequest,
    SearchQuery, Untrusted,
};
use openmail_core::{Error, ErrorCode, Result};
use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::conn::ImapSession;
use crate::error::{ImapError, ImapResult};
use crate::mime;
use crate::ops::{self, MAX_FETCH_BYTES, quote};
use crate::pool::{Pool, with_session};
use crate::search::{self, Translated};
use crate::thread::{self, ThreadEntry, ThreadRelation};
use crate::{paging, tls, utf7};

/// Rounds of header-link expansion when assembling a thread; threads deeper than this
/// are truncated rather than walking the whole mailbox.
const MAX_THREAD_ROUNDS: usize = 3;
/// Hard cap on messages returned for one thread.
const MAX_THREAD_MESSAGES: usize = 200;
/// Only the most recent References entries seed the search (old ancestors add cost, not recall).
const MAX_THREAD_SEED_IDS: usize = 20;
/// Normalized subjects shorter than this are too generic for heuristic matching.
const MIN_HEURISTIC_SUBJECT_LEN: usize = 4;
const MAX_HEURISTIC_MATCHES: usize = 50;

#[derive(Debug)]
pub struct ImapBackend {
    pool: Pool,
    limits: Limits,
}

fn invalid(m: &str) -> Error {
    Error::new(ErrorCode::InvalidInput, m)
}

fn require_folder(folder: &str) -> Result<()> {
    if folder.trim().is_empty() {
        Err(paging::invalid_folder())
    } else {
        Ok(())
    }
}

impl ImapBackend {
    pub fn new(
        accounts: Vec<AccountConfig>,
        limits: Limits,
        secrets: Arc<dyn SecretSource>,
    ) -> Result<Self> {
        Self::with_extra_roots(accounts, limits, secrets, &[])
    }

    /// Like `new`, additionally trusting `roots` (private CA). Verification stays on.
    pub fn with_extra_roots(
        accounts: Vec<AccountConfig>,
        limits: Limits,
        secrets: Arc<dyn SecretSource>,
        roots: &[CertificateDer<'static>],
    ) -> Result<Self> {
        let connector = tls::connector(roots)?;
        Ok(Self {
            pool: Pool::new(accounts, &limits, secrets, connector),
            limits,
        })
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    fn require_organize(&self, id: &AccountId) -> Result<()> {
        let cfg = self.pool.account(id)?;
        if cfg.read_only || !cfg.permissions.organize {
            return Err(Error::new(
                ErrorCode::ReadOnlyAccount,
                format!("account '{id}' does not permit organizing messages"),
            ));
        }
        Ok(())
    }

    fn role_for(cfg: &AccountConfig, name: &str, attrs: &[String]) -> Option<String> {
        if name.eq_ignore_ascii_case("INBOX") {
            return Some("inbox".into());
        }
        for (attr, role) in [
            ("\\sent", "sent"),
            ("\\drafts", "drafts"),
            ("\\archive", "archive"),
            ("\\trash", "trash"),
            ("\\junk", "junk"),
        ] {
            if attrs.iter().any(|a| a == attr) {
                return Some(role.into());
            }
        }
        let m = &cfg.folders;
        [
            (&m.inbox, "inbox"),
            (&m.sent, "sent"),
            (&m.drafts, "drafts"),
            (&m.archive, "archive"),
            (&m.trash, "trash"),
        ]
        .into_iter()
        .find(|(configured, _)| configured.as_deref() == Some(name))
        .map(|(_, role)| role.to_owned())
    }

    async fn fetch_raw_message(
        s: &mut ImapSession,
        r: &MessageRef,
    ) -> ImapResult<(Vec<u8>, openmail_core::model::Flags, Option<u32>)> {
        let sel = ops::select(s, &r.folder, false).await?;
        if sel.uid_validity != r.uid_validity {
            return Err(ImapError::core(
                ErrorCode::StaleReference,
                "message reference is stale: the folder was reset (UIDVALIDITY changed)",
            ));
        }
        // Size first: partial BODY[]<0.n> fetches are not parsed by every server, and a
        // multi-hundred-MB message must not be pulled into memory.
        let probe: Vec<_> = s
            .uid_fetch(r.uid.to_string(), "(UID FLAGS RFC822.SIZE)")
            .await?
            .try_collect()
            .await?;
        let probe = probe.iter().find(|f| f.uid == Some(r.uid)).ok_or_else(|| {
            ImapError::core(
                ErrorCode::MessageNotFound,
                "message no longer exists in this folder",
            )
        })?;
        if probe.size.is_some_and(|n| n > MAX_FETCH_BYTES) {
            return Err(ImapError::core(
                ErrorCode::LimitExceeded,
                format!("message is larger than the {MAX_FETCH_BYTES}-byte fetch limit"),
            ));
        }
        let fetches: Vec<_> = s
            .uid_fetch(r.uid.to_string(), "(UID FLAGS RFC822.SIZE BODY.PEEK[])")
            .await?
            .try_collect()
            .await?;
        let f = fetches
            .iter()
            .find(|f| f.uid == Some(r.uid))
            .ok_or_else(|| {
                ImapError::core(
                    ErrorCode::MessageNotFound,
                    "message no longer exists in this folder",
                )
            })?;
        let raw = f.body().map(<[u8]>::to_vec).ok_or_else(|| {
            ImapError::core(
                ErrorCode::MessageNotFound,
                "server returned no message body",
            )
        })?;
        Ok((raw, ops::map_flags(f.flags()), f.size))
    }

    /// Thread with relationship labels; `get_thread` returns only the exact members.
    /// Scope is the message's own folder (IMAP cannot search across folders in one command).
    pub async fn thread(&self, r: &MessageRef) -> Result<Vec<ThreadEntry>> {
        let account = &r.account;
        with_session!(self.pool, account, true, |s| {
            let sel = ops::select(s, &r.folder, false).await?;
            if sel.uid_validity != r.uid_validity {
                return Err(ImapError::core(
                    ErrorCode::StaleReference,
                    "message reference is stale: the folder was reset (UIDVALIDITY changed)",
                ));
            }
            let anchor =
                ops::fetch_summaries(s, account, &r.folder, sel.uid_validity, &[r.uid]).await?;
            let anchor = anchor.into_iter().next().ok_or_else(|| {
                ImapError::core(
                    ErrorCode::MessageNotFound,
                    "message no longer exists in this folder",
                )
            })?;

            let mut known: HashMap<u32, (MessageSummary, mime::HeaderInfo)> = HashMap::new();
            let mut ids: BTreeSet<String> = BTreeSet::new();
            let mut searched: BTreeSet<String> = BTreeSet::new();
            let seed = |h: &mime::HeaderInfo, ids: &mut BTreeSet<String>| {
                ids.extend(h.message_id.iter().cloned());
                ids.extend(h.in_reply_to.iter().cloned());
                let skip = h.references.len().saturating_sub(MAX_THREAD_SEED_IDS);
                ids.extend(h.references.iter().skip(skip).cloned());
            };
            seed(&anchor.headers, &mut ids);
            let normalized = thread::normalize_subject(&anchor.headers.subject);
            known.insert(r.uid, (anchor.summary, anchor.headers));

            for _ in 0..MAX_THREAD_ROUNDS {
                let fresh: Vec<String> = ids.difference(&searched).cloned().collect();
                if fresh.is_empty() || known.len() >= MAX_THREAD_MESSAGES {
                    break;
                }
                let mut keys = Vec::new();
                for id in &fresh {
                    let q = quote(id)?;
                    keys.push(format!("HEADER Message-ID {q}"));
                    keys.push(format!("HEADER References {q}"));
                    keys.push(format!("HEADER In-Reply-To {q}"));
                }
                searched.extend(fresh);
                let criteria = thread::or_chain(&keys).unwrap_or_else(|| "ALL".into());
                let found = ops::uid_search(s, &criteria, id_needs_utf8(&keys)).await?;
                let new: Vec<u32> = found
                    .into_iter()
                    .filter(|u| !known.contains_key(u))
                    .take(MAX_THREAD_MESSAGES - known.len())
                    .collect();
                for chunk in new.chunks(50) {
                    for f in
                        ops::fetch_summaries(s, account, &r.folder, sel.uid_validity, chunk).await?
                    {
                        seed(&f.headers, &mut ids);
                        known.insert(f.summary.reference.uid, (f.summary, f.headers));
                    }
                }
            }

            let mut entries: Vec<ThreadEntry> = known
                .iter()
                .map(|(uid, (summary, headers))| ThreadEntry {
                    summary: summary.clone(),
                    relation: if *uid == r.uid {
                        ThreadRelation::Anchor
                    } else {
                        ThreadRelation::Exact
                    },
                    parent_message_id: thread::parent_of(headers),
                })
                .collect();

            if normalized.len() >= MIN_HEURISTIC_SUBJECT_LEN {
                let criteria = format!("SUBJECT {}", quote(&normalized)?);
                let found = ops::uid_search(s, &criteria, !normalized.is_ascii()).await?;
                let new: Vec<u32> = found
                    .into_iter()
                    .filter(|u| !known.contains_key(u))
                    .take(MAX_HEURISTIC_MATCHES)
                    .collect();
                for f in ops::fetch_summaries(s, account, &r.folder, sel.uid_validity, &new).await?
                {
                    if thread::normalize_subject(&f.headers.subject) == normalized {
                        entries.push(ThreadEntry {
                            parent_message_id: thread::parent_of(&f.headers),
                            summary: f.summary,
                            relation: ThreadRelation::Heuristic,
                        });
                    }
                }
            }
            thread::sort_entries(&mut entries);
            Ok(entries)
        })
    }

    async fn store_flag(&self, r: &MessageRef, flag: &str, on: bool) -> Result<()> {
        self.require_organize(&r.account)?;
        let cmd = format!("{}FLAGS ({flag})", if on { '+' } else { '-' });
        with_session!(self.pool, &r.account, true, |s| {
            let sel = ops::select(s, &r.folder, true).await?;
            if sel.uid_validity != r.uid_validity {
                return Err(ImapError::core(
                    ErrorCode::StaleReference,
                    "message reference is stale: the folder was reset (UIDVALIDITY changed)",
                ));
            }
            // Non-silent STORE echoes the message back, which is how a missing UID is detected.
            let updated: Vec<_> = s
                .uid_store(r.uid.to_string(), &cmd)
                .await?
                .try_collect()
                .await?;
            if updated.iter().any(|f| f.uid == Some(r.uid)) {
                Ok(())
            } else {
                Err(ImapError::core(
                    ErrorCode::MessageNotFound,
                    "message no longer exists in this folder",
                ))
            }
        })
    }
}

fn id_needs_utf8(keys: &[String]) -> bool {
    keys.iter().any(|k| !k.is_ascii())
}

impl MailBackend for ImapBackend {
    async fn test_connection(&self, account: &AccountId) -> Result<ConnectionReport> {
        self.pool.account(account)?;
        let outcome = with_session!(self.pool, account, false, |s| {
            let caps = s.capabilities().await?;
            let mut names: Vec<String> = caps
                .iter()
                .map(|c| match c {
                    async_imap::types::Capability::Imap4rev1 => "IMAP4rev1".to_owned(),
                    async_imap::types::Capability::Auth(a) => format!("AUTH={a}"),
                    async_imap::types::Capability::Atom(a) => a.clone(),
                })
                .collect();
            names.sort();
            Ok(names)
        });
        Ok(match outcome {
            Ok(capabilities) => ConnectionReport {
                account: account.clone(),
                imap_ok: true,
                smtp_ok: None,
                capabilities,
                detail: None,
            },
            Err(e) => ConnectionReport {
                account: account.clone(),
                imap_ok: false,
                smtp_ok: None,
                capabilities: Vec::new(),
                detail: Some(e.to_string()),
            },
        })
    }

    async fn list_folders(&self, account: &AccountId) -> Result<Vec<Folder>> {
        let cfg = self.pool.account(account)?.clone();
        with_session!(self.pool, account, true, |s| {
            let special_use = s.capabilities().await?.has_str("SPECIAL-USE");
            let cmd = if special_use {
                "LIST \"\" \"*\" RETURN (SPECIAL-USE)"
            } else {
                "LIST \"\" \"*\""
            };
            let reply = ops::run_raw(s, cmd).await?;
            Ok(reply
                .lists
                .into_iter()
                .map(|l| {
                    let name = utf7::decode(&l.name);
                    let selectable = !l
                        .attributes
                        .iter()
                        .any(|a| a == "\\noselect" || a == "\\nonexistent");
                    Folder {
                        role: Self::role_for(&cfg, &name, &l.attributes),
                        name,
                        delimiter: l.delimiter,
                        selectable,
                    }
                })
                .collect())
        })
    }

    async fn folder_status(&self, account: &AccountId, folder: &str) -> Result<FolderStatus> {
        require_folder(folder)?;
        with_session!(self.pool, account, true, |s| {
            let mb = s
                .status(
                    ops::mailbox_name(folder),
                    "(MESSAGES UNSEEN UIDVALIDITY UIDNEXT)",
                )
                .await
                .map_err(|e| match e {
                    async_imap::error::Error::No(_) => ImapError::core(
                        ErrorCode::FolderNotFound,
                        format!("folder '{folder}' not found or not accessible"),
                    ),
                    other => other.into(),
                })?;
            Ok(FolderStatus {
                name: folder.to_owned(),
                exists: mb.exists,
                unseen: mb.unseen,
                uid_validity: mb.uid_validity.ok_or_else(|| {
                    ImapError::core(ErrorCode::Unsupported, "server did not report UIDVALIDITY")
                })?,
                uid_next: mb.uid_next,
            })
        })
    }

    async fn list_messages(
        &self,
        account: &AccountId,
        folder: &str,
        page: PageRequest,
    ) -> Result<Page<MessageSummary>> {
        require_folder(folder)?;
        let all = Translated {
            criteria: "ALL".into(),
            needs_utf8: false,
            has_attachment: None,
        };
        let max = self.limits.max_page_size;
        with_session!(self.pool, account, true, |s| {
            let sel = ops::select(s, folder, false).await?;
            paging::page(s, account, folder, sel, &all, &page, max).await
        })
    }

    async fn search(
        &self,
        account: &AccountId,
        query: &SearchQuery,
        page: PageRequest,
    ) -> Result<Page<MessageSummary>> {
        let folder = query.folder.clone().unwrap_or_else(|| "INBOX".into());
        require_folder(&folder)?;
        let translated = search::translate(query)?;
        let max = self.limits.max_page_size;
        with_session!(self.pool, account, true, |s| {
            let sel = ops::select(s, &folder, false).await?;
            paging::page(s, account, &folder, sel, &translated, &page, max).await
        })
    }

    async fn get_message(&self, reference: &MessageRef, max_body_bytes: usize) -> Result<Message> {
        let (raw, flags, size) = with_session!(self.pool, &reference.account, true, |s| {
            Self::fetch_raw_message(s, reference).await
        })?;
        let parsed = mime::parse_message(&raw, max_body_bytes);
        let body = parsed.body;
        let h = parsed.headers;
        let summary = MessageSummary {
            reference: reference.clone(),
            message_id: h.message_id,
            subject: Untrusted(h.subject),
            from: h.from,
            to: h.to,
            date: h.date,
            flags,
            has_attachments: parsed.attachments.iter().any(|a| !a.inline),
            size,
        };
        Ok(Message {
            summary,
            cc: h.cc,
            in_reply_to: h.in_reply_to.into_iter().next(),
            references: h.references,
            body,
            attachments: parsed.attachments,
        })
    }

    async fn get_thread(&self, reference: &MessageRef) -> Result<Vec<MessageSummary>> {
        Ok(self
            .thread(reference)
            .await?
            .into_iter()
            .filter(|e| e.relation != ThreadRelation::Heuristic)
            .map(|e| e.summary)
            .collect())
    }
}

impl MailOrganizer for ImapBackend {
    async fn set_seen(&self, reference: &MessageRef, seen: bool) -> Result<()> {
        self.store_flag(reference, "\\Seen", seen).await
    }

    async fn set_flagged(&self, reference: &MessageRef, flagged: bool) -> Result<()> {
        self.store_flag(reference, "\\Flagged", flagged).await
    }

    async fn move_message(&self, reference: &MessageRef, dest_folder: &str) -> Result<MessageRef> {
        self.require_organize(&reference.account)?;
        require_folder(dest_folder)?;
        if dest_folder == reference.folder
            || (dest_folder.eq_ignore_ascii_case("INBOX")
                && reference.folder.eq_ignore_ascii_case("INBOX"))
        {
            return Err(invalid(
                "destination folder is the same as the source folder",
            ));
        }
        let dest = quote(&ops::mailbox_name(dest_folder))?;
        // Not retried: a replayed MOVE after a lost reply could act on a different message state.
        let copy = with_session!(self.pool, &reference.account, false, |s| {
            let sel = ops::select(s, &reference.folder, true).await?;
            if sel.uid_validity != reference.uid_validity {
                return Err(ImapError::core(
                    ErrorCode::StaleReference,
                    "message reference is stale: the folder was reset (UIDVALIDITY changed)",
                ));
            }
            let caps = s.capabilities().await?;
            let uid = reference.uid;
            if caps.has_str("MOVE") {
                return Ok(ops::run_raw(s, &format!("UID MOVE {uid} {dest}"))
                    .await?
                    .copy_uid);
            }
            // Fallback: COPY, then flag and expunge only this UID. Plain EXPUNGE would
            // remove unrelated \Deleted mail, so without UIDPLUS we refuse.
            if !caps.has_str("UIDPLUS") {
                return Err(ImapError::core(
                    ErrorCode::Unsupported,
                    "server supports neither MOVE nor UIDPLUS; refusing an unsafe move",
                ));
            }
            let copied = ops::run_raw(s, &format!("UID COPY {uid} {dest}")).await?;
            let _: Vec<_> = s
                .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                .await?
                .try_collect()
                .await?;
            ops::run_raw(s, &format!("UID EXPUNGE {uid}")).await?;
            Ok(copied.copy_uid)
        })?;
        let new_ref = copy.and_then(|c| {
            let idx = c.source.iter().position(|u| *u == reference.uid)?;
            Some(MessageRef {
                account: reference.account.clone(),
                folder: dest_folder.to_owned(),
                uid_validity: c.uid_validity,
                uid: *c.dest.get(idx)?,
            })
        });
        new_ref.ok_or_else(|| Error::new(ErrorCode::Internal, "message was moved but the server did not report its new UID; re-list the destination folder"))
    }
}
