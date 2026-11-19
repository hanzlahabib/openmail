//! Write-side features beyond flags/moves: drafts (APPEND with `\Draft`), the Sent
//! copy, and single-part attachment download. All run through the bounded pool;
//! non-idempotent commands are never retried on a fresh connection.
use futures::TryStreamExt;
use openmail_core::backend::{AttachmentSource, MailBackend, MailDrafts, SentFolder};
use openmail_core::config::AccountConfig;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{Address, AttachmentData, DraftInput, Folder};
use openmail_core::{Error, ErrorCode, Result};
use openmail_smtp::builder::{build_message, generate_message_id};
use openmail_smtp::request::{SendRequest, SmtpLimits};

use crate::attach::{self, Encoding};
use crate::backend::ImapBackend;
use crate::conn::ImapSession;
use crate::error::{ImapError, ImapResult};
use crate::mime::HeaderInfo;
use crate::ops::{self, MAX_FETCH_BYTES, quote};
use crate::pool::with_session;

/// Only the newest ancestors are kept in References; long chains add size, not value.
const MAX_REFERENCES: usize = 20;
/// Slack on the encoded-size pre-check: base64 adds ~37% (line breaks included), so a
/// part whose encoded size exceeds `cap * 3 / 2` cannot decode to `cap` bytes or fewer.
const BASE64_ENCODED_SLACK_BYTES: usize = 4096;
/// Idempotency key placeholder: drafts are never sent through the outbox.
const DRAFT_KEY: &str = "draft";

fn stale() -> ImapError {
    ImapError::core(
        ErrorCode::StaleReference,
        "message reference is stale: the folder was reset (UIDVALIDITY changed)",
    )
}

fn not_found() -> ImapError {
    ImapError::core(
        ErrorCode::MessageNotFound,
        "message no longer exists in this folder",
    )
}

/// Folder name for an RFC 6154 role among already-listed folders.
pub fn pick_role(folders: &[Folder], role: &str) -> Option<String> {
    folders
        .iter()
        .find(|f| f.selectable && f.role.as_deref() == Some(role))
        .map(|f| f.name.clone())
}

fn wrap_id(id: &str) -> Option<String> {
    let id = id.trim().trim_start_matches('<').trim_end_matches('>');
    let ok = id.contains('@')
        && !id
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>');
    ok.then(|| format!("<{id}>"))
}

/// In-Reply-To / References derived from the replied-to message's headers.
fn threading(parent: &HeaderInfo) -> (Option<String>, Vec<String>) {
    let parent_id = parent.message_id.as_deref().and_then(wrap_id);
    let mut refs: Vec<String> = parent
        .references
        .iter()
        .filter_map(|r| wrap_id(r))
        .collect();
    if let Some(id) = &parent_id
        && !refs.contains(id)
    {
        refs.push(id.clone());
    }
    let skip = refs.len().saturating_sub(MAX_REFERENCES);
    (parent_id, refs.split_off(skip))
}

/// RFC 5322 bytes for a draft. Header injection is impossible by construction: the
/// request is validated (no CR/LF/NUL in any header-bound field) and lettre encodes
/// the rest. Bcc is kept as a header here (drafts are stored, not sent) so editing
/// the draft later does not silently drop recipients.
fn build_draft(
    cfg: &AccountConfig,
    draft: &DraftInput,
    parent: Option<&HeaderInfo>,
    message_id: &str,
) -> Result<Vec<u8>> {
    let (in_reply_to, references) = parent.map(threading).unwrap_or_default();
    let request = SendRequest {
        idempotency_key: DRAFT_KEY.into(),
        from: Address {
            name: Some(cfg.display_name.clone()).filter(|n| !n.is_empty()),
            email: cfg.email.clone(),
        },
        to: draft.to.clone(),
        cc: draft.cc.clone(),
        bcc: draft.bcc.clone(),
        subject: draft.subject.clone(),
        text: match (&draft.text, &draft.html) {
            (None, None) => Some(String::new()),
            (t, _) => t.clone(),
        },
        html: draft.html.clone(),
        attachments: Vec::new(),
        in_reply_to,
        references,
    };
    request.validate(&SmtpLimits::default())?;
    let built = build_message(&request, message_id)?;
    if draft.bcc.is_empty() {
        return Ok(built.raw);
    }
    let bcc: Vec<&str> = draft.bcc.iter().map(|a| a.email.as_str()).collect();
    let mut raw = format!("Bcc: {}\r\n", bcc.join(", ")).into_bytes();
    raw.extend_from_slice(&built.raw);
    Ok(raw)
}

/// APPEND, then find the new UID by the Message-ID we generated (servers without
/// UIDPLUS give no APPENDUID, and async-imap discards it anyway).
async fn append_and_locate(
    s: &mut ImapSession,
    account: &AccountId,
    folder: &str,
    flags: &str,
    raw: &[u8],
    message_id: &str,
) -> ImapResult<MessageRef> {
    s.append(ops::mailbox_name(folder), Some(flags), None, raw)
        .await?;
    let sel = ops::select(s, folder, true).await?;
    let found = ops::uid_search(
        s,
        &format!("HEADER Message-ID {}", quote(message_id)?),
        false,
    )
    .await?;
    let uid = found.first().copied().ok_or_else(|| {
        ImapError::core(
            ErrorCode::Internal,
            "draft was stored but could not be located; re-list the Drafts folder",
        )
    })?;
    Ok(MessageRef {
        account: account.clone(),
        folder: folder.to_owned(),
        uid_validity: sel.uid_validity,
        uid,
    })
}

/// Flags the single UID `\Deleted` and expunges only it (UID EXPUNGE); other
/// `\Deleted` mail in the folder is never touched.
async fn remove_uid(s: &mut ImapSession, uid: u32) -> ImapResult<()> {
    let _: Vec<_> = s
        .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
        .await?
        .try_collect()
        .await?;
    ops::run_raw(s, &format!("UID EXPUNGE {uid}")).await?;
    Ok(())
}

/// Selects the draft's folder and proves the target is a real draft in it.
async fn open_existing_draft(s: &mut ImapSession, r: &MessageRef) -> ImapResult<()> {
    let sel = ops::select(s, &r.folder, true).await?;
    if sel.uid_validity != r.uid_validity {
        return Err(stale());
    }
    if !s.capabilities().await?.has_str("UIDPLUS") {
        return Err(ImapError::core(
            ErrorCode::Unsupported,
            "server lacks UIDPLUS; refusing an unsafe expunge of draft mail",
        ));
    }
    let fetched: Vec<_> = s
        .uid_fetch(r.uid.to_string(), "(UID FLAGS)")
        .await?
        .try_collect()
        .await?;
    let f = fetched
        .iter()
        .find(|f| f.uid == Some(r.uid))
        .ok_or_else(not_found)?;
    if !ops::map_flags(f.flags()).draft {
        return Err(ImapError::core(
            ErrorCode::InvalidInput,
            "message is not a draft (missing \\Draft flag); refusing to modify it",
        ));
    }
    Ok(())
}

async fn parent_headers(s: &mut ImapSession, r: &MessageRef) -> ImapResult<HeaderInfo> {
    let sel = ops::select(s, &r.folder, false).await?;
    if sel.uid_validity != r.uid_validity {
        return Err(stale());
    }
    let fetched =
        ops::fetch_summaries(s, &r.account, &r.folder, sel.uid_validity, &[r.uid]).await?;
    fetched
        .into_iter()
        .next()
        .map(|f| f.headers)
        .ok_or_else(not_found)
}

impl ImapBackend {
    fn require_drafts(&self, id: &AccountId) -> Result<&AccountConfig> {
        let cfg = self.pool().account(id)?;
        if cfg.read_only || !cfg.permissions.drafts {
            return Err(Error::new(
                ErrorCode::ReadOnlyAccount,
                format!("account '{id}' does not permit drafts"),
            ));
        }
        Ok(cfg)
    }

    /// Configured folder first, then the server's RFC 6154 role, else a clear error.
    async fn special_folder(
        &self,
        account: &AccountId,
        configured: Option<&String>,
        role: &str,
    ) -> Result<String> {
        if let Some(name) = configured.filter(|n| !n.trim().is_empty()) {
            return Ok(name.clone());
        }
        pick_role(&self.list_folders(account).await?, role).ok_or_else(|| {
            Error::new(
                ErrorCode::FolderNotFound,
                format!(
                    "no {role} folder: set folders.{role} in the account config or use a server that advertises \\{} (RFC 6154)",
                    role[..1].to_uppercase() + &role[1..]
                ),
            )
        })
    }

    async fn drafts_folder(&self, cfg: &AccountConfig) -> Result<String> {
        self.special_folder(&cfg.id, cfg.folders.drafts.as_ref(), "drafts")
            .await
    }
}

impl MailDrafts for ImapBackend {
    async fn create_draft(&self, account: &AccountId, draft: DraftInput) -> Result<MessageRef> {
        let cfg = self.require_drafts(account)?.clone();
        let folder = self.drafts_folder(&cfg).await?;
        let message_id = generate_message_id(&cfg.email)?;
        let reply_to = draft.in_reply_to.clone();
        if reply_to.as_ref().is_some_and(|r| r.account != *account) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "in_reply_to belongs to a different account",
            ));
        }
        // Not retried: a replayed APPEND after a lost reply would duplicate the draft.
        with_session!(self.pool(), account, false, |s| {
            let parent = match &reply_to {
                Some(r) => Some(parent_headers(s, r).await?),
                None => None,
            };
            let raw = build_draft(&cfg, &draft, parent.as_ref(), &message_id)?;
            append_and_locate(s, account, &folder, "(\\Draft)", &raw, &message_id).await
        })
    }

    async fn update_draft(&self, reference: &MessageRef, draft: DraftInput) -> Result<MessageRef> {
        let cfg = self.require_drafts(&reference.account)?.clone();
        let folder = self.drafts_folder(&cfg).await?;
        if reference.folder != folder {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "reference is not in the account's Drafts folder",
            ));
        }
        let message_id = generate_message_id(&cfg.email)?;
        let reply_to = draft.in_reply_to.clone();
        if reply_to
            .as_ref()
            .is_some_and(|r| r.account != reference.account)
        {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "in_reply_to belongs to a different account",
            ));
        }
        with_session!(self.pool(), &reference.account, false, |s| {
            // Replacement order: validate target, store the new draft, only then remove
            // the old one — a failure in between can duplicate a draft but never lose it.
            open_existing_draft(s, reference).await?;
            let parent = match &reply_to {
                Some(r) => Some(parent_headers(s, r).await?),
                None => None,
            };
            let raw = build_draft(&cfg, &draft, parent.as_ref(), &message_id)?;
            let new_ref = append_and_locate(
                s,
                &reference.account,
                &folder,
                "(\\Draft)",
                &raw,
                &message_id,
            )
            .await?;
            if new_ref.uid_validity != reference.uid_validity {
                return Err(stale());
            }
            remove_uid(s, reference.uid).await?;
            Ok(new_ref)
        })
    }

    async fn delete_draft(&self, reference: &MessageRef) -> Result<()> {
        let cfg = self.require_drafts(&reference.account)?.clone();
        let folder = self.drafts_folder(&cfg).await?;
        if reference.folder != folder {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "reference is not in the account's Drafts folder",
            ));
        }
        with_session!(self.pool(), &reference.account, false, |s| {
            open_existing_draft(s, reference).await?;
            remove_uid(s, reference.uid).await
        })
    }
}

impl SentFolder for ImapBackend {
    async fn append_sent(&self, account: &AccountId, rfc822: Vec<u8>) -> Result<()> {
        let cfg = self.pool().account(account)?.clone();
        if cfg.read_only || !cfg.permissions.send {
            return Err(Error::new(
                ErrorCode::ReadOnlyAccount,
                format!("account '{account}' does not permit sending"),
            ));
        }
        if rfc822.len() > MAX_FETCH_BYTES as usize {
            return Err(Error::new(
                ErrorCode::LimitExceeded,
                "message is too large to store in the Sent folder",
            ));
        }
        let folder = self
            .special_folder(account, cfg.folders.sent.as_ref(), "sent")
            .await?;
        with_session!(self.pool(), account, false, |s| {
            s.append(ops::mailbox_name(&folder), Some("(\\Seen)"), None, &rfc822)
                .await?;
            Ok(())
        })
    }
}

impl AttachmentSource for ImapBackend {
    async fn get_attachment(
        &self,
        reference: &MessageRef,
        index: u32,
        max_bytes: usize,
    ) -> Result<AttachmentData> {
        with_session!(self.pool(), &reference.account, true, |s| {
            let sel = ops::select(s, &reference.folder, false).await?;
            if sel.uid_validity != reference.uid_validity {
                return Err(stale());
            }
            let uid = reference.uid.to_string();
            let probe: Vec<_> = s
                .uid_fetch(&uid, "(UID BODYSTRUCTURE)")
                .await?
                .try_collect()
                .await?;
            let structure = probe
                .iter()
                .find(|f| f.uid == Some(reference.uid))
                .ok_or_else(not_found)?
                .bodystructure()
                .ok_or_else(|| {
                    ImapError::core(ErrorCode::Unsupported, "server returned no BODYSTRUCTURE")
                })?;
            let loc = attach::locate(structure, index).ok_or_else(|| {
                ImapError::core(ErrorCode::MessageNotFound, "attachment index out of range")
            })?;
            let too_big = |what: &str| {
                ImapError::core(
                    ErrorCode::LimitExceeded,
                    format!("attachment exceeds the {max_bytes}-byte limit ({what})"),
                )
            };
            // Refuse before transferring anything when the encoded size already proves it.
            let octets = loc.octets as usize;
            if octets > MAX_FETCH_BYTES as usize {
                return Err(too_big("encoded size"));
            }
            let provably_over = match loc.encoding {
                Encoding::Identity => octets > max_bytes,
                Encoding::Base64 => octets > max_bytes + max_bytes / 2 + BASE64_ENCODED_SLACK_BYTES,
                Encoding::QuotedPrintable => false,
            };
            if provably_over {
                return Err(too_big("encoded size"));
            }
            let section = loc
                .section
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".");
            let path = async_imap::imap_proto::SectionPath::Part(loc.section.clone(), None);
            let fetched: Vec<_> = s
                .uid_fetch(&uid, format!("(UID BODY.PEEK[{section}])"))
                .await?
                .try_collect()
                .await?;
            let raw = fetched
                .iter()
                .find(|f| f.uid == Some(reference.uid))
                .and_then(|f| f.section(&path))
                .ok_or_else(not_found)?;
            let bytes = attach::decode(raw, loc.encoding).ok_or_else(|| {
                ImapError::core(ErrorCode::Internal, "attachment could not be decoded")
            })?;
            if bytes.len() > max_bytes {
                return Err(too_big("decoded size"));
            }
            let mut meta = loc.meta;
            meta.size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            Ok(AttachmentData { meta, bytes })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, role: Option<&str>, selectable: bool) -> Folder {
        Folder {
            name: name.into(),
            delimiter: Some('/'),
            role: role.map(str::to_owned),
            selectable,
        }
    }

    #[test]
    fn role_pick_uses_advertised_special_use() {
        let fs = vec![
            folder("INBOX", Some("inbox"), true),
            folder("[Gmail]/Drafts", Some("drafts"), true),
            folder("Old", Some("drafts"), false),
        ];
        assert_eq!(pick_role(&fs, "drafts").as_deref(), Some("[Gmail]/Drafts"));
        assert_eq!(pick_role(&fs, "sent"), None);
    }

    #[test]
    fn threading_wraps_ids_and_appends_parent() {
        let parent = HeaderInfo {
            message_id: Some("c@x.org".into()),
            references: vec!["a@x.org".into(), "<b@x.org>".into(), "junk".into()],
            ..HeaderInfo::default()
        };
        let (irt, refs) = threading(&parent);
        assert_eq!(irt.as_deref(), Some("<c@x.org>"));
        assert_eq!(refs, vec!["<a@x.org>", "<b@x.org>", "<c@x.org>"]);
    }
}
