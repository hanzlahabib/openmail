//! Thin, typed wrappers over raw IMAP commands. Every folder name taking a `&str`
//! here is the UTF-8 name; modified UTF-7 conversion happens in `mailbox_name`.
use std::ops::RangeInclusive;

use async_imap::imap_proto::{MailboxDatum, NameAttribute, Response, ResponseCode, Status};
use async_imap::imap_proto::rfc4315::UidSetMember;
use async_imap::types::{Fetch, Flag};
use futures::TryStreamExt;
use openmail_core::ErrorCode;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{Flags, MessageSummary, Untrusted};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::conn::ImapSession;
use crate::error::{ImapError, ImapResult};
use crate::mime::{self, HeaderInfo};
use crate::{search, utf7};

/// Largest slice of one message we pull into memory (headers + bodies + attachments).
pub const MAX_FETCH_BYTES: u32 = 32 * 1024 * 1024;
/// Upper bound on UIDs expanded out of a COPYUID range, to bound memory on hostile servers.
const MAX_UID_EXPANSION: usize = 10_000;

/// Wire name: INBOX is case-insensitive, everything else is modified UTF-7.
pub fn mailbox_name(folder: &str) -> String {
    if folder.eq_ignore_ascii_case("INBOX") { "INBOX".into() } else { utf7::encode(folder) }
}

#[derive(Debug, Clone, Copy)]
pub struct Selected {
    pub uid_validity: u32,
}

pub async fn select(s: &mut ImapSession, folder: &str, write: bool) -> ImapResult<Selected> {
    let name = mailbox_name(folder);
    let res = if write { s.select(&name).await } else { s.examine(&name).await };
    let mb = res.map_err(|e| match e {
        async_imap::error::Error::No(_) => ImapError::core(ErrorCode::FolderNotFound, format!("folder '{folder}' not found or not accessible")),
        other => other.into(),
    })?;
    let uid_validity = mb.uid_validity.ok_or_else(|| ImapError::core(ErrorCode::Unsupported, "server did not report UIDVALIDITY"))?;
    Ok(Selected { uid_validity })
}

#[derive(Debug, Default)]
pub struct CopyUid {
    pub uid_validity: u32,
    pub source: Vec<u32>,
    pub dest: Vec<u32>,
}

#[derive(Debug)]
pub struct ListEntry {
    pub name: String,
    pub delimiter: Option<char>,
    pub attributes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RawReply {
    pub lists: Vec<ListEntry>,
    pub copy_uid: Option<CopyUid>,
}

fn expand(set: &[UidSetMember]) -> Vec<u32> {
    let mut out = Vec::new();
    for m in set {
        match m {
            UidSetMember::Uid(u) => out.push(*u),
            UidSetMember::UidRange(r) => {
                let r: &RangeInclusive<u32> = r;
                out.extend(r.clone().take(MAX_UID_EXPANSION.saturating_sub(out.len())));
            }
        }
    }
    out.truncate(MAX_UID_EXPANSION);
    out
}

fn attr_name(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\noinferiors".into(),
        NameAttribute::NoSelect => "\\noselect".into(),
        NameAttribute::Marked => "\\marked".into(),
        NameAttribute::Unmarked => "\\unmarked".into(),
        NameAttribute::All => "\\all".into(),
        NameAttribute::Archive => "\\archive".into(),
        NameAttribute::Drafts => "\\drafts".into(),
        NameAttribute::Flagged => "\\flagged".into(),
        NameAttribute::Junk => "\\junk".into(),
        NameAttribute::Sent => "\\sent".into(),
        NameAttribute::Trash => "\\trash".into(),
        NameAttribute::Extension(e) => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Runs a command and collects the pieces async-imap's typed helpers discard
/// (LIST with RETURN options, COPYUID response codes). NO/BAD become typed errors.
pub async fn run_raw(s: &mut ImapSession, cmd: &str) -> ImapResult<RawReply> {
    let id = s.run_command(cmd).await?;
    let mut reply = RawReply::default();
    loop {
        let Some(resp) = s.read_response().await.map_err(|e| ImapError::Connection(e.to_string()))? else {
            return Err(ImapError::Connection("connection lost".into()));
        };
        match resp.parsed() {
            Response::MailboxData(MailboxDatum::List(l)) => reply.lists.push(ListEntry {
                name: l.name.to_string(),
                delimiter: l.delimiter.as_deref().and_then(|d| d.chars().next()),
                attributes: l.name_attributes.iter().map(attr_name).collect(),
            }),
            Response::Data { outcome, .. } => {
                if let Some(ResponseCode::CopyUid(v, src, dst)) = &outcome.code {
                    reply.copy_uid = Some(CopyUid { uid_validity: *v, source: expand(src), dest: expand(dst) });
                }
            }
            Response::Done { tag, status, outcome } if *tag == id => {
                if let Some(ResponseCode::CopyUid(v, src, dst)) = &outcome.code {
                    reply.copy_uid = Some(CopyUid { uid_validity: *v, source: expand(src), dest: expand(dst) });
                }
                return match status {
                    Status::Ok => Ok(reply),
                    _ if matches!(outcome.code, Some(ResponseCode::TryCreate)) => {
                        Err(ImapError::core(ErrorCode::FolderNotFound, "destination folder does not exist"))
                    }
                    _ => Err(ImapError::Rejected(outcome.information.as_deref().unwrap_or("command failed").chars().filter(|c| !c.is_control()).take(120).collect())),
                };
            }
            _ => {}
        }
    }
}

/// `UID SEARCH`; results sorted newest (highest UID) first.
pub async fn uid_search(s: &mut ImapSession, criteria: &str, utf8: bool) -> ImapResult<Vec<u32>> {
    let q = if utf8 { format!("CHARSET UTF-8 {criteria}") } else { criteria.to_owned() };
    let mut v: Vec<u32> = s.uid_search(q).await?.into_iter().collect();
    v.sort_unstable_by(|a, b| b.cmp(a));
    Ok(v)
}

pub fn uid_set(uids: &[u32]) -> String {
    uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

pub fn map_flags<'a>(flags: impl Iterator<Item = Flag<'a>>) -> Flags {
    let mut out = Flags::default();
    for f in flags {
        match f {
            Flag::Seen => out.seen = true,
            Flag::Flagged => out.flagged = true,
            Flag::Answered => out.answered = true,
            Flag::Draft => out.draft = true,
            Flag::Deleted => out.deleted = true,
            _ => {}
        }
    }
    out
}

fn is_attachment_part(common: &async_imap::imap_proto::BodyContentCommon<'_>, leaf_basic: bool) -> bool {
    let disp = common.disposition.as_ref().map(|d| d.ty.to_ascii_lowercase());
    match disp.as_deref() {
        Some("attachment") => true,
        Some("inline") => false,
        _ => {
            let has_name = |p: &async_imap::imap_proto::BodyParams<'_>| {
                p.as_ref().is_some_and(|v| v.iter().any(|(k, _)| k.eq_ignore_ascii_case("name") || k.eq_ignore_ascii_case("filename")))
            };
            leaf_basic && has_name(&common.ty.params)
        }
    }
}

/// Server-side structure walk: true when any leaf looks like a downloadable attachment.
pub fn structure_has_attachment(bs: &async_imap::imap_proto::BodyStructure<'_>) -> bool {
    use async_imap::imap_proto::BodyStructure as B;
    match bs {
        B::Multipart { bodies, .. } => bodies.iter().any(structure_has_attachment),
        B::Basic { common, .. } => is_attachment_part(common, true),
        B::Text { common, .. } => is_attachment_part(common, false),
        B::Message { common, .. } => is_attachment_part(common, false),
    }
}

pub const SUMMARY_QUERY: &str = "(UID FLAGS RFC822.SIZE INTERNALDATE BODYSTRUCTURE BODY.PEEK[HEADER])";

pub struct FetchedSummary {
    pub summary: MessageSummary,
    pub headers: HeaderInfo,
}

fn internal_date_utc(f: &Fetch) -> Option<String> {
    let ts = f.internal_date()?.timestamp();
    OffsetDateTime::from_unix_timestamp(ts).ok()?.format(&Rfc3339).ok()
}

pub fn summary_from_fetch(f: &Fetch, account: &AccountId, folder: &str, uid_validity: u32) -> Option<FetchedSummary> {
    let uid = f.uid?;
    let headers = f.header().map(mime::parse_headers).unwrap_or_default();
    let summary = MessageSummary {
        reference: MessageRef { account: account.clone(), folder: folder.to_owned(), uid_validity, uid },
        message_id: headers.message_id.clone(),
        subject: Untrusted(headers.subject.clone()),
        from: headers.from.clone(),
        to: headers.to.clone(),
        date: headers.date.clone().or_else(|| internal_date_utc(f)),
        flags: map_flags(f.flags()),
        has_attachments: f.bodystructure().is_some_and(structure_has_attachment),
        size: f.size,
    };
    Some(FetchedSummary { summary, headers })
}

/// Fetches summaries for `uids` and returns them newest first.
pub async fn fetch_summaries(s: &mut ImapSession, account: &AccountId, folder: &str, uid_validity: u32, uids: &[u32]) -> ImapResult<Vec<FetchedSummary>> {
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let fetches: Vec<Fetch> = s.uid_fetch(uid_set(uids), SUMMARY_QUERY).await?.try_collect().await?;
    let mut out: Vec<FetchedSummary> = fetches.iter().filter_map(|f| summary_from_fetch(f, account, folder, uid_validity)).collect();
    out.sort_by(|a, b| b.summary.reference.uid.cmp(&a.summary.reference.uid));
    Ok(out)
}

pub use search::quote;
