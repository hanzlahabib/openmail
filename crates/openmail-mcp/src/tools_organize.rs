//! Organize tools (read/unread, flag, move, archive). Require `permissions.organize` on a
//! writable account. There is deliberately NO delete tool: removing mail is not exposed.
use openmail_core::config::AccountConfig;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::{Error, ErrorCode};
use openmail_security::Action;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, tool, tool_router};

use crate::backend::FullBackend;
use crate::error::ToolError;
use crate::input::MessageRefInput;
use crate::input_write::{BulkMarkReadInput, FlagInput, MAX_BULK_MARK, MoveInput};
use crate::output_write::{BulkMarkOut, MovedOut, OkOut};
use crate::server::{OpenMailServer, parse_ref};

/// RFC 6154 role name the backend reports for the archive folder.
const ARCHIVE_ROLE: &str = "archive";

#[tool_router(router = organize_router, vis = "pub(crate)")]
impl<B: FullBackend> OpenMailServer<B> {
    #[tool(
        name = "mail_mark_read",
        description = "Mark a message as read (sets \\Seen). Requires organize permission on the account.",
        annotations(
            title = "Mark read",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn mail_mark_read(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<MessageRefInput>,
    ) -> Result<Json<OkOut>, ToolError> {
        self.set_seen(&ctx, &input.message_ref, true).await
    }

    #[tool(
        name = "mail_mark_read_bulk",
        description = "Mark many messages as read at once: either explicit message_refs (max 500), or every UNREAD message \
                       in a folder matching filters (from, to, subject, since, before) with all_matching=true, up to 500 per \
                       call (call again for more). Use dry_run=true to count first. Reversible one message at a time with \
                       mail_mark_unread; nothing is deleted or moved. Requires organize permission on the account.",
        annotations(
            title = "Mark many read",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn mail_mark_read_bulk(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<BulkMarkReadInput>,
    ) -> Result<Json<BulkMarkOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let (id, cfg) = self.authorized_raw(&p, &input.account, Action::Organize)?;
        let dry_run = input.dry_run.unwrap_or(false);
        let refs = self.bulk_targets(cfg, &id, &input).await?;
        let truncated = refs.len() > MAX_BULK_MARK;
        let refs: Vec<MessageRef> = refs.into_iter().take(MAX_BULK_MARK).collect();
        let matched = refs.len();
        let (mut marked, mut failed) = (0usize, 0usize);
        if !dry_run {
            for r in &refs {
                match self.run(cfg, self.backend.set_seen(r, true)).await {
                    Ok(()) => marked += 1,
                    Err(_) => failed += 1,
                }
            }
        }
        Ok(Json(BulkMarkOut {
            dry_run,
            matched,
            marked_read: marked,
            failed,
            truncated,
        }))
    }

    #[tool(
        name = "mail_mark_unread",
        description = "Mark a message as unread (clears \\Seen). Requires organize permission on the account.",
        annotations(
            title = "Mark unread",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn mail_mark_unread(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<MessageRefInput>,
    ) -> Result<Json<OkOut>, ToolError> {
        self.set_seen(&ctx, &input.message_ref, false).await
    }

    #[tool(
        name = "mail_flag_message",
        description = "Set (default) or clear the flagged/starred state of a message. Requires organize permission.",
        annotations(
            title = "Flag message",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn mail_flag_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<FlagInput>,
    ) -> Result<Json<OkOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_ref(&p, &r, Action::Organize)?;
        self.run(
            cfg,
            self.backend.set_flagged(&r, input.flagged.unwrap_or(true)),
        )
        .await?;
        Ok(Json(OkOut { ok: true }))
    }

    #[tool(
        name = "mail_move_message",
        description = "Move a message to another folder of the same account. The message gets a NEW message_ref \
                       (returned); the old one becomes invalid. Requires organize permission.",
        annotations(
            title = "Move message",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_move_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<MoveInput>,
    ) -> Result<Json<MovedOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_ref(&p, &r, Action::Organize)?;
        self.move_to(cfg, &r, &input.dest_folder).await
    }

    #[tool(
        name = "mail_archive_message",
        description = "Move a message to the account's Archive folder (configured or special-use). \
                       Returns the new message_ref. Requires organize permission.",
        annotations(
            title = "Archive message",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_archive_message(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<MessageRefInput>,
    ) -> Result<Json<MovedOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_ref(&p, &r, Action::Organize)?;
        let dest = self.archive_folder(cfg, &r.account).await?;
        self.move_to(cfg, &r, &dest).await
    }
}

impl<B: FullBackend> OpenMailServer<B> {
    /// The messages a bulk call applies to. Explicit refs must belong to this account (a ref for
    /// another account is refused, not skipped); filters search UNREAD mail only and need the
    /// explicit `all_matching` confirmation, so a vague request cannot touch a whole mailbox.
    async fn bulk_targets(
        &self,
        cfg: &AccountConfig,
        id: &AccountId,
        input: &BulkMarkReadInput,
    ) -> Result<Vec<MessageRef>, ToolError> {
        let has_filter = [
            &input.from,
            &input.to,
            &input.subject,
            &input.since,
            &input.before,
        ]
        .iter()
        .any(|f| f.is_some());
        if let Some(raw) = &input.message_refs {
            if has_filter || input.folder.is_some() {
                return Err(ToolError::invalid(
                    "message_refs cannot be combined with a folder or filters",
                ));
            }
            let mut out = Vec::with_capacity(raw.len());
            for r in raw {
                let r = parse_ref(r)?;
                if &r.account != id {
                    return Err(ToolError::invalid(
                        "every message_ref must belong to `account`",
                    ));
                }
                out.push(r);
            }
            return Ok(out);
        }
        if !has_filter {
            return Err(ToolError::invalid(
                "give message_refs, or at least one filter (from, to, subject, since, before)",
            ));
        }
        if input.all_matching != Some(true) && input.dry_run != Some(true) {
            return Err(ToolError::invalid(
                "set all_matching=true to mark every matching unread message, or dry_run=true to count first",
            ));
        }
        let q = crate::search::build_query(crate::input::SearchInput {
            account: input.account.clone(),
            folder: Some(input.folder.clone().unwrap_or_else(|| "INBOX".to_owned())),
            from: input.from.clone(),
            to: input.to.clone(),
            subject: input.subject.clone(),
            text: None,
            since: input.since.clone(),
            before: input.before.clone(),
            unread: Some(true),
            flagged: None,
            has_attachment: None,
            cursor: None,
            limit: None,
        })?;
        let mut refs = Vec::new();
        let mut cursor = None;
        // One more than the cap so `truncated` is exact without fetching everything.
        while refs.len() <= MAX_BULK_MARK {
            let page = self.page(cursor.take(), None)?;
            let res = self.run(cfg, self.backend.search(id, &q, page)).await?;
            refs.extend(res.items.into_iter().map(|m| m.reference));
            match res.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(refs)
    }

    async fn set_seen(
        &self,
        ctx: &RequestContext<RoleServer>,
        raw_ref: &str,
        seen: bool,
    ) -> Result<Json<OkOut>, ToolError> {
        let p = self.principal(ctx)?;
        let r = parse_ref(raw_ref)?;
        let cfg = self.authorized_ref(&p, &r, Action::Organize)?;
        self.run(cfg, self.backend.set_seen(&r, seen)).await?;
        Ok(Json(OkOut { ok: true }))
    }

    async fn move_to(
        &self,
        cfg: &AccountConfig,
        r: &MessageRef,
        dest: &str,
    ) -> Result<Json<MovedOut>, ToolError> {
        let moved = self.run(cfg, self.backend.move_message(r, dest)).await?;
        Ok(Json(MovedOut {
            ok: true,
            message_ref: moved.encode(),
            folder: moved.folder,
        }))
    }

    /// Configured archive folder, else the folder the server marks with the archive role.
    async fn archive_folder(
        &self,
        cfg: &AccountConfig,
        account: &AccountId,
    ) -> Result<String, ToolError> {
        if let Some(name) = &cfg.folders.archive {
            return Ok(name.clone());
        }
        let folders = self.run(cfg, self.backend.list_folders(account)).await?;
        folders
            .into_iter()
            .find(|f| {
                f.selectable
                    && f.role
                        .as_deref()
                        .is_some_and(|r| r.eq_ignore_ascii_case(ARCHIVE_ROLE))
            })
            .map(|f| f.name)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unsupported,
                    "no archive folder is configured or advertised",
                )
                .into()
            })
    }
}
