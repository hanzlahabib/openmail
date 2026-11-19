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
use crate::input_write::{FlagInput, MoveInput};
use crate::output_write::{MovedOut, OkOut};
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
