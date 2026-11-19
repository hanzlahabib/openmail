//! Draft tools. They only ever write to the Drafts folder; sending is a separate approved action
//! (`tools_send`). Require `permissions.drafts` on a writable account.
use openmail_core::config::AccountConfig;
use openmail_core::ids::{AccountId, MessageRef};
use openmail_core::model::{Address, DraftInput};
use openmail_core::{Error, ErrorCode};
use openmail_security::Action;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, tool, tool_router};

use crate::backend::FullBackend;
use crate::error::ToolError;
use crate::input::MessageRefInput;
use crate::input_write::{
    AddressInput, CreateDraftInput, PrepareReplyInput, UpdateDraftInput, addresses,
};
use crate::limits::{MAX_DRAFT_BODY_BYTES, MAX_RECIPIENTS, MAX_SUBJECT_CHARS, truncate_utf8};
use crate::output_write::{DraftOut, OkOut, PrepareReplyOut};
use crate::sanitize::strip_invisible;
use crate::server::{OpenMailServer, parse_account, parse_ref};
use crate::untrusted::UntrustedText;

/// RFC 6154 role of the Drafts folder.
const DRAFTS_ROLE: &str = "drafts";
const REPLY_PREFIX: &str = "Re: ";

/// Fields shared by create and update.
struct DraftFields {
    to: Vec<AddressInput>,
    cc: Option<Vec<AddressInput>>,
    bcc: Option<Vec<AddressInput>>,
    subject: String,
    text: Option<String>,
    html: Option<String>,
    in_reply_to: Option<String>,
}

fn invalid_subject(subject: &str) -> bool {
    subject.chars().count() > MAX_SUBJECT_CHARS
        || subject.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
}

fn build_draft(account: &AccountId, f: DraftFields) -> Result<DraftInput, ToolError> {
    if invalid_subject(&f.subject) {
        return Err(ToolError::invalid(
            "subject must be a single line of at most 998 characters",
        ));
    }
    for body in [&f.text, &f.html].into_iter().flatten() {
        if body.len() > MAX_DRAFT_BODY_BYTES {
            return Err(ToolError::invalid("draft body is too large"));
        }
    }
    let in_reply_to = f
        .in_reply_to
        .as_deref()
        .map(parse_ref)
        .transpose()?
        .map(|r| {
            // A reply source on another account would make the backend read mail the caller was
            // never authorized for; same answer as any other forbidden account.
            if &r.account == account {
                Ok(r)
            } else {
                Err(ToolError::from(Error::new(
                    ErrorCode::AccessDenied,
                    "access denied",
                )))
            }
        })
        .transpose()?;
    let (to, cc, bcc) = (addresses(Some(f.to))?, addresses(f.cc)?, addresses(f.bcc)?);
    if to.len() + cc.len() + bcc.len() > MAX_RECIPIENTS {
        return Err(ToolError::invalid("too many recipients"));
    }
    Ok(DraftInput {
        to,
        cc,
        bcc,
        subject: f.subject,
        text: f.text,
        html: f.html,
        in_reply_to,
    })
}

fn reply_subject(subject: &str) -> String {
    let clean = strip_invisible(subject).replace(['\r', '\n', '\0'], " ");
    let clean = clean.trim();
    let has_prefix = clean
        .get(..3)
        .is_some_and(|p| p.eq_ignore_ascii_case("re:"));
    let full = if has_prefix {
        clean.to_owned()
    } else {
        format!("{REPLY_PREFIX}{clean}")
    };
    // Cut by bytes (cheap, char-safe) well inside the character limit.
    truncate_utf8(full, MAX_SUBJECT_CHARS).0
}

#[tool_router(router = draft_router, vis = "pub(crate)")]
impl<B: FullBackend> OpenMailServer<B> {
    #[tool(
        name = "mail_create_draft",
        description = "Save a new draft in the account's Drafts folder. Does NOT send anything. \
                       Requires drafts permission on the account.",
        annotations(
            title = "Create draft",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_create_draft(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<CreateDraftInput>,
    ) -> Result<Json<DraftOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let id = parse_account(&input.account)?;
        let actions: &[Action] = if input.in_reply_to.is_some() {
            &[Action::Draft, Action::Read]
        } else {
            &[Action::Draft]
        };
        let cfg = self.authorized_all(&p, &id, actions)?;
        let draft = build_draft(
            &id,
            DraftFields {
                to: input.to,
                cc: input.cc,
                bcc: input.bcc,
                subject: input.subject,
                text: input.text,
                html: input.html,
                in_reply_to: input.in_reply_to,
            },
        )?;
        let r = self.run(cfg, self.backend.create_draft(&id, draft)).await?;
        Ok(Json(DraftOut {
            ok: true,
            message_ref: r.encode(),
        }))
    }

    #[tool(
        name = "mail_update_draft",
        description = "Replace the content of an existing draft. Drafts are replaced, not edited in place, \
                       so the result carries the NEW message_ref. Only messages in the Drafts folder can be \
                       updated. Requires drafts permission.",
        annotations(
            title = "Update draft",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_update_draft(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<UpdateDraftInput>,
    ) -> Result<Json<DraftOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let actions: &[Action] = if input.in_reply_to.is_some() {
            &[Action::Draft, Action::Read]
        } else {
            &[Action::Draft]
        };
        let cfg = self.authorized_all(&p, &r.account, actions)?;
        let draft = build_draft(
            &r.account,
            DraftFields {
                to: input.to,
                cc: input.cc,
                bcc: input.bcc,
                subject: input.subject,
                text: input.text,
                html: input.html,
                in_reply_to: input.in_reply_to,
            },
        )?;
        self.ensure_in_drafts(cfg, &r).await?;
        let new_ref = self.run(cfg, self.backend.update_draft(&r, draft)).await?;
        Ok(Json(DraftOut {
            ok: true,
            message_ref: new_ref.encode(),
        }))
    }

    #[tool(
        name = "mail_delete_draft",
        description = "Delete a draft from the Drafts folder. Refuses any message outside the Drafts folder; \
                       OpenMail has no tool that deletes received mail. Requires drafts permission.",
        annotations(
            title = "Delete draft",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_delete_draft(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<MessageRefInput>,
    ) -> Result<Json<OkOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_ref(&p, &r, Action::Draft)?;
        self.ensure_in_drafts(cfg, &r).await?;
        self.run(cfg, self.backend.delete_draft(&r)).await?;
        Ok(Json(OkOut { ok: true }))
    }

    #[tool(
        name = "mail_prepare_reply",
        description = "Create a reply draft for a message: recipients, subject and threading come from the \
                       source message's headers; the body is exactly the `text` you pass. Nothing is copied \
                       from the email body, and nothing is sent. Requires read and drafts permission.",
        annotations(
            title = "Prepare reply",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_prepare_reply(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<PrepareReplyInput>,
    ) -> Result<Json<PrepareReplyOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_all(&p, &r.account, &[Action::Read, Action::Draft])?;
        if input.text.len() > MAX_DRAFT_BODY_BYTES {
            return Err(ToolError::invalid("reply text is too large"));
        }
        // Headers only (max_body 0): the body is never needed, so it cannot influence the reply.
        let source = self.run(cfg, self.backend.get_message(&r, 0)).await?;
        let to = reply_recipients(
            &source.summary.from,
            &source.summary.to,
            &source.cc,
            &cfg.email,
            input.reply_all.unwrap_or(false),
        );
        if to.is_empty() {
            return Err(ToolError::invalid(
                "the source message has no usable sender to reply to",
            ));
        }
        let subject = reply_subject(&source.summary.subject.0);
        let draft = DraftInput {
            to: to.clone(),
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: subject.clone(),
            text: Some(input.text),
            html: None,
            in_reply_to: Some(r.clone()),
        };
        let new_ref = self
            .run(cfg, self.backend.create_draft(&r.account, draft))
            .await?;
        Ok(Json(PrepareReplyOut {
            ok: true,
            message_ref: new_ref.encode(),
            to: to
                .into_iter()
                .map(|a| UntrustedText::from(a.email))
                .collect(),
            subject: UntrustedText::from(subject),
        }))
    }
}

/// Sender (or everyone, minus the account's own address, for reply-all), de-duplicated.
fn reply_recipients(
    from: &[Address],
    to: &[Address],
    cc: &[Address],
    own: &str,
    reply_all: bool,
) -> Vec<Address> {
    let mut out: Vec<Address> = Vec::new();
    let candidates: Vec<&Address> = if reply_all {
        from.iter().chain(to).chain(cc).collect()
    } else {
        from.iter().collect()
    };
    for a in candidates {
        let dup = out.iter().any(|o| o.email.eq_ignore_ascii_case(&a.email));
        if !dup && (!reply_all || !a.email.eq_ignore_ascii_case(own)) {
            out.push(a.clone());
        }
    }
    out
}

impl<B: FullBackend> OpenMailServer<B> {
    /// Draft tools must not become a general-purpose message mutator: the reference has to point
    /// into the account's Drafts folder (configured name, else the server's `\Drafts` role).
    pub(crate) async fn ensure_in_drafts(
        &self,
        cfg: &AccountConfig,
        r: &MessageRef,
    ) -> Result<(), ToolError> {
        let drafts = match &cfg.folders.drafts {
            Some(name) => Some(name.clone()),
            None => self
                .run(cfg, self.backend.list_folders(&r.account))
                .await?
                .into_iter()
                .find(|f| {
                    f.role
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(DRAFTS_ROLE))
                })
                .map(|f| f.name),
        };
        if drafts.as_deref() == Some(r.folder.as_str()) {
            Ok(())
        } else {
            Err(ToolError::invalid("message_ref is not a draft"))
        }
    }
}
