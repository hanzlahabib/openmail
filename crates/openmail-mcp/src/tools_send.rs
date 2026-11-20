//! Approved sending. Nothing here can send without an approval id that the account owner granted
//! out of band; the approval is bound to the exact message (recipients, subject, content,
//! attachments) and consumed atomically, so a replayed id or an id for a different message fails.
//! Message text is never consulted as permission.
use std::sync::Mutex;

use openmail_core::config::AccountConfig;
use openmail_core::ids::MessageRef;
use openmail_core::model::{Address, AttachmentMeta, Message};
use openmail_core::{Error, ErrorCode};
use openmail_security::{Action, Principal};
use openmail_smtp::builder::build_message;
use openmail_smtp::{
    ApprovalConsumer, ApprovalProof, Attachment, SendOutcome, SendRequest, SendRequestDescriptor,
};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, tool, tool_router};
use sha2::{Digest, Sha256};

use crate::backend::FullBackend;
use crate::error::ToolError;
use crate::input_write::{ForwardApprovedInput, SendApprovedInput, addresses};
use crate::limits::truncate_utf8;
use crate::limits::{
    MAX_ATTACHMENT_BYTES, MAX_DRAFT_BODY_BYTES, MAX_RECIPIENTS, MAX_SUBJECT_CHARS,
};
use crate::outgoing::{Outgoing, not_configured};
use crate::output_write::SendOut;
use crate::sanitize::{safe_content_type, sanitize_filename, strip_invisible};
use crate::server::{OpenMailServer, parse_ref};

/// Prefix of idempotency keys derived by this server.
const KEY_PREFIX: &str = "om-";
/// Hex characters of the key digest kept: 128 bits, ample for per-message uniqueness.
const KEY_HEX_CHARS: usize = 32;
const FORWARD_PREFIX: &str = "Fwd: ";
const FORWARD_BANNER: &str = "---------- Forwarded message ----------";

const UNCERTAIN_HINT: &str = "Delivery state is UNCERTAIN: the mail server may or may not have accepted the message. \
Do NOT retry or send again. Ask the account owner to check the Sent folder and record the outcome \
(openmail-smtp RECOVERY.md, resolve_uncertain) using the idempotency_key in this error.";

/// Runs the real approval check and, when it fails for lack of a valid approval, files a pending
/// request for the very descriptor that was checked (the only place that descriptor exists).
struct Recorder<'a> {
    outgoing: &'a dyn Outgoing,
    pending: Mutex<Option<String>>,
}

impl ApprovalConsumer for Recorder<'_> {
    fn consume(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
        token: Option<&str>,
    ) -> openmail_core::Result<()> {
        let result = self
            .outgoing
            .consumer()
            .consume(principal, descriptor, token);
        if let Err(Error::Coded { code, .. }) = &result
            && matches!(
                code,
                ErrorCode::SendNotApproved | ErrorCode::ApprovalInvalid
            )
        {
            match self.outgoing.request_approval(principal, descriptor) {
                Ok(id) => {
                    if let Ok(mut slot) = self.pending.lock() {
                        *slot = Some(id);
                    }
                }
                // The owner can still approve by other means; the agent just gets no request id.
                Err(e) => tracing::warn!(error = %e, "could not file a pending approval request"),
            }
        }
        result
    }
}

fn single_line(s: &str) -> String {
    strip_invisible(s)
        .replace(['\r', '\n', '\0'], " ")
        .trim()
        .to_owned()
}

fn idempotency_key(request: &SendRequest, source: &MessageRef) -> String {
    let mut h = Sha256::new();
    h.update(source.account.as_str().as_bytes());
    h.update([0]);
    h.update(source.encode().as_bytes());
    h.update([0]);
    h.update(request.content_hash().as_bytes());
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    format!("{KEY_PREFIX}{}", &hex[..KEY_HEX_CHARS])
}

fn render_address(a: &Address) -> String {
    match &a.name {
        Some(n) => format!("{} <{}>", single_line(n), single_line(&a.email)),
        None => single_line(&a.email),
    }
}

#[tool_router(router = send_router, vis = "pub(crate)")]
impl<B: FullBackend> OpenMailServer<B> {
    #[tool(
        name = "mail_send_approved",
        description = "Send an email from one of your accounts. Two modes: (1) message_ref of a saved draft; or \
                       (2) compose and send: account, to (and optional cc), subject and text/html. Sending \
                       needs explicit consent: in mode 2 show the user the recipients, subject and body, and \
                       only after they say yes call again with user_confirmed=true (a first call without it \
                       sends nothing and returns a preview). On top of that the server owner's approval policy \
                       applies: with owner approval an approval_id granted out of band is required (without a \
                       valid id nothing is sent and the error carries a request_id the owner can approve; each \
                       approval works once); under standing rules or delegated mode the server may approve \
                       within its limits (daily cap per account). You can never create an approval yourself. \
                       Requires send permission on the account.",
        annotations(
            title = "Send email (with approval)",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_send_approved(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<SendApprovedInput>,
    ) -> Result<Json<SendOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let compose = input.account.is_some()
            || input.to.is_some()
            || input.cc.is_some()
            || input.subject.is_some()
            || input.text.is_some()
            || input.html.is_some();
        match (&input.message_ref, compose) {
            (Some(_), true) => Err(ToolError::invalid(
                "use either message_ref (send a draft) or account/to/subject/body (compose), not both",
            )),
            (None, false) => Err(ToolError::invalid(
                "give message_ref of a draft, or account, to, subject and a body",
            )),
            (Some(raw), false) => self.send_draft(&p, raw, input.approval_id.as_deref()).await,
            (None, true) => self.send_composed(&p, input).await,
        }
    }

    #[tool(
        name = "mail_forward_approved",
        description = "Forward a message to new recipients with an optional note of your own. Requires an \
                       approval_id that the account OWNER granted out of band for exactly this forward; you \
                       cannot create one. Without a valid id nothing is sent and the error carries a \
                       request_id the owner can approve. Each approval works once. Requires read and send permission.",
        annotations(
            title = "Forward approved message",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn mail_forward_approved(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(input): Parameters<ForwardApprovedInput>,
    ) -> Result<Json<SendOut>, ToolError> {
        let p = self.principal(&ctx)?;
        let r = parse_ref(&input.message_ref)?;
        let cfg = self.authorized_all(&p, &r.account, &[Action::Read, Action::Send])?;
        self.ready_to_send(cfg)?;
        let to = addresses(Some(input.to))?;
        let cc = addresses(input.cc)?;
        if to.is_empty() || to.len() + cc.len() > MAX_RECIPIENTS {
            return Err(ToolError::invalid("recipient count out of range"));
        }
        let note = input.note.unwrap_or_default();
        if note.len() > MAX_DRAFT_BODY_BYTES {
            return Err(ToolError::invalid("note is too large"));
        }
        let msg = self.load_source(cfg, &r).await?;
        let attachments = self.collect_attachments(cfg, &r, &msg.attachments).await?;
        let subject = forward_subject(&msg.summary.subject.0);
        let text = forward_text(&note, &msg);
        let request = SendRequest {
            idempotency_key: String::new(),
            from: own_address(cfg),
            to,
            cc,
            bcc: Vec::new(),
            subject,
            text: Some(text),
            html: None,
            attachments,
            in_reply_to: None,
            references: Vec::new(),
        };
        self.deliver(&p, cfg, &r, request, input.approval_id.as_deref())
            .await
    }
}

fn own_address(cfg: &AccountConfig) -> Address {
    Address {
        name: Some(single_line(&cfg.display_name)).filter(|n| !n.is_empty()),
        email: cfg.email.clone(),
    }
}

fn forward_subject(subject: &str) -> String {
    let s = single_line(subject);
    let full = if s.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("fwd:")) {
        s
    } else {
        format!("{FORWARD_PREFIX}{s}")
    };
    truncate_utf8(full, MAX_SUBJECT_CHARS).0
}

fn forward_text(note: &str, m: &Message) -> String {
    let s = &m.summary;
    let from = s
        .from
        .iter()
        .map(render_address)
        .collect::<Vec<_>>()
        .join(", ");
    let to =
        s.to.iter()
            .map(render_address)
            .collect::<Vec<_>>()
            .join(", ");
    let body = m.body.text.as_ref().map_or("", |t| t.0.as_str());
    let date = s.date.as_deref().map(single_line).unwrap_or_default();
    format!(
        "{note}\n\n{FORWARD_BANNER}\nFrom: {from}\nDate: {date}\nSubject: {}\nTo: {to}\n\n{body}\n",
        single_line(&s.subject.0)
    )
}

impl<B: FullBackend> OpenMailServer<B> {
    /// Mode 1: send a draft the account already holds.
    async fn send_draft(
        &self,
        p: &Principal,
        raw_ref: &str,
        approval: Option<&str>,
    ) -> Result<Json<SendOut>, ToolError> {
        let r = parse_ref(raw_ref)?;
        let cfg = self.authorized_all(p, &r.account, &[Action::Read, Action::Send])?;
        self.ready_to_send(cfg)?;
        self.ensure_in_drafts(cfg, &r).await?;
        let msg = self.load_source(cfg, &r).await?;
        let attachments = self.collect_attachments(cfg, &r, &msg.attachments).await?;
        let request = SendRequest {
            idempotency_key: String::new(),
            from: own_address(cfg),
            to: msg.summary.to.clone(),
            cc: msg.cc.clone(),
            // The Message contract carries no Bcc, so a draft's Bcc is not sent (documented gap).
            bcc: Vec::new(),
            subject: single_line(&msg.summary.subject.0),
            text: msg.body.text.map(|t| t.0),
            html: msg.body.html_sanitized.map(|h| h.0),
            attachments,
            in_reply_to: msg.in_reply_to,
            references: msg.references,
        };
        self.deliver(p, cfg, &r, request, approval).await
    }

    /// Mode 2: compose in one call. The model's own wording is what gets sent, so the human must
    /// have seen it: without `user_confirmed=true` this returns a preview and sends nothing.
    async fn send_composed(
        &self,
        p: &Principal,
        input: SendApprovedInput,
    ) -> Result<Json<SendOut>, ToolError> {
        let raw_account = input
            .account
            .as_deref()
            .ok_or_else(|| ToolError::invalid("account is required to compose a message"))?;
        let (id, cfg) = self.authorized_raw(p, raw_account, Action::Send)?;
        self.ready_to_send(cfg)?;
        let to = addresses(input.to)?;
        let cc = addresses(input.cc)?;
        if to.is_empty() || to.len() + cc.len() > MAX_RECIPIENTS {
            return Err(ToolError::invalid("1 to 100 recipients are required"));
        }
        let subject = single_line(
            input
                .subject
                .as_deref()
                .ok_or_else(|| ToolError::invalid("subject is required"))?,
        );
        if subject.is_empty() || subject.chars().count() > MAX_SUBJECT_CHARS {
            return Err(ToolError::invalid("subject must be 1 to 998 characters"));
        }
        if input.text.is_none() && input.html.is_none() {
            return Err(ToolError::invalid("a text or html body is required"));
        }
        let body_len =
            input.text.as_deref().map_or(0, str::len) + input.html.as_deref().map_or(0, str::len);
        if body_len > MAX_DRAFT_BODY_BYTES {
            return Err(ToolError::invalid("the body is too large"));
        }
        if input.user_confirmed != Some(true) {
            let preview = serde_json::json!({
                "account": id.as_str(),
                "from": cfg.email,
                "to": to.iter().map(render_address).collect::<Vec<_>>(),
                "cc": cc.iter().map(render_address).collect::<Vec<_>>(),
                "subject": subject,
                "body_chars": input.text.as_deref().or(input.html.as_deref()).map_or(0, |b| b.chars().count()),
            });
            return Err(ToolError::new(
                ErrorCode::SendNotApproved,
                "nothing was sent: show the user the recipients, subject and body, and call again with user_confirmed=true only after they explicitly agree",
            )
            .with_detail("needs_user_confirmation", true)
            .with_detail("preview", preview));
        }
        let request = SendRequest {
            idempotency_key: String::new(),
            from: own_address(cfg),
            to,
            cc,
            bcc: Vec::new(),
            subject,
            text: input.text,
            html: input.html,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
        };
        // No source message: the idempotency key then covers account + exact content only.
        let source = MessageRef {
            account: id,
            folder: "-".to_owned(),
            uid_validity: 0,
            uid: 0,
        };
        self.deliver(p, cfg, &source, request, input.approval_id.as_deref())
            .await
    }

    /// Fail before touching the backend when this deployment cannot send at all.
    fn ready_to_send(&self, cfg: &AccountConfig) -> Result<(), ToolError> {
        if self.outgoing.is_none() {
            return Err(not_configured().into());
        }
        if cfg.smtp.is_none() {
            return Err(Error::new(ErrorCode::ConfigInvalid, "account has no SMTP section").into());
        }
        Ok(())
    }

    async fn load_source(&self, cfg: &AccountConfig, r: &MessageRef) -> Result<Message, ToolError> {
        let m = self
            .run(cfg, self.backend.get_message(r, MAX_DRAFT_BODY_BYTES))
            .await?;
        if m.body.truncated {
            return Err(ToolError::invalid("message is too large to send"));
        }
        Ok(m)
    }

    /// Non-inline attachments, fetched through the backend (never via the filesystem).
    async fn collect_attachments(
        &self,
        cfg: &AccountConfig,
        r: &MessageRef,
        metas: &[AttachmentMeta],
    ) -> Result<Vec<Attachment>, ToolError> {
        let mut out = Vec::new();
        for meta in metas.iter().filter(|m| !m.inline) {
            let a = self
                .run(
                    cfg,
                    self.backend
                        .get_attachment(r, meta.index, MAX_ATTACHMENT_BYTES),
                )
                .await?;
            if a.bytes.len() > MAX_ATTACHMENT_BYTES {
                return Err(Error::new(ErrorCode::LimitExceeded, "attachment too large").into());
            }
            out.push(Attachment {
                filename: sanitize_filename(a.meta.filename.as_deref().unwrap_or_default()),
                content_type: safe_content_type(&a.meta.content_type),
                data: a.bytes,
            });
        }
        Ok(out)
    }

    /// Approval check, then exactly one SMTP attempt. An `Uncertain` result is surfaced, never retried.
    async fn deliver(
        &self,
        principal: &Principal,
        cfg: &AccountConfig,
        source: &MessageRef,
        mut request: SendRequest,
        approval: Option<&str>,
    ) -> Result<Json<SendOut>, ToolError> {
        let outgoing = self
            .outgoing
            .as_deref()
            .ok_or_else(|| ToolError::from(not_configured()))?;
        request.idempotency_key = idempotency_key(&request, source);
        let key = request.idempotency_key.clone();

        let recorder = Recorder {
            outgoing,
            pending: Mutex::new(None),
        };
        let proof = match ApprovalProof::obtain(
            &recorder,
            principal.client_id(),
            &cfg.id,
            &request,
            approval,
        ) {
            Ok(proof) => proof,
            Err(e) => {
                let pending = recorder.pending.lock().ok().and_then(|mut s| s.take());
                return Err(not_approved(e, pending, approval.is_some()));
            }
        };

        let sent_request = request.clone();
        let (message_id, already_sent) = match outgoing.send(cfg, request, proof).await {
            Ok(SendOutcome::Sent { message_id }) => (message_id, false),
            Ok(SendOutcome::AlreadyAccepted { message_id }) => (message_id, true),
            Err(Error::Coded {
                code: ErrorCode::DeliveryUncertain,
                ..
            }) => {
                return Err(ToolError::new(ErrorCode::DeliveryUncertain, UNCERTAIN_HINT)
                    .with_detail("idempotency_key", key));
            }
            Err(e) => return Err(e.into()),
        };
        let sent_copy_saved =
            !already_sent && self.save_sent_copy(cfg, &sent_request, &message_id).await;
        Ok(Json(SendOut {
            sent: true,
            already_sent,
            message_id,
            sent_copy_saved,
        }))
    }

    /// Best effort: the message is already delivered, so a failure here is reported, not fatal.
    async fn save_sent_copy(
        &self,
        cfg: &AccountConfig,
        request: &SendRequest,
        message_id: &str,
    ) -> bool {
        let built = match build_message(request, message_id) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(account = %cfg.id, error = %e, "could not render the Sent copy");
                return false;
            }
        };
        match self
            .run(cfg, self.backend.append_sent(&cfg.id, built.raw))
            .await
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(account = %cfg.id, code = ?e.code, "Sent-folder copy failed");
                false
            }
        }
    }
}

/// No approval, or one that does not verify for exactly this message: always the same code, so a
/// caller cannot tell expired from replayed from mismatched, plus the pending request to approve.
fn not_approved(e: Error, pending: Option<String>, supplied: bool) -> ToolError {
    let Error::Coded { code, .. } = &e;
    if !matches!(
        code,
        ErrorCode::SendNotApproved | ErrorCode::ApprovalInvalid
    ) {
        return e.into();
    }
    let msg = if supplied {
        "the approval is invalid, expired, already used, or was granted for a different message; nothing was sent"
    } else {
        "sending requires an approval granted by the account owner; nothing was sent"
    };
    let err = ToolError::new(ErrorCode::SendNotApproved, msg);
    match pending {
        Some(id) => err.with_detail("request_id", id),
        None => err,
    }
}
