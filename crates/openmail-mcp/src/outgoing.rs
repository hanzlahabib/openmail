//! The send pipeline the MCP server drives: approval consumption, pending-approval requests and
//! SMTP delivery, behind one object-safe trait so `OpenMailServer<B>` needs no extra generics and
//! read-only deployments simply have none.
use std::future::Future;
use std::pin::Pin;

use openmail_core::backend::SecretSource;
use openmail_core::config::AccountConfig;
use openmail_core::{Error, ErrorCode, Result};
use openmail_smtp::{
    ApprovalConsumer, ApprovalProof, SendOutcome, SendRequest, SendRequestDescriptor, SmtpClient,
    SqliteOutbox,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Creates a *pending* approval request that a human can grant out of band (CLI/UI). It can
/// never mint a usable approval id, so an agent calling a tool cannot approve its own send.
pub trait ApprovalRequester: Send + Sync {
    /// Returns the id of the pending request. It is shown to the human, and is not itself a
    /// bearer approval.
    fn request(&self, principal: &str, descriptor: &SendRequestDescriptor) -> Result<String>;
}

/// Everything the send tools need. Implemented by [`SmtpOutgoing`]; tests supply doubles.
pub trait Outgoing: Send + Sync + std::fmt::Debug + 'static {
    fn consumer(&self) -> &dyn ApprovalConsumer;
    fn request_approval(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
    ) -> Result<String>;
    fn send<'a>(
        &'a self,
        account: &'a AccountConfig,
        request: SendRequest,
        proof: ApprovalProof,
    ) -> BoxFuture<'a, Result<SendOutcome>>;
}

/// Adapts `&dyn ApprovalConsumer` to the `impl ApprovalConsumer` that `ApprovalProof::obtain` takes.
pub(crate) struct DynConsumer<'a>(pub &'a dyn ApprovalConsumer);

impl ApprovalConsumer for DynConsumer<'_> {
    fn consume(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
        token: Option<&str>,
    ) -> Result<()> {
        self.0.consume(principal, descriptor, token)
    }
}

/// Production [`Outgoing`]: the real SMTP client, the security crate's approval verifier and a
/// pending-approval requester. Concrete over `SqliteOutbox` because `OutboxStore`'s async fns do
/// not promise `Send` futures, which the object-safe `send` below needs.
pub struct SmtpOutgoing<S, V, R> {
    smtp: SmtpClient<SqliteOutbox, S>,
    verifier: V,
    requests: R,
}

impl<S, V, R> SmtpOutgoing<S, V, R> {
    pub fn new(smtp: SmtpClient<SqliteOutbox, S>, verifier: V, requests: R) -> Self {
        Self {
            smtp,
            verifier,
            requests,
        }
    }
}

impl<S, V, R> std::fmt::Debug for SmtpOutgoing<S, V, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpOutgoing").finish_non_exhaustive()
    }
}

impl<S, V, R> Outgoing for SmtpOutgoing<S, V, R>
where
    S: SecretSource + 'static,
    V: ApprovalConsumer + Send + Sync + 'static,
    R: ApprovalRequester + 'static,
{
    fn consumer(&self) -> &dyn ApprovalConsumer {
        &self.verifier
    }

    fn request_approval(
        &self,
        principal: &str,
        descriptor: &SendRequestDescriptor,
    ) -> Result<String> {
        self.requests.request(principal, descriptor)
    }

    fn send<'a>(
        &'a self,
        account: &'a AccountConfig,
        request: SendRequest,
        proof: ApprovalProof,
    ) -> BoxFuture<'a, Result<SendOutcome>> {
        Box::pin(self.smtp.send(account, request, proof))
    }
}

pub(crate) fn not_configured() -> Error {
    Error::new(ErrorCode::Unsupported, "sending is not configured")
}

/// The security crate's pending-approval queue is the production requester: it only records a
/// request for a human to review; granting needs an out-of-band `HumanConfirmation`.
impl<C> ApprovalRequester for openmail_security::PendingApprovals<C>
where
    C: openmail_security::Clock + Clone + Send + Sync,
{
    fn request(&self, principal: &str, descriptor: &SendRequestDescriptor) -> Result<String> {
        let id = openmail_security::PendingApprovals::request(
            self,
            principal,
            descriptor.account(),
            descriptor,
        )?;
        Ok(id.as_str().to_owned())
    }
}
