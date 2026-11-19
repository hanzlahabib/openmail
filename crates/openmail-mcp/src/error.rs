//! Tool-level errors: returned as `isError: true` results with a structured
//! `{ "error": { "code", "message" } }` payload so models can route on `code`.
use openmail_core::{Error, ErrorCode};
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResponse, CallToolResult};
use serde_json::json;

#[derive(Debug)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    /// Extra machine-readable fields merged into the `error` object (for example the
    /// `request_id` of a pending approval). Only server-generated values go here.
    pub details: Vec<(&'static str, serde_json::Value)>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_detail(mut self, key: &'static str, value: impl Into<serde_json::Value>) -> Self {
        self.details.push((key, value.into()));
        self
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }
}

/// Longest locally generated message passed through to the client.
const MAX_MESSAGE_CHARS: usize = 200;

/// Fixed text for codes whose message may carry server- or mailbox-controlled text
/// (security review F3): the model sees only the code and this constant. The original
/// message goes to the operator log.
fn fixed_message(code: ErrorCode) -> Option<&'static str> {
    Some(match code {
        ErrorCode::ConfigInvalid => "the account configuration is invalid",
        ErrorCode::AuthFailed => "authentication with the mail server failed",
        ErrorCode::ConnectionFailed => "could not connect to the mail server",
        ErrorCode::Timeout => "the mail server did not answer in time",
        ErrorCode::FolderNotFound => "folder not found",
        ErrorCode::MessageNotFound => "message not found",
        ErrorCode::LimitExceeded => "a configured limit was exceeded",
        ErrorCode::DeliveryUncertain => "delivery state is uncertain; do not retry blindly",
        ErrorCode::Unsupported => "the mail server does not support this operation",
        ErrorCode::Internal => "internal error",
        ErrorCode::CredentialMissing => {
            "the mailbox credential is not configured on the server; the operator must set it"
        }
        ErrorCode::AccountNotFound
        | ErrorCode::AccessDenied
        | ErrorCode::ReadOnlyAccount
        | ErrorCode::SendNotApproved
        | ErrorCode::ApprovalInvalid
        | ErrorCode::StaleReference
        | ErrorCode::RateLimited
        | ErrorCode::InvalidInput => return None,
    })
}

impl From<Error> for ToolError {
    fn from(e: Error) -> Self {
        let Error::Coded { code, message } = e;
        match fixed_message(code) {
            Some(fixed) => {
                tracing::debug!(?code, detail = %message, "tool error detail withheld from client");
                Self::new(code, fixed)
            }
            None => {
                let clean: String = crate::sanitize::strip_invisible(&message)
                    .chars()
                    .take(MAX_MESSAGE_CHARS)
                    .collect();
                Self::new(code, clean)
            }
        }
    }
}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, rmcp::ErrorData> {
        // ErrorCode serializes SCREAMING_SNAKE_CASE; falls back to INTERNAL only if serde fails.
        let code = serde_json::to_value(self.code).unwrap_or_else(|_| json!("INTERNAL"));
        let mut error = json!({ "code": code, "message": self.message });
        if let Some(obj) = error.as_object_mut() {
            for (k, v) in self.details {
                obj.insert((*k).to_owned(), v);
            }
        }
        let payload = json!({ "error": error });
        Ok(CallToolResult::structured_error(payload).into())
    }
}
