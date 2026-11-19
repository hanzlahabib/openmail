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
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }
}

impl From<Error> for ToolError {
    fn from(e: Error) -> Self {
        match e {
            Error::Coded { code, message } => Self { code, message },
        }
    }
}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, rmcp::ErrorData> {
        // ErrorCode serializes SCREAMING_SNAKE_CASE; falls back to INTERNAL only if serde fails.
        let code = serde_json::to_value(self.code).unwrap_or_else(|_| json!("INTERNAL"));
        let payload = json!({ "error": { "code": code, "message": self.message } });
        Ok(CallToolResult::structured_error(payload).into())
    }
}
