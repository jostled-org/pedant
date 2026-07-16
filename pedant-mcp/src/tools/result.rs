use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;

pub(crate) fn json_result<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_string_pretty(value) {
        Ok(json) => CallToolResult::success(vec![ContentBlock::text(json)]),
        Err(e) => error_result(format!("serialization error: {e}")),
    }
}

pub(crate) fn error_result(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}
