use pedant_core::lookup_rationale;
use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::{error_result, json_result};

/// Parameters for the `explain_finding` tool.
#[derive(Deserialize)]
pub struct ExplainFindingParams {
    /// Check or violation type name to explain.
    pub check_name: Box<str>,
}

/// Get detailed rationale for a check or violation type.
pub fn explain_finding(params: ExplainFindingParams) -> CallToolResult {
    let rationale = match lookup_rationale(&params.check_name) {
        Some(r) => r,
        None => return error_result(&format!("unknown check: {}", params.check_name)),
    };

    json_result(&rationale)
}
