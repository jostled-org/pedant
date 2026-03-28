use pedant_core::lookup_rationale;
use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::{error_result, json_result};

/// Deserialized arguments for `explain_finding`.
#[derive(Deserialize)]
pub struct ExplainFindingParams {
    /// Check code to look up (e.g., `"max-depth"`, `"clone-in-loop"`).
    pub check_name: Box<str>,
}

/// Handler: return the structured rationale for a check code.
pub fn explain_finding(params: ExplainFindingParams) -> CallToolResult {
    let rationale = match lookup_rationale(&params.check_name) {
        Some(r) => r,
        None => return error_result(format!("unknown check: {}", params.check_name)),
    };

    json_result(&rationale)
}
