use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::super::json_result;
use super::outputs::{ViolationOutput, violation_output};
use super::scope::resolve_violations;
use crate::index::WorkspaceIndex;

/// Deserialized arguments for `query_violations`.
#[derive(Deserialize)]
pub struct QueryViolationsParams {
    /// Crate name, file path, or `"workspace"`.
    pub scope: Box<str>,
    /// Restrict to a specific check code (e.g., `"max-depth"`).
    #[serde(default)]
    pub check: Option<Box<str>>,
    /// Restrict to a category (e.g., `"nesting"`).
    #[serde(default)]
    pub category: Option<Box<str>>,
}

/// Handler: list style violations scoped to a crate, file, or workspace.
pub fn query_violations(params: QueryViolationsParams, index: &WorkspaceIndex) -> CallToolResult {
    let check_filter = params.check.as_deref();
    let category_filter = params.category.as_deref();

    let violations = match resolve_violations(&params.scope, index) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let out: Vec<ViolationOutput<'_>> = violations
        .into_iter()
        .filter_map(|v| {
            let code = v.violation_type.code();
            let category = v.violation_type.category();
            let check_matches = check_filter.is_none_or(|filter| code == filter);
            let category_matches = category_filter.is_none_or(|filter| category == filter);
            match (check_matches, category_matches) {
                (true, true) => Some(violation_output(v)),
                _ => None,
            }
        })
        .collect();
    json_result(&out)
}
