use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::super::json_result;
use super::outputs::{VerdictOutput, verdict_output};
use super::scope::resolve_verdicts;
use crate::index::WorkspaceIndex;

/// Deserialized arguments for `query_gate_verdicts`.
#[derive(Deserialize)]
pub struct QueryGateVerdictsParams {
    /// Crate name or `"workspace"`.
    pub scope: Box<str>,
}

/// Handler: return fired gate verdicts for a crate or workspace.
pub fn query_gate_verdicts(
    params: QueryGateVerdictsParams,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let verdicts = match resolve_verdicts(&params.scope, index) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let out: Vec<VerdictOutput<'_>> = verdicts.into_iter().map(verdict_output).collect();
    json_result(&out)
}
