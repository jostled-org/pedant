mod explain;
mod query;

pub use explain::{ExplainFindingParams, explain_finding};
pub use query::{
    AuditCrateParams, QueryCapabilitiesParams, QueryGateVerdictsParams, QueryViolationsParams,
    SearchByCapabilityParams, audit_crate, query_capabilities, query_gate_verdicts,
    query_violations, search_by_capability,
};

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

pub(crate) fn json_result<T: Serialize>(value: &T) -> CallToolResult {
    match serde_json::to_string_pretty(value) {
        Ok(json) => CallToolResult::success(vec![Content::text(json)]),
        Err(e) => error_result(&format!("serialization error: {e}")),
    }
}

pub(crate) fn error_result(message: &str) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message.to_string())])
}
