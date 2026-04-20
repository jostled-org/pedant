use pedant_types::{Capability, CapabilityFinding, ExecutionContext};
use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::super::{error_result, json_result};
use super::outputs::{FindingOutput, finding_output};
use super::scope::resolve_findings;
use crate::index::WorkspaceIndex;

/// Deserialized arguments for `query_capabilities`.
#[derive(Deserialize)]
pub struct QueryCapabilitiesParams {
    /// Crate name, file path, or `"workspace"`.
    pub scope: Box<str>,
    /// Restrict to a single capability type (e.g., `"network"`).
    #[serde(default)]
    pub capability: Option<Box<str>>,
    /// Filter by execution context (e.g., `"build_hook"`, `"install_hook"`).
    #[serde(default)]
    pub execution_context: Option<Box<str>>,
}

/// Handler: list capability findings scoped to a crate, file, or workspace.
pub fn query_capabilities(
    params: QueryCapabilitiesParams,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let cap_filter = match params
        .capability
        .as_deref()
        .map(parse_capability)
        .transpose()
    {
        Ok(f) => f,
        Err(msg) => return error_result(msg),
    };
    let ctx_filter = match params
        .execution_context
        .as_deref()
        .map(parse_execution_context)
        .transpose()
    {
        Ok(f) => f,
        Err(msg) => return error_result(msg),
    };

    let findings = match resolve_findings(&params.scope, index) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let out: Box<[FindingOutput<'_>]> = findings
        .into_iter()
        .filter(|f| filter_finding(f, cap_filter, ctx_filter))
        .map(finding_output)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    json_result(&out)
}

pub(super) fn parse_capability(name: &str) -> Result<Capability, String> {
    name.parse()
        .map_err(|e: pedant_types::ParseCapabilityError| e.to_string())
}

/// Filter on execution context. `None` means no filter (include all).
fn filter_finding(
    finding: &CapabilityFinding,
    cap_filter: Option<Capability>,
    ctx_filter: Option<ExecutionContext>,
) -> bool {
    let cap_ok = cap_filter.is_none_or(|c| finding.capability == c);
    let ctx_ok = ctx_filter.is_none_or(|c| finding.execution_context == Some(c));
    cap_ok && ctx_ok
}

fn parse_execution_context(name: &str) -> Result<ExecutionContext, String> {
    match name {
        "runtime" => Ok(ExecutionContext::Runtime),
        "build_hook" => Ok(ExecutionContext::BuildHook),
        "install_hook" => Ok(ExecutionContext::InstallHook),
        "generator" => Ok(ExecutionContext::Generator),
        _ => Err(format!("unknown execution context: {name}")),
    }
}
