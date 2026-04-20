use pedant_core::Violation;
use pedant_core::gate::GateVerdict;
use pedant_types::CapabilityFinding;
use rmcp::model::CallToolResult;

use super::super::error_result;
use crate::index::WorkspaceIndex;

/// Generic scope resolver: tries workspace, then crate, then file, returning
/// the first match. Each level is an `Option`-returning closure; `None` means
/// "this scope level doesn't apply" and resolution continues to the next.
fn resolve_scope<T>(
    scope: &str,
    workspace_fn: impl FnOnce() -> Vec<T>,
    crate_fn: impl FnOnce(&str) -> Option<Vec<T>>,
    file_fn: impl FnOnce(&str) -> Option<Vec<T>>,
) -> Result<Vec<T>, CallToolResult> {
    match scope {
        "workspace" => Ok(workspace_fn()),
        _ => crate_fn(scope)
            .or_else(|| file_fn(scope))
            .ok_or_else(|| error_result(format!("unknown scope: {scope}"))),
    }
}

pub(super) fn resolve_findings<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a CapabilityFinding>, CallToolResult> {
    resolve_scope(
        scope,
        || {
            index
                .all_profiles()
                .flat_map(|(_, p)| p.findings.iter())
                .collect()
        },
        |s| index.crate_profile(s).map(|p| p.findings.iter().collect()),
        |s| {
            index
                .file_result(s)
                .map(|r| r.capabilities.findings.iter().collect())
        },
    )
}

pub(super) fn resolve_verdicts<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a GateVerdict>, CallToolResult> {
    resolve_scope(
        scope,
        || index.all_verdicts().flat_map(|(_, vs)| vs.iter()).collect(),
        |s| index.crate_verdicts(s).map(|vs| vs.iter().collect()),
        |_| None,
    )
}

pub(super) fn resolve_violations<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a Violation>, CallToolResult> {
    resolve_scope(
        scope,
        || {
            index
                .crate_names()
                .flat_map(|name| collect_crate_violations(index, name))
                .collect()
        },
        |s| {
            index
                .crate_profile(s)
                .map(|_| collect_crate_violations(index, s))
        },
        |s| index.file_result(s).map(|r| r.violations.iter().collect()),
    )
}

pub(super) fn collect_crate_violations<'a>(
    index: &'a WorkspaceIndex,
    name: &str,
) -> Vec<&'a Violation> {
    index
        .crate_files(name)
        .map(|files| files.flat_map(|(_, r)| r.violations.iter()).collect())
        .unwrap_or_default()
}
