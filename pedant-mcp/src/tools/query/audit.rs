use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::super::{error_result, json_result};
use super::outputs::{
    AuditOutput, data_flow_output, degraded_file_output, finding_output, verdict_output,
    violation_output,
};
use super::scope::collect_crate_violations;
use crate::index::WorkspaceIndex;

/// Deserialized arguments for `audit_crate`.
#[derive(Deserialize)]
pub struct AuditCrateParams {
    /// Crate to produce a full security audit for.
    #[serde(alias = "crate_name")]
    pub scope: Box<str>,
}

/// Handler: full security audit combining capabilities, verdicts, and violations.
pub fn audit_crate(params: AuditCrateParams, index: &WorkspaceIndex) -> CallToolResult {
    let name = params.scope.as_ref();
    let profile = match index.crate_profile(name) {
        Some(p) => p,
        None => return error_result(format!("unknown crate: {name}")),
    };

    let verdicts = index.crate_verdicts(name).unwrap_or(&[]);
    let violations = collect_crate_violations(index, name);

    let data_flows: Box<[_]> = index
        .crate_data_flows(name)
        .map(|flows| flows.map(data_flow_output).collect())
        .unwrap_or_default();
    let degraded_files: Box<[_]> = index
        .crate_degraded_files(name)
        .map(|files| files.map(degraded_file_output).collect())
        .unwrap_or_default();

    let out = AuditOutput {
        crate_name: name,
        tier: index.crate_tier(name),
        degraded_files,
        capabilities: profile
            .findings
            .iter()
            .map(finding_output)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        gate_verdicts: verdicts
            .iter()
            .map(verdict_output)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        violations: violations
            .into_iter()
            .map(violation_output)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        data_flows,
    };
    json_result(&out)
}
