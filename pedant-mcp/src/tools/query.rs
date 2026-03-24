use pedant_core::Violation;
use pedant_core::gate::{GateSeverity, GateVerdict};
use pedant_core::ir::DataFlowFact;
use pedant_types::{Capability, CapabilityFinding};
use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};

use super::{error_result, json_result};
use crate::index::WorkspaceIndex;

// ---------------------------------------------------------------------------
// Parameter structs
// ---------------------------------------------------------------------------

/// Deserialized arguments for `query_capabilities`.
#[derive(Deserialize)]
pub struct QueryCapabilitiesParams {
    /// Crate name, file path, or `"workspace"`.
    pub scope: Box<str>,
    /// Restrict to a single capability type (e.g., `"network"`).
    #[serde(default)]
    pub capability: Option<Box<str>>,
    /// When true, only return build-script findings.
    #[serde(default)]
    pub build_script_only: Option<bool>,
}

/// Deserialized arguments for `query_gate_verdicts`.
#[derive(Deserialize)]
pub struct QueryGateVerdictsParams {
    /// Crate name or `"workspace"`.
    pub scope: Box<str>,
}

/// Deserialized arguments for `query_violations`.
#[derive(Deserialize)]
pub struct QueryViolationsParams {
    /// Crate name, file path, or `"workspace"`.
    pub scope: Box<str>,
    /// Restrict to a check code or category (e.g., `"max-depth"` or `"nesting"`).
    #[serde(default)]
    pub check: Option<Box<str>>,
}

/// Deserialized arguments for `search_by_capability`.
#[derive(Deserialize)]
pub struct SearchByCapabilityParams {
    /// Single capability or intersection (e.g., `"network + crypto"`).
    pub pattern: Box<str>,
}

/// Deserialized arguments for `audit_crate`.
#[derive(Deserialize)]
pub struct AuditCrateParams {
    /// Crate to produce a full security audit for.
    pub crate_name: Box<str>,
}

// ---------------------------------------------------------------------------
// Output types (all connected via AuditOutput and CapabilitySearchResult)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FindingOutput<'a> {
    capability: Capability,
    file: &'a str,
    line: usize,
    evidence: &'a str,
    build_script: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reachable: Option<bool>,
}

#[derive(Serialize)]
struct VerdictOutput<'a> {
    rule: &'a str,
    severity: &'a GateSeverity,
    rationale: &'a str,
}

#[derive(Serialize)]
struct ViolationOutput<'a> {
    check: &'a str,
    code: &'a str,
    file: &'a str,
    line: usize,
    column: usize,
    message: &'a str,
}

#[derive(Serialize)]
struct DataFlowOutput<'a> {
    source: Capability,
    source_line: usize,
    sink: Capability,
    sink_line: usize,
    call_chain: &'a [Box<str>],
}

#[derive(Serialize)]
struct CapabilitySearchResult<'a> {
    crate_name: &'a str,
    findings: Vec<FindingOutput<'a>>,
}

#[derive(Serialize)]
struct AuditOutput<'a> {
    crate_name: &'a str,
    tier: &'a str,
    capabilities: Vec<FindingOutput<'a>>,
    gate_verdicts: Vec<VerdictOutput<'a>>,
    violations: Vec<ViolationOutput<'a>>,
    data_flows: Vec<DataFlowOutput<'a>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

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
        Err(msg) => return error_result(&msg),
    };
    let build_only = params.build_script_only.unwrap_or(false);

    let findings = match resolve_findings(&params.scope, index) {
        Ok(f) => f,
        Err(r) => return r,
    };

    let out: Vec<FindingOutput<'_>> = findings
        .into_iter()
        .filter(|f| filter_finding(f, cap_filter, build_only))
        .map(finding_output)
        .collect();
    json_result(&out)
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

/// Handler: list style violations scoped to a crate, file, or workspace.
pub fn query_violations(params: QueryViolationsParams, index: &WorkspaceIndex) -> CallToolResult {
    let check_filter = params.check.as_deref();

    let violations = match resolve_violations(&params.scope, index) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let out: Vec<ViolationOutput<'_>> = violations
        .into_iter()
        .filter_map(|v| {
            let code = v.violation_type.code();
            let check = v.violation_type.check_name();
            match check_filter {
                Some(filter) if code != filter && check != filter => None,
                _ => Some(ViolationOutput {
                    check,
                    code,
                    file: &v.file_path,
                    line: v.line,
                    column: v.column,
                    message: &v.message,
                }),
            }
        })
        .collect();
    json_result(&out)
}

/// Handler: find crates whose profiles contain all requested capabilities.
pub fn search_by_capability(
    params: SearchByCapabilityParams,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let required = match parse_capability_pattern(&params.pattern) {
        Ok(caps) => caps,
        Err(msg) => return error_result(&msg),
    };

    let results: Vec<CapabilitySearchResult<'_>> = index
        .all_profiles()
        .filter(|(_, profile)| {
            required
                .iter()
                .all(|r| profile.findings.iter().any(|f| f.capability == *r))
        })
        .map(|(name, profile)| CapabilitySearchResult {
            crate_name: name,
            findings: profile.findings.iter().map(finding_output).collect(),
        })
        .collect();
    json_result(&results)
}

/// Handler: full security audit combining capabilities, verdicts, and violations.
pub fn audit_crate(params: AuditCrateParams, index: &WorkspaceIndex) -> CallToolResult {
    let name = params.crate_name.as_ref();
    let profile = match index.crate_profile(name) {
        Some(p) => p,
        None => return error_result(&format!("unknown crate: {name}")),
    };

    let verdicts = index.crate_verdicts(name).unwrap_or(&[]);
    let violations = collect_crate_violations(index, name);

    let data_flows: Vec<DataFlowOutput> = index
        .crate_data_flows(name)
        .map(|flows| flows.map(data_flow_output).collect())
        .unwrap_or_default();

    let out = AuditOutput {
        crate_name: name,
        tier: index.crate_tier(name),
        capabilities: profile.findings.iter().map(finding_output).collect(),
        gate_verdicts: verdicts.iter().map(verdict_output).collect(),
        violations: violations.into_iter().map(violation_output).collect(),
        data_flows,
    };
    json_result(&out)
}

// ---------------------------------------------------------------------------
// Scope resolution (flat, no nested matches)
// ---------------------------------------------------------------------------

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
            .ok_or_else(|| error_result(&format!("unknown scope: {scope}"))),
    }
}

fn resolve_findings<'a>(
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

fn resolve_verdicts<'a>(
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

fn resolve_violations<'a>(
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
                .crate_files(s)
                .map(|files| files.flat_map(|(_, r)| r.violations.iter()).collect())
        },
        |s| index.file_result(s).map(|r| r.violations.iter().collect()),
    )
}

fn collect_crate_violations<'a>(index: &'a WorkspaceIndex, name: &str) -> Vec<&'a Violation> {
    index
        .crate_files(name)
        .map(|files| files.flat_map(|(_, r)| r.violations.iter()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_capability(name: &str) -> Result<Capability, String> {
    name.parse()
        .map_err(|e: pedant_types::ParseCapabilityError| e.to_string())
}

fn parse_capability_pattern(pattern: &str) -> Result<Vec<Capability>, String> {
    pattern
        .split('+')
        .map(|s| parse_capability(s.trim()))
        .collect()
}

fn filter_finding(
    finding: &CapabilityFinding,
    cap_filter: Option<Capability>,
    build_only: bool,
) -> bool {
    match (cap_filter, build_only) {
        (Some(cap), true) => finding.capability == cap && finding.build_script,
        (Some(cap), false) => finding.capability == cap,
        (None, true) => finding.build_script,
        (None, false) => true,
    }
}

fn finding_output(f: &CapabilityFinding) -> FindingOutput<'_> {
    FindingOutput {
        capability: f.capability,
        file: &f.location.file,
        line: f.location.line,
        evidence: &f.evidence,
        build_script: f.build_script,
        reachable: f.reachable,
    }
}

fn verdict_output(v: &GateVerdict) -> VerdictOutput<'_> {
    VerdictOutput {
        rule: v.rule,
        severity: &v.severity,
        rationale: v.rationale,
    }
}

fn data_flow_output(f: &DataFlowFact) -> DataFlowOutput<'_> {
    DataFlowOutput {
        source: f.source_capability,
        source_line: f.source_span.line,
        sink: f.sink_capability,
        sink_line: f.sink_span.line,
        call_chain: &f.call_chain,
    }
}

fn violation_output(v: &Violation) -> ViolationOutput<'_> {
    ViolationOutput {
        check: v.violation_type.check_name(),
        code: v.violation_type.code(),
        file: &v.file_path,
        line: v.line,
        column: v.column,
        message: &v.message,
    }
}
