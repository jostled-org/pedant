use pedant_core::Violation;
use pedant_core::gate::{GateSeverity, GateVerdict};
use pedant_types::{Capability, CapabilityFinding};
use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};

use super::{error_result, json_result};
use crate::index::WorkspaceIndex;

// ---------------------------------------------------------------------------
// Parameter structs
// ---------------------------------------------------------------------------

/// Parameters for the `query_capabilities` tool.
#[derive(Deserialize)]
pub struct QueryCapabilitiesParams {
    /// Crate name to query.
    pub scope: Box<str>,
    /// Optional capability filter (e.g. "network").
    #[serde(default)]
    pub capability: Option<Box<str>>,
    /// When true, only return build-script findings.
    #[serde(default)]
    pub build_script_only: Option<bool>,
}

/// Parameters for the `query_gate_verdicts` tool.
#[derive(Deserialize)]
pub struct QueryGateVerdictsParams {
    /// Crate name to query.
    pub scope: Box<str>,
}

/// Parameters for the `query_violations` tool.
#[derive(Deserialize)]
pub struct QueryViolationsParams {
    /// Crate name to query.
    pub scope: Box<str>,
    /// Optional check name filter.
    #[serde(default)]
    pub check: Option<Box<str>>,
}

/// Parameters for the `search_by_capability` tool.
#[derive(Deserialize)]
pub struct SearchByCapabilityParams {
    /// Capability pattern (e.g. "network + crypto").
    pub pattern: Box<str>,
}

/// Parameters for the `audit_crate` tool.
#[derive(Deserialize)]
pub struct AuditCrateParams {
    /// Crate name to audit.
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
struct CapabilitySearchResult<'a> {
    crate_name: &'a str,
    findings: Vec<FindingOutput<'a>>,
}

#[derive(Serialize)]
struct AuditOutput<'a> {
    crate_name: &'a str,
    tier: &'static str,
    capabilities: Vec<FindingOutput<'a>>,
    gate_verdicts: Vec<VerdictOutput<'a>>,
    violations: Vec<ViolationOutput<'a>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List capability findings for a crate, file, or workspace.
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

/// Evaluate gate rule verdicts for a crate or workspace.
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

/// List violations for a crate, file, or workspace.
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

/// Find crates matching a capability pattern (e.g. "network + crypto").
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

/// Full security audit for a crate: capabilities, verdicts, tier, violations.
pub fn audit_crate(params: AuditCrateParams, index: &WorkspaceIndex) -> CallToolResult {
    let name = params.crate_name.as_ref();
    let profile = match index.crate_profile(name) {
        Some(p) => p,
        None => return error_result(&format!("unknown crate: {name}")),
    };

    let verdicts = index.crate_verdicts(name).unwrap_or(&[]);
    let violations = collect_crate_violations(index, name);

    let out = AuditOutput {
        crate_name: name,
        tier: "syntactic",
        capabilities: profile.findings.iter().map(finding_output).collect(),
        gate_verdicts: verdicts.iter().map(verdict_output).collect(),
        violations: violations.into_iter().map(violation_output).collect(),
    };
    json_result(&out)
}

// ---------------------------------------------------------------------------
// Scope resolution (flat, no nested matches)
// ---------------------------------------------------------------------------

fn resolve_findings<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a CapabilityFinding>, CallToolResult> {
    if scope == "workspace" {
        return Ok(index
            .all_profiles()
            .flat_map(|(_, p)| p.findings.iter())
            .collect());
    }
    if let Some(profile) = index.crate_profile(scope) {
        return Ok(profile.findings.iter().collect());
    }
    if let Some(result) = index.file_result(scope) {
        return Ok(result.capabilities.findings.iter().collect());
    }
    Err(error_result(&format!("unknown scope: {scope}")))
}

fn resolve_verdicts<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a GateVerdict>, CallToolResult> {
    if scope == "workspace" {
        return Ok(index.all_verdicts().flat_map(|(_, vs)| vs.iter()).collect());
    }
    if let Some(verdicts) = index.crate_verdicts(scope) {
        return Ok(verdicts.iter().collect());
    }
    Err(error_result(&format!("unknown scope: {scope}")))
}

fn resolve_violations<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<&'a Violation>, CallToolResult> {
    if scope == "workspace" {
        return Ok(index
            .crate_names()
            .flat_map(|name| collect_crate_violations(index, name))
            .collect());
    }
    if let Some(files) = index.crate_files(scope) {
        return Ok(files.flat_map(|(_, r)| r.violations.iter()).collect());
    }
    if let Some(result) = index.file_result(scope) {
        return Ok(result.violations.iter().collect());
    }
    Err(error_result(&format!("unknown scope: {scope}")))
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
    name.parse().map_err(|e: pedant_types::ParseCapabilityError| e.to_string())
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
    }
}

fn verdict_output(v: &GateVerdict) -> VerdictOutput<'_> {
    VerdictOutput {
        rule: v.rule,
        severity: &v.severity,
        rationale: v.rationale,
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
