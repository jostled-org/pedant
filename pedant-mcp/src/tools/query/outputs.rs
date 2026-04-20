use pedant_core::gate::GateSeverity;
use pedant_core::ir::DataFlowFact;
use pedant_types::{Capability, CapabilityFinding, ExecutionContext, Language};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct FindingOutput<'a> {
    pub(super) capability: Capability,
    pub(super) file: &'a str,
    pub(super) line: usize,
    pub(super) evidence: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) language: Option<Language>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) execution_context: Option<ExecutionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reachable: Option<bool>,
}

#[derive(Serialize)]
pub(super) struct VerdictOutput<'a> {
    pub(super) rule: &'a str,
    pub(super) severity: &'a GateSeverity,
    pub(super) rationale: &'a str,
}

#[derive(Serialize)]
pub(super) struct ViolationOutput<'a> {
    pub(super) check: &'a str,
    pub(super) category: &'a str,
    pub(super) file: &'a str,
    pub(super) line: usize,
    pub(super) column: usize,
    pub(super) message: &'a str,
}

#[derive(Serialize)]
pub(super) struct DataFlowOutput<'a> {
    pub(super) kind: &'static str,
    pub(super) source: Option<Capability>,
    pub(super) source_line: usize,
    pub(super) sink: Option<Capability>,
    pub(super) sink_line: usize,
    pub(super) call_chain: &'a [Box<str>],
    pub(super) message: &'a str,
}

#[derive(Serialize)]
pub(super) struct AuditOutput<'a> {
    pub(super) crate_name: &'a str,
    pub(super) tier: &'a str,
    pub(super) degraded_files: Box<[DegradedFileOutput<'a>]>,
    pub(super) capabilities: Box<[FindingOutput<'a>]>,
    pub(super) gate_verdicts: Box<[VerdictOutput<'a>]>,
    pub(super) violations: Box<[ViolationOutput<'a>]>,
    pub(super) data_flows: Box<[DataFlowOutput<'a>]>,
}

#[derive(Serialize)]
pub(super) struct DegradedFileOutput<'a> {
    pub(super) file: &'a str,
    pub(super) error: &'a str,
}

#[derive(Serialize)]
pub(super) struct CapabilitySearchResult<'a> {
    pub(super) crate_name: &'a str,
    pub(super) findings: Box<[FindingOutput<'a>]>,
}

pub(super) fn finding_output(f: &CapabilityFinding) -> FindingOutput<'_> {
    FindingOutput {
        capability: f.capability,
        file: &f.location.file,
        line: f.location.line,
        evidence: &f.evidence,
        language: f.language,
        execution_context: f.execution_context,
        reachable: f.reachable,
    }
}

pub(super) fn verdict_output(v: &pedant_core::gate::GateVerdict) -> VerdictOutput<'_> {
    VerdictOutput {
        rule: v.rule,
        severity: &v.severity,
        rationale: v.rationale,
    }
}

pub(super) fn violation_output(v: &pedant_core::Violation) -> ViolationOutput<'_> {
    ViolationOutput {
        check: v.violation_type.code(),
        category: v.violation_type.category(),
        file: &v.file_path,
        line: v.line,
        column: v.column,
        message: &v.message,
    }
}

pub(super) fn data_flow_output(f: &DataFlowFact) -> DataFlowOutput<'_> {
    DataFlowOutput {
        kind: f.kind.code(),
        source: f.source_capability,
        source_line: f.source_span.line,
        sink: f.sink_capability,
        sink_line: f.sink_span.line,
        call_chain: &f.call_chain,
        message: &f.message,
    }
}

pub(super) fn degraded_file_output<'a>(
    (file, error): (&'a str, &'a str),
) -> DegradedFileOutput<'a> {
    DegradedFileOutput { file, error }
}
