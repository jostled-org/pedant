//! The capability and data-flow evaluator and the summary its rules read.

use std::collections::BTreeSet;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin};

use crate::check_config::GateConfig;
use crate::ir::{DataFlowFact, DataFlowKind};

use super::catalog::{CAPABILITY_RULES, resolve_severity};
use super::verdict::GateVerdict;

/// Precomputed summary of capability findings and data flows for gate evaluation.
///
/// Built once per evaluation from raw findings and flows. Every rule predicate
/// reads from this summary instead of rescanning the original slices.
pub struct GateInputSummary {
    all_capabilities: BTreeSet<Capability>,
    build_hook_capabilities: BTreeSet<Capability>,
    has_key_material: bool,
    flow_kinds: BTreeSet<DataFlowKind>,
    taint_pairs: BTreeSet<(Capability, Capability)>,
}

/// Check if a single finding represents embedded key material (not a crypto import).
///
/// When `origin` metadata is present, uses it directly: `StringLiteral` origin
/// indicates embedded key material. Falls back to evidence-based heuristic
/// (no `::` in evidence) for legacy findings without origin metadata.
fn is_key_material(f: &CapabilityFinding) -> bool {
    match (f.capability, f.origin) {
        (Capability::Crypto, Some(FindingOrigin::StringLiteral)) => true,
        (Capability::Crypto, None) => !f.evidence.contains("::"),
        _ => false,
    }
}

impl GateInputSummary {
    /// Build a summary from raw findings and data flow facts.
    pub fn from_analysis(findings: &[CapabilityFinding], flows: &[DataFlowFact]) -> Self {
        Self::build(findings, flows)
    }

    /// Build a summary from borrowed finding references and data flow facts.
    pub fn from_refs(findings: &[&CapabilityFinding], flows: &[DataFlowFact]) -> Self {
        Self::build(findings.iter().copied(), flows)
    }

    /// One pass over the findings, whichever shape the caller holds them in.
    ///
    /// Both public constructors reach the summary through here, so neither can
    /// accumulate a set the other does not.
    fn build<'f>(
        findings: impl IntoIterator<Item = &'f CapabilityFinding>,
        flows: &[DataFlowFact],
    ) -> Self {
        let mut all_capabilities = BTreeSet::new();
        let mut build_hook_capabilities = BTreeSet::new();
        let mut has_key_material = false;

        for finding in findings {
            all_capabilities.insert(finding.capability);
            if finding.is_build_hook() {
                build_hook_capabilities.insert(finding.capability);
            }
            has_key_material |= is_key_material(finding);
        }

        let mut flow_kinds = BTreeSet::new();
        let mut taint_pairs = BTreeSet::new();
        for flow in flows {
            flow_kinds.insert(flow.kind);
            if let (Some(src), Some(sink)) = (flow.source_capability, flow.sink_capability) {
                taint_pairs.insert((src, sink));
            }
        }

        Self {
            all_capabilities,
            build_hook_capabilities,
            has_key_material,
            flow_kinds,
            taint_pairs,
        }
    }

    pub(super) fn has_capability(&self, cap: Capability) -> bool {
        self.all_capabilities.contains(&cap)
    }

    pub(super) fn has_build_hook_capability(&self, cap: Capability) -> bool {
        self.build_hook_capabilities.contains(&cap)
    }

    pub(super) fn has_key_material(&self) -> bool {
        self.has_key_material
    }

    pub(super) fn has_flow(&self, source: Capability, sink: Capability) -> bool {
        self.taint_pairs.contains(&(source, sink))
    }

    pub(super) fn has_kind(&self, kind: DataFlowKind) -> bool {
        self.flow_kinds.contains(&kind)
    }
}

/// Run every enabled gate rule against a precomputed summary, returning fired verdicts.
///
/// Build the summary via `GateInputSummary::from_analysis` before calling this.
/// Respects per-rule config overrides.
pub fn evaluate_gate_rules(summary: &GateInputSummary, config: &GateConfig) -> Box<[GateVerdict]> {
    if !config.enabled {
        return Box::new([]);
    }

    CAPABILITY_RULES
        .iter()
        .filter_map(|rule| {
            let severity = resolve_severity(rule.name, rule.default_severity, &config.overrides)?;
            (rule.predicate)(summary).then(|| rule.verdict(severity, None))
        })
        .collect()
}
