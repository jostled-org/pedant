//! Shared builders for the core gate root: capability findings, data-flow
//! facts, and graph-neutral module-boundary rows.
//!
//! Every gate support module draws its inputs from here, so no case restates a
//! finding shape, a flow fact, or a validated module-boundary row.

use std::sync::Arc;

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{
    GateEvidence, GateInputSummary, GateLocation, GateSeverity, GateVerdict, ModuleBoundaryEntity,
    ModuleBoundaryEvidence, ModuleBoundaryFact, ModuleBoundaryInput, evaluate_gate_rules,
    evaluate_module_boundary_rules,
};
use pedant_core::ir::{DataFlowFact, DataFlowKind, IrSpan};
use pedant_types::{
    Capability, CapabilityFinding, ExecutionContext, FindingOrigin, SourceLocation,
};

/// The one target label every module-boundary case is scoped to.
pub(crate) const TARGET: &str = ".#lib:demo";

/// The module-boundary rule names in catalog order.
///
/// `configuration.rs` owns the full catalog records and holds itself to this
/// order; every other case names the list rather than restating the count as a
/// bare literal.
pub(crate) const MODULE_BOUNDARY_RULE_NAMES: &[&str] = &[
    "large-scc",
    "boundary-crossing-scc",
    "misplaced-symbol",
    "low-module-cohesion",
];

pub(crate) fn finding(capability: Capability, build_hook: bool) -> CapabilityFinding {
    finding_with_evidence(capability, build_hook, "test evidence")
}

pub(crate) fn finding_with_evidence(
    capability: Capability,
    build_hook: bool,
    evidence: &str,
) -> CapabilityFinding {
    let execution_context = match build_hook {
        true => Some(ExecutionContext::BuildHook),
        false => None,
    };
    CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::from("test.rs"),
            line: 1,
            column: 1,
        },
        evidence: Arc::from(evidence),
        origin: None,
        language: None,
        execution_context,
        reachable: None,
    }
}

pub(crate) fn finding_with_origin(
    capability: Capability,
    origin: FindingOrigin,
    evidence: &str,
) -> CapabilityFinding {
    CapabilityFinding {
        origin: Some(origin),
        ..finding_with_evidence(capability, false, evidence)
    }
}

/// Convenience wrapper: build summary and evaluate in one call.
pub(crate) fn eval(
    findings: &[CapabilityFinding],
    data_flows: &[DataFlowFact],
    config: &GateConfig,
) -> Box<[GateVerdict]> {
    let summary = GateInputSummary::from_analysis(findings, data_flows);
    evaluate_gate_rules(&summary, config)
}

pub(crate) fn kind_fact(kind: DataFlowKind, message: &str) -> DataFlowFact {
    DataFlowFact {
        kind,
        source_capability: None,
        source_span: IrSpan { line: 1, column: 0 },
        sink_capability: None,
        sink_span: IrSpan { line: 5, column: 0 },
        call_chain: Box::new([]),
        message: Box::from(message),
    }
}

pub(crate) fn flow_fact(source: Capability, sink: Capability) -> DataFlowFact {
    DataFlowFact {
        kind: DataFlowKind::TaintFlow,
        source_capability: Some(source),
        source_span: IrSpan { line: 1, column: 0 },
        sink_capability: Some(sink),
        sink_span: IrSpan { line: 5, column: 0 },
        call_chain: Box::new([]),
        message: format!("{source:?} flows to {sink:?}").into_boxed_str(),
    }
}

/// A location-free graph-neutral entity.
pub(crate) fn entity(ordinal: u32, label: &str) -> ModuleBoundaryEntity {
    ModuleBoundaryEntity::try_new(ordinal, label, None).expect("a non-empty label is valid")
}

/// An entity anchored at a one-based source coordinate.
pub(crate) fn located_entity(
    ordinal: u32,
    label: &str,
    path: &str,
    line: u32,
    column: u32,
) -> ModuleBoundaryEntity {
    let location = GateLocation::try_new(path, line, column).expect("one-based coordinates");
    ModuleBoundaryEntity::try_new(ordinal, label, Some(location)).expect("a non-empty label")
}

/// An entity anchored at the file that holds it, with no span of its own.
pub(crate) fn file_entity(ordinal: u32, label: &str, path: &str) -> ModuleBoundaryEntity {
    let location = GateLocation::try_new_file(path).expect("a non-empty path");
    ModuleBoundaryEntity::try_new(ordinal, label, Some(location)).expect("a non-empty label")
}

/// The declared partition every misplacement and cohesion row is scoped to.
pub(crate) fn left_module() -> ModuleBoundaryEntity {
    entity(10, "demo::left")
}

/// The candidate partition a misplaced symbol leans toward.
pub(crate) fn right_module() -> ModuleBoundaryEntity {
    entity(11, "demo::right")
}

/// The same declared partition, anchored at the file that declares it.
pub(crate) fn left_partition() -> ModuleBoundaryEntity {
    located_entity(10, "demo::left", "src/left.rs", 1, 1)
}

/// The same candidate partition, anchored at the file that declares it.
pub(crate) fn right_partition() -> ModuleBoundaryEntity {
    located_entity(11, "demo::right", "src/right.rs", 1, 1)
}

/// Collect any entity sequence into the immutable slice the fact constructors
/// take, so a temporary array, an owned collection, and a borrowed slice's
/// clones all reach one builder.
pub(crate) fn entities(
    rows: impl IntoIterator<Item = ModuleBoundaryEntity>,
) -> Arc<[ModuleBoundaryEntity]> {
    rows.into_iter().collect()
}

/// A component with `count` cyclic members spread over `partition_count`
/// declared partitions. Members and partitions occupy disjoint ordinal ranges.
pub(crate) fn component(cyclic: bool, count: u32, partition_count: u32) -> ModuleBoundaryFact {
    let members = entities((0..count).map(|index| entity(index, &format!("demo::member{index}"))));
    let partitions = entities(
        (0..partition_count).map(|index| entity(1_000 + index, &format!("demo::partition{index}"))),
    );
    ModuleBoundaryFact::component(cyclic, members, partitions).expect("a validated component row")
}

pub(crate) fn misplaced(foreign_edges: u32, total_outgoing_edges: u32) -> ModuleBoundaryFact {
    ModuleBoundaryFact::misplaced_symbol(
        entity(3, "demo::left::item"),
        left_module(),
        right_module(),
        foreign_edges,
        total_outgoing_edges,
    )
    .expect("a validated misplaced-symbol row")
}

pub(crate) fn cohesion(internal_edges: u32, boundary_edges: u32) -> ModuleBoundaryFact {
    ModuleBoundaryFact::low_module_cohesion(left_module(), internal_edges, boundary_edges)
}

pub(crate) fn input(facts: Box<[ModuleBoundaryFact]>) -> ModuleBoundaryInput {
    ModuleBoundaryInput::try_new(TARGET, facts).expect("a non-empty target")
}

/// Evaluate module-boundary policy over one target's facts.
pub(crate) fn judge(facts: Box<[ModuleBoundaryFact]>, config: &GateConfig) -> Box<[GateVerdict]> {
    evaluate_module_boundary_rules(&input(facts), config)
}

/// The evidence a structural verdict is required to carry.
pub(crate) fn gate_evidence(verdict: &GateVerdict) -> &GateEvidence {
    verdict
        .evidence
        .as_ref()
        .expect("a module-boundary verdict carries evidence")
}

/// The module-boundary evidence behind that domain envelope.
pub(crate) fn evidence_of(verdict: &GateVerdict) -> &ModuleBoundaryEvidence {
    let GateEvidence::ModuleBoundary(evidence) = gate_evidence(verdict);
    evidence
}

/// The rule names of a verdict slice, in emission order.
///
/// The result stays a `Vec` because `Vec<T>: PartialEq<[U; N]>` is what lets a
/// case state its expected order as a plain array literal; a boxed slice has no
/// such comparison and would push formatting noise into every assertion.
pub(crate) fn rule_names(verdicts: &[GateVerdict]) -> Vec<&'static str> {
    verdicts.iter().map(|verdict| verdict.rule).collect()
}

/// Assert one rule fired at one severity, naming the whole emitted set on
/// failure so a missing verdict reports what did fire.
pub(crate) fn assert_rule_severity(verdicts: &[GateVerdict], rule: &str, severity: GateSeverity) {
    let fired = verdicts
        .iter()
        .find(|verdict| verdict.rule == rule)
        .unwrap_or_else(|| panic!("expected a {rule} verdict, got {:?}", rule_names(verdicts)));
    assert_eq!(fired.severity, severity, "{rule} severity");
}

/// Assert one rule did not fire, naming the whole emitted set on failure.
pub(crate) fn assert_rule_absent(verdicts: &[GateVerdict], rule: &str) {
    assert!(
        !verdicts.iter().any(|verdict| verdict.rule == rule),
        "{rule} should not fire, got {:?}",
        rule_names(verdicts)
    );
}

/// Assert a verdict slice holds nothing at all, naming what it holds instead.
pub(crate) fn assert_no_verdicts(verdicts: &[GateVerdict], claim: &str) {
    assert!(
        verdicts.is_empty(),
        "{claim}, got {:?}",
        rule_names(verdicts)
    );
}

/// Parse a `[gate]` section body into the config the evaluators consume.
pub(crate) fn gate_config(body: &str) -> GateConfig {
    toml::from_str(body).expect("the gate section should parse")
}

/// A `[gate]` body whose module-boundary table states `key = value`.
pub(crate) fn module_boundary_config(key: &str, value: &str) -> GateConfig {
    gate_config(&format!("[module-boundary]\n{key} = {value}\n"))
}

/// Every rejected `[gate]` body is refused with its own concrete message.
pub(crate) fn assert_gate_config_rejections(rows: &[(&str, &str)]) {
    for (body, expected) in rows {
        let error =
            toml::from_str::<GateConfig>(body).expect_err(&format!("{body} should be rejected"));
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in {error}"
        );
    }
}
