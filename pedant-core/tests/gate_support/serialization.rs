//! The exact serialized gate contract: evidence-bearing module-boundary
//! verdicts and byte-identical legacy capability and data-flow verdicts.

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{GateVerdict, ModuleBoundaryFact};
use pedant_types::Capability;

use crate::fixture::{
    entities, eval, finding, flow_fact, gate_evidence, judge, left_partition, located_entity,
    right_partition,
};

const COMPONENT_VERDICT: &str = r#"{"rule":"boundary-crossing-scc","severity":"deny","rationale":"cycle crosses declared module partitions","evidence":{"domain":"module_boundary","evidence":{"target":".#lib:demo","subject":{"ordinal":1,"label":"scc::demo::a","location":{"path":"src/lib.rs","line":4,"column":1}},"measurement":{"kind":"component","cyclic":true,"members":[{"ordinal":1,"label":"demo::a","location":{"path":"src/lib.rs","line":4,"column":1}},{"ordinal":2,"label":"demo::b","location":{"path":"src/lib.rs","line":8,"column":1}}],"partitions":[{"ordinal":10,"label":"demo::left","location":{"path":"src/left.rs","line":1,"column":1}},{"ordinal":11,"label":"demo::right","location":{"path":"src/right.rs","line":1,"column":1}}]}}}}"#;

const SYMBOL_EVIDENCE: &str = r#"{"domain":"module_boundary","evidence":{"target":".#lib:demo","subject":{"ordinal":3,"label":"demo::left::item","location":{"path":"src/left.rs","line":7,"column":1}},"measurement":{"kind":"misplaced_symbol","declared_partition":{"ordinal":10,"label":"demo::left","location":{"path":"src/left.rs","line":1,"column":1}},"candidate_partition":{"ordinal":11,"label":"demo::right","location":{"path":"src/right.rs","line":1,"column":1}},"foreign_edges":3,"total_outgoing_edges":4}}}"#;

const COHESION_EVIDENCE: &str = r#"{"domain":"module_boundary","evidence":{"target":".#lib:demo","subject":{"ordinal":10,"label":"demo::left","location":{"path":"src/left.rs","line":1,"column":1}},"measurement":{"kind":"low_module_cohesion","internal_edges":2,"boundary_edges":3}}}"#;

const LEGACY_VERDICTS: &[&str] = &[
    r#"{"rule":"build-script-network","severity":"deny","rationale":"Build scripts should not make network requests"}"#,
    r#"{"rule":"env-to-network","severity":"deny","rationale":"Environment variable value reaches a network call — potential credential exfiltration"}"#,
];

fn spec_facts() -> Box<[ModuleBoundaryFact]> {
    let left = left_partition();
    let right = right_partition();
    let members = entities([
        located_entity(1, "demo::a", "src/lib.rs", 4, 1),
        located_entity(2, "demo::b", "src/lib.rs", 8, 1),
    ]);
    let partitions = entities([left.clone(), right.clone()]);
    let component = ModuleBoundaryFact::component(true, members, partitions)
        .expect("a validated cyclic component");
    let symbol = ModuleBoundaryFact::misplaced_symbol(
        located_entity(3, "demo::left::item", "src/left.rs", 7, 1),
        left.clone(),
        right,
        3,
        4,
    )
    .expect("a validated misplaced-symbol row");
    let cohesion = ModuleBoundaryFact::low_module_cohesion(left, 2, 3);
    Box::new([component, symbol, cohesion])
}

fn evidence_json(verdict: &GateVerdict) -> String {
    serde_json::to_string(gate_evidence(verdict)).expect("evidence serializes")
}

/// Module-boundary JSON matches the published contract; legacy verdict bytes
/// are unchanged because absent evidence is omitted.
pub(crate) fn gate_evidence_serialization_is_exact_and_legacy_json_is_unchanged() {
    let verdicts = judge(spec_facts(), &GateConfig::default());
    assert_eq!(
        verdicts.len(),
        3,
        "one component, one symbol, and one cohesion verdict"
    );
    assert_eq!(
        serde_json::to_string(&verdicts[0]).expect("a verdict serializes"),
        COMPONENT_VERDICT
    );
    assert_eq!(evidence_json(&verdicts[1]), SYMBOL_EVIDENCE);
    assert_eq!(evidence_json(&verdicts[2]), COHESION_EVIDENCE);

    let capability = eval(
        &[finding(Capability::Network, true)],
        &[],
        &GateConfig::default(),
    );
    let build_script = capability
        .iter()
        .find(|verdict| verdict.rule == "build-script-network")
        .expect("expected build-script-network verdict");
    assert!(build_script.evidence.is_none());
    assert_eq!(
        serde_json::to_string(build_script).expect("a verdict serializes"),
        LEGACY_VERDICTS[0]
    );

    let flows = eval(
        &[],
        &[flow_fact(Capability::EnvAccess, Capability::Network)],
        &GateConfig::default(),
    );
    let taint = flows
        .iter()
        .find(|verdict| verdict.rule == "env-to-network")
        .expect("expected env-to-network verdict");
    assert_eq!(
        serde_json::to_string(taint).expect("a verdict serializes"),
        LEGACY_VERDICTS[1]
    );

    let manual = GateVerdict {
        rule: "build-script-network",
        severity: build_script.severity,
        rationale: build_script.rationale,
        evidence: None,
    };
    assert_eq!(
        serde_json::to_string(&manual).expect("a verdict serializes"),
        LEGACY_VERDICTS[0],
        "an explicitly evidence-free verdict keeps the legacy object"
    );
}
