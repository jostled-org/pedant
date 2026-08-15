//! Verdict evidence: subject derivation, annotation precedence, retained
//! counts, and input order. The serialized form of these rows is owned by
//! `serialization.rs`; this module owns their values.

use std::sync::Arc;

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{
    GateVerdict, ModuleBoundaryEntity, ModuleBoundaryFact, ModuleBoundaryMeasurement,
    evaluate_module_boundary_rules,
};

use crate::fixture::{
    TARGET, cohesion, component, entities, entity, evidence_of, file_entity, input, judge,
    left_module, left_partition, located_entity, misplaced, right_module, rule_names,
};

/// An annotation row: members in node order and the location the subject takes.
type AnchorRow = (
    &'static str,
    Box<[ModuleBoundaryEntity]>,
    Option<(&'static str, u32, u32)>,
);

/// A component verdict names its first member, annotates it at the first
/// spanned member rather than the earlier file-anchored one, and keeps every
/// retained row.
fn assert_component_evidence_is_exact(
    verdict: &GateVerdict,
    members: Arc<[ModuleBoundaryEntity]>,
    partitions: Arc<[ModuleBoundaryEntity]>,
) {
    let evidence = evidence_of(verdict);
    assert_eq!(evidence.target(), TARGET);
    let subject = evidence.subject();
    assert_eq!(subject.ordinal(), 1, "the first member owns the ordinal");
    assert_eq!(subject.label(), "scc::demo::a");
    let anchor = subject
        .location()
        .expect("the first spanned member annotates the component");
    assert_eq!(
        (anchor.path(), anchor.line(), anchor.column()),
        ("src/lib.rs", 8, 3)
    );
    assert_eq!(
        evidence.measurement(),
        &ModuleBoundaryMeasurement::Component {
            cyclic: true,
            members,
            partitions,
        },
        "equal labels stay distinct rows through their target-local ordinals"
    );
}

/// The component annotation follows span, then file, then no location, and
/// never the coordinates alone: a file anchor and a span both read 1:1.
fn assert_component_annotation_follows_span_then_file() {
    let file_a = file_entity(1, "demo::a", "src/lib.rs");
    let rows: [AnchorRow; 5] = [
        (
            "a later span outranks an earlier file",
            Box::new([
                file_a.clone(),
                located_entity(2, "demo::b", "src/right.rs", 9, 5),
            ]),
            Some(("src/right.rs", 9, 5)),
        ),
        (
            "a span at the origin still outranks an earlier file",
            Box::new([
                file_a.clone(),
                located_entity(2, "demo::b", "src/right.rs", 1, 1),
            ]),
            Some(("src/right.rs", 1, 1)),
        ),
        (
            "the first file anchors when no member has a span",
            Box::new([file_a.clone(), file_entity(2, "demo::b", "src/right.rs")]),
            Some(("src/lib.rs", 1, 1)),
        ),
        (
            "a file outranks no location",
            Box::new([entity(1, "demo::a"), file_entity(2, "demo::b", "src/b.rs")]),
            Some(("src/b.rs", 1, 1)),
        ),
        (
            "no member is located",
            Box::new([entity(1, "demo::a"), entity(2, "demo::b")]),
            None,
        ),
    ];
    for (label, members, expected) in rows {
        let component = ModuleBoundaryFact::component(
            true,
            entities(members),
            entities([entity(10, "demo::p")]),
        )
        .expect("a validated cyclic component");
        let subject = component.subject();
        let annotation = subject
            .location()
            .map(|anchor| (anchor.path(), anchor.line(), anchor.column()));
        assert_eq!(annotation, expected, "{label}");
        assert_eq!(
            (subject.ordinal(), subject.label()),
            (1, "scc::demo::a"),
            "{label}: the annotation does not move the subject identity"
        );
    }
}

/// A symbol verdict and a cohesion verdict keep their subjects and counts.
fn assert_symbol_and_cohesion_evidence_are_exact(symbol: &GateVerdict, module: &GateVerdict) {
    let symbol_evidence = evidence_of(symbol);
    assert_eq!(
        symbol_evidence.measurement(),
        &ModuleBoundaryMeasurement::MisplacedSymbol {
            declared_partition: left_module(),
            candidate_partition: right_module(),
            foreign_edges: 3,
            total_outgoing_edges: 5,
        }
    );
    assert_eq!(symbol_evidence.subject().ordinal(), 3);

    let cohesion_evidence = evidence_of(module);
    assert_eq!(cohesion_evidence.subject().label(), "demo::left");
    assert_eq!(
        cohesion_evidence.measurement(),
        &ModuleBoundaryMeasurement::LowModuleCohesion {
            internal_edges: 1,
            boundary_edges: 3,
        }
    );
}

/// A location-free root stays identified, equal rows stay in input order, and
/// a target with no fact produces nothing.
fn assert_unanchored_and_repeated_rows_are_identified() {
    let unanchored = judge(Box::new([component(true, 2, 2)]), &GateConfig::default());
    let root = evidence_of(&unanchored[0]);
    assert_eq!(root.subject().location(), None);
    assert_eq!(root.subject().label(), "scc::demo::member0");

    let repeated = judge(
        Box::new([cohesion(1, 3), cohesion(0, 4)]),
        &GateConfig::default(),
    );
    assert_eq!(repeated.len(), 2, "input order is retained within one rule");
    assert_eq!(
        evidence_of(&repeated[1]).measurement(),
        &ModuleBoundaryMeasurement::LowModuleCohesion {
            internal_edges: 0,
            boundary_edges: 4,
        }
    );

    let empty = input(Box::new([]));
    assert!(
        evaluate_module_boundary_rules(&empty, &GateConfig::default()).is_empty(),
        "a target with no fact produces no verdict"
    );
}

/// Every verdict names one target and subject and retains its exact counts.
pub(crate) fn module_boundary_evidence_is_complete_and_ordered() {
    let members = entities([
        file_entity(1, "demo::a", "src/first.rs"),
        located_entity(2, "demo::a", "src/lib.rs", 8, 3),
        located_entity(3, "demo::b", "src/right.rs", 1, 1),
    ]);
    let partitions = entities([left_partition(), right_module()]);
    let anchored =
        ModuleBoundaryFact::component(true, Arc::clone(&members), Arc::clone(&partitions))
            .expect("a validated cyclic component");
    let verdicts = judge(
        Box::new([anchored, misplaced(3, 5), cohesion(1, 3)]),
        &GateConfig::default(),
    );
    assert_eq!(
        rule_names(&verdicts),
        [
            "boundary-crossing-scc",
            "misplaced-symbol",
            "low-module-cohesion"
        ]
    );

    assert_component_evidence_is_exact(&verdicts[0], members, partitions);
    assert_component_annotation_follows_span_then_file();
    assert_symbol_and_cohesion_evidence_are_exact(&verdicts[1], &verdicts[2]);
    assert_unanchored_and_repeated_rows_are_identified();
}
