//! Graph-neutral module-boundary judgment: constructor invariants and the four
//! fixed predicates at their exact rational thresholds. Verdict evidence is
//! owned by `evidence.rs`.

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{
    GateAnchor, GateLocation, GateSeverity, GateVerdict, ModuleBoundaryEntity, ModuleBoundaryFact,
    ModuleBoundaryInput, ModuleBoundaryInputError, ModuleBoundaryMeasurement,
};

use crate::fixture::{
    TARGET, assert_no_verdicts, assert_rule_severity, cohesion, component, entities, entity,
    gate_config, judge, left_module, misplaced, module_boundary_config, right_module, rule_names,
};

/// A rejection row: the constructor call under test and the exact error it owes.
type Rejection = (
    &'static str,
    fn() -> Result<(), ModuleBoundaryInputError>,
    ModuleBoundaryInputError,
);

fn member_pair() -> [ModuleBoundaryEntity; 2] {
    [entity(1, "demo::a"), entity(2, "demo::b")]
}

const REJECTIONS: &[Rejection] = &[
    (
        "empty location path",
        || GateLocation::try_new("", 4, 1).map(|_| ()),
        ModuleBoundaryInputError::EmptyLocationPath,
    ),
    (
        "zero line",
        || GateLocation::try_new("src/lib.rs", 0, 1).map(|_| ()),
        ModuleBoundaryInputError::ZeroLocationLine,
    ),
    (
        "zero column",
        || GateLocation::try_new("src/lib.rs", 4, 0).map(|_| ()),
        ModuleBoundaryInputError::ZeroLocationColumn,
    ),
    (
        "path emptiness precedes zero coordinates",
        || GateLocation::try_new("", 0, 0).map(|_| ()),
        ModuleBoundaryInputError::EmptyLocationPath,
    ),
    (
        "line precedes column",
        || GateLocation::try_new("src/lib.rs", 0, 0).map(|_| ()),
        ModuleBoundaryInputError::ZeroLocationLine,
    ),
    (
        "empty file location path",
        || GateLocation::try_new_file("").map(|_| ()),
        ModuleBoundaryInputError::EmptyLocationPath,
    ),
    (
        "empty entity label",
        || ModuleBoundaryEntity::try_new(7, "", None).map(|_| ()),
        ModuleBoundaryInputError::EmptyEntityLabel { ordinal: 7 },
    ),
    (
        "empty component members",
        || {
            ModuleBoundaryFact::component(true, entities([]), entities([entity(10, "demo::p")]))
                .map(|_| ())
        },
        ModuleBoundaryInputError::EmptyComponentMembers,
    ),
    (
        "member emptiness precedes partition emptiness",
        || ModuleBoundaryFact::component(true, entities([]), entities([])).map(|_| ()),
        ModuleBoundaryInputError::EmptyComponentMembers,
    ),
    (
        "duplicate member ordinal",
        || {
            let members = [entity(1, "demo::a"), entity(1, "demo::b")];
            ModuleBoundaryFact::component(
                true,
                entities(members),
                entities([entity(10, "demo::p")]),
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::DuplicateComponentMember { ordinal: 1 },
    ),
    (
        "duplicate member precedes empty partitions",
        || {
            let members = [entity(4, "demo::a"), entity(4, "demo::b")];
            ModuleBoundaryFact::component(true, entities(members), entities([])).map(|_| ())
        },
        ModuleBoundaryInputError::DuplicateComponentMember { ordinal: 4 },
    ),
    (
        "empty component partitions",
        || ModuleBoundaryFact::component(true, entities(member_pair()), entities([])).map(|_| ()),
        ModuleBoundaryInputError::EmptyComponentPartitions,
    ),
    (
        "duplicate partition ordinal",
        || {
            let partitions = [left_module(), entity(10, "demo::right")];
            ModuleBoundaryFact::component(true, entities(member_pair()), entities(partitions))
                .map(|_| ())
        },
        ModuleBoundaryInputError::DuplicateComponentPartition { ordinal: 10 },
    ),
    (
        "more partitions than members",
        || {
            ModuleBoundaryFact::component(
                true,
                entities([entity(1, "demo::a")]),
                entities([left_module(), right_module()]),
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::ComponentPartitionsExceedMembers {
            members: 1,
            partitions: 2,
        },
    ),
    (
        "acyclic component with more than one member",
        || {
            ModuleBoundaryFact::component(
                false,
                entities(member_pair()),
                entities([entity(10, "demo::p")]),
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::AcyclicComponentHasMultipleMembers { members: 2 },
    ),
    (
        "equal misplaced partitions",
        || {
            ModuleBoundaryFact::misplaced_symbol(
                entity(3, "demo::item"),
                left_module(),
                left_module(),
                1,
                2,
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::MisplacedSymbolPartitionsAreEqual { ordinal: 10 },
    ),
    (
        "zero total outgoing edges",
        || {
            ModuleBoundaryFact::misplaced_symbol(
                entity(3, "demo::item"),
                left_module(),
                right_module(),
                0,
                0,
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::MisplacedSymbolHasNoOutgoingEdges { ordinal: 3 },
    ),
    (
        "foreign edges above total",
        || {
            ModuleBoundaryFact::misplaced_symbol(
                entity(3, "demo::item"),
                left_module(),
                right_module(),
                3,
                2,
            )
            .map(|_| ())
        },
        ModuleBoundaryInputError::MisplacedSymbolForeignEdgesExceedTotal {
            foreign_edges: 3,
            total_outgoing_edges: 2,
        },
    ),
    (
        "empty input target",
        || ModuleBoundaryInput::try_new("", Box::new([])).map(|_| ()),
        ModuleBoundaryInputError::EmptyInputTarget,
    ),
];

/// The rule and severity of every emitted verdict, in emission order.
fn rule_severities(verdicts: &[GateVerdict]) -> Vec<(&'static str, GateSeverity)> {
    verdicts
        .iter()
        .map(|verdict| (verdict.rule, verdict.severity))
        .collect()
}

/// Every constructor rejection, its exact variant, and its precedence.
pub(crate) fn module_boundary_input_validation_is_total_and_ordered() {
    for (label, call, expected) in REJECTIONS {
        assert_eq!(call(), Err(*expected), "{label} should be rejected exactly");
    }

    let isolated = ModuleBoundaryFact::low_module_cohesion(left_module(), 0, 0);
    assert_eq!(
        isolated.measurement(),
        &ModuleBoundaryMeasurement::LowModuleCohesion {
            internal_edges: 0,
            boundary_edges: 0
        },
        "an isolated module is a valid cohesion fact"
    );

    let span = GateLocation::try_new("src/lib.rs", 1, 1).expect("one-based coordinates");
    let file = GateLocation::try_new_file("src/lib.rs").expect("a non-empty path");
    assert_eq!(span.anchor(), GateAnchor::Span);
    assert_eq!(
        (file.anchor(), file.path(), file.line(), file.column()),
        (GateAnchor::File, "src/lib.rs", 1, 1),
        "a file location is the whole-file anchor at one-based origin"
    );
    assert_ne!(
        span, file,
        "equal coordinates from different derivations stay distinct"
    );

    let location_free = ModuleBoundaryFact::component(
        true,
        entities(member_pair()),
        entities([entity(10, "demo::p")]),
    )
    .expect("a location-free cyclic component is valid");
    assert_eq!(location_free.subject().location(), None);

    let accepted = ModuleBoundaryInput::try_new(TARGET, Box::new([location_free]))
        .expect("a non-empty target with validated facts is accepted");
    assert_eq!(accepted.target(), TARGET);
    assert_eq!(accepted.facts().len(), 1);
}

/// Equality boundaries and the value on either side, for every default
/// threshold, using counts that overflow `u32` once multiplied by a percentage.
pub(crate) fn module_boundary_default_threshold_boundaries_are_exact() {
    let default = GateConfig::default();
    let scc_rows = [(7_u32, false), (8, false), (9, true)];
    for (members, expected) in scc_rows {
        let fired = rule_names(&judge(Box::new([component(true, members, 1)]), &default))
            .contains(&"large-scc");
        assert_eq!(fired, expected, "large-scc at {members} cyclic members");
    }

    let affinity_rows = [
        (2_u32, 3_u32, false),
        (3, 5, true),
        (3, 6, false),
        (2_400_000_001, 4_000_000_000, true),
        (2_399_999_999, 4_000_000_000, false),
    ];
    for (foreign, total, expected) in affinity_rows {
        let fired = rule_names(&judge(Box::new([misplaced(foreign, total)]), &default))
            .contains(&"misplaced-symbol");
        assert_eq!(fired, expected, "misplaced-symbol at {foreign}/{total}");
    }

    let cohesion_rows = [
        (1_u32, 2_u32, false),
        (2, 2, false),
        (1, 3, true),
        (0, 0, false),
        (2_000_000_000, 2_000_000_000, false),
        (1_999_999_999, 2_000_000_001, true),
    ];
    for (internal, boundary, expected) in cohesion_rows {
        let fired = rule_names(&judge(Box::new([cohesion(internal, boundary)]), &default))
            .contains(&"low-module-cohesion");
        assert_eq!(
            fired, expected,
            "low-module-cohesion at {internal}/{boundary}"
        );
    }

    let all_four = judge(
        Box::new([component(true, 9, 2), misplaced(3, 5), cohesion(1, 3)]),
        &default,
    );
    assert_eq!(
        rule_severities(&all_four),
        [
            ("large-scc", GateSeverity::Warn),
            ("boundary-crossing-scc", GateSeverity::Deny),
            ("misplaced-symbol", GateSeverity::Warn),
            ("low-module-cohesion", GateSeverity::Warn),
        ],
        "rules are evaluated in fixed catalog order at their catalog severities"
    );
}

/// Cycles that cross a declared partition, independent of every other rule.
pub(crate) fn module_boundary_crossing_cycles_are_partition_exact() {
    let default = GateConfig::default();
    let rows = [
        ("multi-partition cycle", component(true, 2, 2), true),
        ("same-partition cycle", component(true, 2, 1), false),
        ("acyclic component", component(false, 1, 1), false),
    ];
    for (label, fact, expected) in rows {
        let fired =
            rule_names(&judge(Box::new([fact]), &default)).contains(&"boundary-crossing-scc");
        assert_eq!(fired, expected, "{label}");
    }

    let extreme = gate_config(
        "[module-boundary]\nmax-scc-members = 4294967295\nmisplaced-symbol-min-foreign-edges = 4294967295\nmisplaced-symbol-min-affinity-percent = 100\nlow-module-cohesion-min-outgoing-edges = 4294967295\nlow-module-cohesion-min-percent = 0\n",
    );
    let verdicts = judge(
        Box::new([component(true, 2, 2), misplaced(3, 5), cohesion(1, 3)]),
        &extreme,
    );
    assert_eq!(
        rule_names(&verdicts),
        ["boundary-crossing-scc"],
        "the crossing rule is independent of the other five thresholds"
    );
    assert_rule_severity(&verdicts, "boundary-crossing-scc", GateSeverity::Deny);

    assert_percent_thresholds_reach_their_own_predicates(&default);

    let severity_override = module_boundary_config("boundary-crossing-scc", "\"info\"");
    let overridden = judge(Box::new([component(true, 2, 2)]), &severity_override);
    assert_eq!(rule_names(&overridden), ["boundary-crossing-scc"]);
    assert_rule_severity(&overridden, "boundary-crossing-scc", GateSeverity::Info);
}

/// Each configured percentage reaches the predicate that names it. A 60%
/// affinity is below a written 100, and a 25% cohesion is not below a written
/// 0, so both rules stop firing on the rows that fire at the defaults —
/// exchanging the two fields would make both fire instead.
fn assert_percent_thresholds_reach_their_own_predicates(default: &GateConfig) {
    let rows: Box<[ModuleBoundaryFact]> = Box::new([misplaced(3, 5), cohesion(1, 3)]);
    assert_eq!(
        rule_names(&judge(rows.clone(), default)),
        ["misplaced-symbol", "low-module-cohesion"],
        "both rows fire at the default percentages"
    );

    let percents = gate_config(
        "[module-boundary]\nmisplaced-symbol-min-affinity-percent = 100\nlow-module-cohesion-min-percent = 0\n",
    );
    assert_no_verdicts(
        &judge(rows, &percents),
        "each written percentage suppresses the rule it names",
    );
}
