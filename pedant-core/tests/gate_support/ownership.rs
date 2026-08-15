//! The judgment-versus-topology boundary, read from tracked production source
//! and Cargo manifests only. No lifecycle file is consulted.

use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{
    GateAnchor, GateEvidence, GateLocation, ModuleBoundaryEntity, ModuleBoundaryEvidence,
    ModuleBoundaryFact, ModuleBoundaryInput, ModuleBoundaryMeasurement, all_module_boundary_rules,
    evaluate_module_boundary_rules,
};

use crate::fixture::{MODULE_BOUNDARY_RULE_NAMES, entities, evidence_of, gate_evidence};

/// The judgment tree, enumerated so a later module cannot escape the scan.
const GATE_TREE: &str = "src/gate";

/// Every module the enumerated judgment tree is required to hold, sorted.
const GATE_MODULES: &[&str] = &[
    "capability.rs",
    "catalog.rs",
    "mod.rs",
    "module_boundary.rs",
    "verdict.rs",
];

/// The module-boundary policy owner that lives outside the judgment tree.
const GATE_CONFIG_OWNER: &str = "src/check_config/module_boundary.rs";

/// Topology vocabulary and inexact arithmetic the judgment owner may not hold.
const FORBIDDEN_IN_GATE: &[&str] = &[
    "pedant_graph",
    "pedant-graph",
    "CodeGraph",
    "GraphNodeId",
    "f32",
    "f64",
    "percentile",
    "tarjan",
    "strongly_connected_components",
    "betweenness",
    "centrality",
    "modularity",
];

/// Policy vocabulary the topology owner may not hold.
const FORBIDDEN_IN_GRAPH: &[&str] = &[
    "GateVerdict",
    "GateSeverity",
    "GateConfig",
    "GateRuleOverride",
    "GateEvidence",
    "ModuleBoundaryConfig",
    "ModuleBoundaryInput",
    "evaluate_module_boundary_rules",
    "all_module_boundary_rules",
    "pedant_core::gate",
    "pedant_core::check_config",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is tracked: {error}", path.display()))
}

/// Every `.rs` file beneath one production tree, gathered once.
fn rust_source_tree(root: &Path) -> Box<[PathBuf]> {
    let mut found = Vec::new();
    rust_sources(root, &mut found);
    found.into_boxed_slice()
}

fn rust_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", root.display()));
    for entry in entries {
        let path = entry.expect("a directory entry is readable").path();
        collect_source(&path, found);
    }
}

fn collect_source(path: &Path, found: &mut Vec<PathBuf>) {
    match (
        path.is_dir(),
        path.extension().is_some_and(|ext| ext == "rs"),
    ) {
        (true, _) => rust_sources(path, found),
        (false, true) => found.push(path.to_path_buf()),
        (false, false) => (),
    }
}

/// Every judgment source, enumerated from the tree and pinned to the declared
/// inventory so an added module is both scanned and visible.
fn gate_family(root: &Path) -> Box<[PathBuf]> {
    let tree = root.join(GATE_TREE);
    let mut enumerated = rust_source_tree(&tree).into_vec();
    enumerated.sort();
    let mut declared: Vec<PathBuf> = GATE_MODULES.iter().map(|name| tree.join(name)).collect();
    declared.sort();
    assert_eq!(
        enumerated,
        declared,
        "every module under {} is declared and scanned",
        tree.display()
    );
    enumerated.push(root.join(GATE_CONFIG_OWNER));
    enumerated.into_boxed_slice()
}

fn assert_absent(path: &Path, source: &str, forbidden: &[&str]) {
    let present: Box<[&str]> = forbidden
        .iter()
        .copied()
        .filter(|token| source.contains(token))
        .collect();
    assert!(
        present.is_empty(),
        "{} must not name {present:?}",
        path.display()
    );
}

/// Every public constructor and accessor, exercised once so the surface is a
/// compile-time contract rather than a documented intention.
fn exercise_public_surface() {
    let location = GateLocation::try_new("src/lib.rs", 4, 1).expect("a valid location");
    assert_eq!(
        (
            location.path(),
            location.line(),
            location.column(),
            location.anchor()
        ),
        ("src/lib.rs", 4, 1, GateAnchor::Span)
    );
    let whole_file = GateLocation::try_new_file("src/lib.rs").expect("a valid file location");
    assert_eq!(whole_file.anchor(), GateAnchor::File);

    let member = ModuleBoundaryEntity::try_new(1, "demo::a", Some(location.clone()))
        .expect("a valid entity");
    let partition = ModuleBoundaryEntity::try_new(10, "demo::left", None).expect("a valid entity");
    assert_eq!(
        (member.ordinal(), member.label(), member.location()),
        (1, "demo::a", Some(&location))
    );

    let second = ModuleBoundaryEntity::try_new(2, "demo::b", None).expect("a valid entity");
    let candidate = ModuleBoundaryEntity::try_new(11, "demo::right", None).expect("a valid entity");
    let component = ModuleBoundaryFact::component(
        true,
        entities([member.clone(), second]),
        entities([partition.clone(), candidate]),
    )
    .expect("a validated component row");
    let symbol =
        ModuleBoundaryFact::misplaced_symbol(member, partition.clone(), partition.clone(), 3, 4)
            .map(|_| ());
    assert!(symbol.is_err(), "equal partitions are rejected");
    let cohesion = ModuleBoundaryFact::low_module_cohesion(partition, 2, 3);
    assert!(matches!(
        cohesion.measurement(),
        ModuleBoundaryMeasurement::LowModuleCohesion { .. }
    ));

    let facts: Box<[ModuleBoundaryFact]> = Box::new([component, cohesion]);
    let input = ModuleBoundaryInput::try_new(".#lib:demo", facts).expect("a valid input");
    assert_eq!(input.target(), ".#lib:demo");
    assert_eq!(input.facts().len(), 2);

    let verdicts = evaluate_module_boundary_rules(&input, &GateConfig::default());
    let crossing = verdicts
        .iter()
        .find(|verdict| verdict.rule == "boundary-crossing-scc")
        .expect("the cross-partition cycle is judged");
    let evidence: &GateEvidence = gate_evidence(crossing);
    assert!(matches!(evidence, GateEvidence::ModuleBoundary(_)));
    let module_boundary: &ModuleBoundaryEvidence = evidence_of(crossing);
    assert_eq!(module_boundary.target(), ".#lib:demo");
    assert_eq!(module_boundary.subject().label(), "scc::demo::a");
    assert!(matches!(
        module_boundary.measurement(),
        ModuleBoundaryMeasurement::Component { .. }
    ));
    assert_eq!(
        all_module_boundary_rules()
            .iter()
            .map(|rule| rule.name)
            .collect::<Vec<_>>(),
        MODULE_BOUNDARY_RULE_NAMES,
        "the published listing names the catalog rules"
    );
}

/// The judgment library holds no topology, and the topology library holds no
/// policy, in both source and Cargo direction.
pub(crate) fn module_boundary_ownership_and_public_surface_are_exact() {
    exercise_public_surface();

    let root = manifest_dir();
    for path in &gate_family(&root) {
        assert_absent(path, &read(path), FORBIDDEN_IN_GATE);
    }

    let core_manifest = read(&root.join("Cargo.toml"));
    assert!(
        !core_manifest.contains("pedant-graph"),
        "pedant-core must not depend on pedant-graph"
    );

    let graph_root = root
        .parent()
        .expect("the workspace root is the manifest parent")
        .join("pedant-graph");
    let graph_sources = rust_source_tree(&graph_root.join("src"));
    assert!(
        graph_sources.len() > 1,
        "the graph production tree was located"
    );
    for path in &graph_sources {
        assert_absent(path, &read(path), FORBIDDEN_IN_GRAPH);
    }

    let graph_manifest = read(&graph_root.join("Cargo.toml"));
    let core_edges: Box<[&str]> = graph_manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("pedant-core = {"))
        .collect();
    assert!(!core_edges.is_empty(), "the graph consumes pedant-core");
    for edge in &core_edges {
        assert!(
            edge.contains("default-features = false"),
            "the graph takes pedant-core without its judgment surface: {edge}"
        );
    }
    assert!(
        !graph_manifest.contains("\"checks\""),
        "no graph edge or feature selects the judgment surface"
    );
}
