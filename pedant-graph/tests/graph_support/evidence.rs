//! Reference records, candidate edges, and Cargo dependency evidence.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{CodeGraph, GraphCertainty, GraphEdgeKind, GraphEdgeOrigin, GraphReferenceKind};
use pedant_types::{ReferenceKind, ResolutionCertainty, ResolutionReport};

use super::fixture;
use super::render;

/// The exact graph reference kind and candidate edge kind every consumed Rust
/// reference kind takes.
const EXPECTED_KIND_MAPPING: &[&str] = &[
    "Call|Call|Call",
    "Implementation|Implementation|Implementation",
    "Import|Import|Import",
    "Module|Reference|Reference",
    "Type|Reference|Reference",
];

/// Every dependency edge the corpus produces, exactly.
const EXPECTED_CORPUS_DEPENDENCIES: &[&str] = &[
    "app>gated|DependsOn|Possible|dependency:gated:Normal:cfg(unix)",
    "app>helper|DependsOn|Resolved|dependency:helper:Normal:-",
    "app>harness|DependsOn|Possible|dependency:harness:Development:cfg(test)",
];

/// Every dependency edge the build-script corpus produces, exactly.
const EXPECTED_BUILD_DEPENDENCIES: &[&str] =
    &["build_script_build>builder|DependsOn|Resolved|dependency:builder:Build:-"];

/// Every report reference produces one record whose source follows the
/// enclosing-definition rule, and a candidate-free record keeps its gaps.
pub fn assert_references_are_retained() {
    let (_fixture, resolved, graph) = fixture::project_corpus_library();
    let report = resolved.resolution.report();

    assert_eq!(
        graph.references().len(),
        report.references().len(),
        "every report reference produces exactly one graph reference"
    );

    let files = file_nodes(&graph);
    let definitions = definition_nodes(&graph, report);
    let mut enclosed = 0;
    let mut top_level = 0;
    for (record, reference) in graph.references().iter().zip(report.references()) {
        match reference.enclosing_definition() {
            Some(enclosing) => {
                enclosed += 1;
                assert_eq!(
                    Some(record.source()),
                    definitions.get(&enclosing.index()).copied(),
                    "an enclosed reference starts at its enclosing definition node"
                );
            }
            None => {
                top_level += 1;
                assert_eq!(
                    Some(record.source()),
                    files.get(reference.span().file()).copied(),
                    "a top-level reference starts at its unit-qualified file node"
                );
            }
        }
    }
    assert!(
        enclosed > 0 && top_level > 0,
        "the corpus must state both enclosed and top-level references"
    );

    let candidate_free: Vec<String> = graph
        .references()
        .iter()
        .filter(|record| record.edges().is_empty())
        .map(render::reference)
        .collect();
    assert_eq!(
        candidate_free,
        [
            "2|11|Rust|Reference|u32|src/lib.rs:4:17-4:20|ExternalDefinition|-",
            "3|12|Rust|Reference|str|src/lib.rs:6:18-6:21|ExternalDefinition|-",
            "4|15|Rust|Reference|u32|src/lib.rs:15:9-15:12|ExternalDefinition|-",
            "5|17|Rust|Reference|Self|src/lib.rs:19:13-19:17|ExternalDefinition|-",
        ],
        "a candidate-free record keeps its site, its language, and its gaps"
    );
}

/// Every candidate produces one edge that keeps its certainty and links back to
/// the record that produced it, and no edge exists without evidence.
pub fn assert_candidate_edges_retain_evidence() {
    let (_fixture, resolved, graph) = fixture::project_corpus_library();
    let report = resolved.resolution.report();

    let candidates = assert_candidates_produce_one_edge_each(&graph, report);
    assert_candidate_edges_name_their_evidence(&graph, report);
    assert_dependency_edges_complete_the_partition(
        &graph,
        (candidates, resolved.snapshot.edges().len()),
    );
}

/// How many candidates the report states, proved equal to the reference-origin
/// edges the graph holds.
fn assert_candidates_produce_one_edge_each(graph: &CodeGraph, report: &ResolutionReport) -> usize {
    let candidates: usize = report
        .resolutions()
        .iter()
        .map(|record| record.candidates().len())
        .sum();
    let reference_edges = graph
        .edges()
        .iter()
        .filter(|edge| matches!(edge.origin(), GraphEdgeOrigin::Reference { .. }))
        .count();
    assert!(
        candidates > 0,
        "the corpus must state at least one resolution candidate"
    );
    assert_eq!(
        reference_edges, candidates,
        "every resolution candidate produces exactly one graph edge"
    );
    candidates
}

/// Every record keeps one edge per candidate, and each edge keeps the site it
/// starts at, the definition it names, its certainty, and its record.
fn assert_candidate_edges_name_their_evidence(graph: &CodeGraph, report: &ResolutionReport) {
    let definitions = definition_nodes(graph, report);
    assert_eq!(
        graph.references().len(),
        report.resolutions().len(),
        "every record is paired with the answer that produced it"
    );
    for (record, source) in graph.references().iter().zip(report.resolutions()) {
        assert_eq!(
            record.edges().len(),
            source.candidates().len(),
            "record {} keeps one edge per candidate",
            record.id().index()
        );
        for (produced, candidate) in record.edges().iter().zip(source.candidates()) {
            let edge = graph
                .edge(*produced)
                .unwrap_or_else(|| panic!("edge {} exists", produced.index()));
            assert_eq!(
                edge.source(),
                record.source(),
                "a candidate edge starts where its record does"
            );
            assert_eq!(
                Some(edge.target()),
                definitions.get(&candidate.definition().index()).copied(),
                "a candidate edge ends at the definition it names"
            );
            assert_eq!(
                edge.certainty(),
                expected_certainty(candidate.certainty()),
                "a candidate edge keeps its exact certainty"
            );
            assert_eq!(
                edge.origin(),
                &GraphEdgeOrigin::Reference {
                    reference: record.id()
                },
                "a candidate edge links back to its record"
            );
        }
    }
}

/// The dependency edges answer the snapshot's Cargo edges, and the two origins
/// account for every edge the graph holds.
///
/// Each count is held to the input that produced it rather than to the other
/// count: the two origins partition every edge whatever the projection did, so
/// a dropped or invented edge balances the partition and fails here.
fn assert_dependency_edges_complete_the_partition(graph: &CodeGraph, stated: (usize, usize)) {
    let (candidates, snapshot_edges) = stated;
    let dependencies = graph
        .edges()
        .iter()
        .filter(|edge| matches!(edge.origin(), GraphEdgeOrigin::Dependency { .. }))
        .count();
    assert!(
        dependencies > 0,
        "the corpus must state at least one Cargo dependency edge"
    );
    assert_eq!(
        dependencies, snapshot_edges,
        "every dependency edge answers one snapshot Cargo edge"
    );
    assert_eq!(
        graph.edges().len(),
        candidates + snapshot_edges,
        "the graph holds one edge per stated candidate and per snapshot Cargo edge"
    );
}

/// All five consumed Rust reference kinds map to their exact graph reference
/// kind, and each mapped candidate edge takes the corresponding edge kind.
pub fn assert_reference_kinds_map_exactly() {
    let (_fixture, resolved, graph) = fixture::project_corpus_library();
    let report = resolved.resolution.report();

    let stated: BTreeSet<ReferenceKind> = report
        .references()
        .iter()
        .map(|reference| reference.kind())
        .collect();
    assert_eq!(
        stated.len(),
        5,
        "the corpus must state all five reference kinds, found {stated:?}"
    );

    let mut observed: BTreeSet<String> = BTreeSet::new();
    assert_eq!(
        graph.references().len(),
        report.references().len(),
        "every record is paired with the reference it was projected from"
    );
    for (record, reference) in graph.references().iter().zip(report.references()) {
        for produced in record.edges() {
            let edge = graph
                .edge(*produced)
                .unwrap_or_else(|| panic!("edge {} exists", produced.index()));
            observed.insert(format!(
                "{:?}|{:?}|{:?}",
                reference.kind(),
                record.kind(),
                edge.kind()
            ));
        }
    }
    assert_eq!(
        observed.iter().map(String::as_str).collect::<Vec<&str>>(),
        EXPECTED_KIND_MAPPING,
        "the reference and candidate edge mapping changed"
    );
    assert_eq!(
        graph
            .references()
            .iter()
            .filter(|record| record.kind() == GraphReferenceKind::Reference)
            .count(),
        report
            .references()
            .iter()
            .filter(|reference| matches!(
                reference.kind(),
                ReferenceKind::Module | ReferenceKind::Type
            ))
            .count(),
        "module and type references become general graph references"
    );
}

/// Every snapshot Cargo edge produces one `DependsOn` edge between unit
/// containers, retaining its alias, kind, activation, and predicate.
pub fn assert_dependency_evidence_is_preserved() {
    let (_corpus, resolved, graph) = fixture::project_corpus_library();
    assert_eq!(
        dependency_lines(&graph),
        EXPECTED_CORPUS_DEPENDENCIES,
        "normal, development, always-active, and conditional evidence is retained"
    );
    assert_eq!(
        graph
            .edges()
            .iter()
            .filter(|edge| edge.kind() == GraphEdgeKind::DependsOn)
            .count(),
        resolved.snapshot.edges().len(),
        "each snapshot Cargo edge produces exactly one DependsOn edge"
    );

    let (_build, _script, build_graph) = fixture::project_build_script();
    assert_eq!(
        dependency_lines(&build_graph),
        EXPECTED_BUILD_DEPENDENCIES,
        "a build dependency keeps its own table"
    );
}

/// Every dependency edge as `sourceName>targetName|kind|certainty|origin`.
fn dependency_lines(graph: &CodeGraph) -> Vec<String> {
    graph
        .edges()
        .iter()
        .filter(|edge| edge.kind() == GraphEdgeKind::DependsOn)
        .map(|edge| {
            format!(
                "{}>{}|{:?}|{:?}|{}",
                container_name(graph, edge.source()),
                container_name(graph, edge.target()),
                edge.kind(),
                edge.certainty(),
                render::origin(edge.origin()),
            )
        })
        .collect()
}

fn container_name(graph: &CodeGraph, node: pedant_graph::GraphNodeId) -> String {
    let found = graph
        .node(node)
        .unwrap_or_else(|| panic!("node {} exists", node.index()));
    assert!(
        found.location().is_none(),
        "a dependency edge joins unit containers, not {}",
        found.name()
    );
    found.name().to_owned()
}

fn expected_certainty(certainty: ResolutionCertainty) -> GraphCertainty {
    match certainty {
        ResolutionCertainty::Resolved => GraphCertainty::Resolved,
        ResolutionCertainty::Possible => GraphCertainty::Possible,
    }
}

/// Every unit-qualified file node, keyed by its normalized path.
///
/// The corpus binds one unit per path, so one entry per path is exact here.
fn file_nodes(graph: &CodeGraph) -> BTreeMap<&str, pedant_graph::GraphNodeId> {
    graph
        .nodes()
        .iter()
        .filter_map(|node| render::file_path(node).map(|path| (path, node.id())))
        .collect()
}

/// Every definition node, keyed by the report definition that produced it.
///
/// The key is the definition's own report identifier, taken by pairing the
/// span-located nodes with the definitions in order. The two sequences are held
/// to one length first, because a pairing by enumeration position alone would
/// answer for definitions the graph never projected.
fn definition_nodes(
    graph: &CodeGraph,
    report: &ResolutionReport,
) -> BTreeMap<u32, pedant_graph::GraphNodeId> {
    let projected: Vec<pedant_graph::GraphNodeId> = graph
        .nodes()
        .iter()
        .filter(|node| render::is_definition(node))
        .map(|node| node.id())
        .collect();
    assert_eq!(
        projected.len(),
        report.definitions().len(),
        "every report definition produces exactly one span-located node"
    );
    report
        .definitions()
        .iter()
        .zip(projected)
        .map(|(definition, node)| (definition.id().index(), node))
        .collect()
}
