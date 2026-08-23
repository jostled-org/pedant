//! The Go graph's version-1 bytes, its determinism, and the queries it is read
//! through.
//!
//! Every case here reads the public boundary only: the compact JSON
//! `serde_json` produces, and the analysis view a caller opens over a graph it
//! was handed. Nothing is language-specific — that is the claim — so each case
//! ends by asking the retained Rust owners for their own answers again.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphAnalysisLimits, GraphDirection, GraphEdgeSelection, GraphNodeId,
};
use serde_json::Value;

use super::cache_exact;
use super::go_corpus::GO_CORPUS;
use super::go_fixture::{GoFixture, GoResolved, close_repository, project_go, projected};
use super::projection_exactness;
use super::wire::{
    CERTAINTIES, EDGE_KINDS, LOCATION_KINDS, NODE_CATEGORIES, ORIGIN_KINDS, REFERENCE_KINDS,
};

/// The ceilings every query in these cases is admitted under.
fn query_limits() -> GraphAnalysisLimits {
    GraphAnalysisLimits::new(100_000, 400_000, 8, 50_000_000)
}

/// The six keys a version-1 object states, in the order it states them.
const WIRE_KEYS: &[&str] = &[
    "schema_version",
    "tier",
    "nodes",
    "containment",
    "references",
    "edges",
];

/// One Go repository states one snapshot whatever order its files were written
/// in, and one snapshot states one set of graph bytes.
///
/// Two claims, and the first is what makes the second worth reading. The Go
/// discovery walk sorts every directory entry, so the order the corpus happened
/// to be written in is already gone by the time a projection sees anything.
/// That is asserted rather than assumed: without it the comparison below would
/// be the assembler called twice over one input and could not fail. What the
/// projection is then held to is that one snapshot, read twice, states one set
/// of version-1 bytes.
///
/// The fingerprint is not what answers the first claim, and must not be read as
/// though it were: it covers the canonical repository root, and two fixtures
/// are two temporary directories, so two snapshots of one corpus never share
/// one. What a projection reads is each package context's source membership and
/// each source's normalized path and exact bytes, and those already agree.
pub fn assert_go_graph_is_deterministic_and_rust_stays_exact() {
    let forward = GoFixture::build(GO_CORPUS);
    let reversed = GoFixture::written(GO_CORPUS.iter().rev().copied());
    let written = forward.resolve();
    let rewritten = reversed.resolve();
    close_repository(forward);
    close_repository(reversed);
    assert_eq!(
        snapshot_sources(&written),
        snapshot_sources(&rewritten),
        "both walks read the same sources, with the same bytes, in one order"
    );
    assert_eq!(
        instantiated_sources(&written),
        instantiated_sources(&rewritten),
        "both walks give every package context the same source membership"
    );

    let first = compact(&projected(&written));
    let again = compact(&projected(&written));
    let second = compact(&projected(&rewritten));
    assert_eq!(
        first, second,
        "one repository states one set of version-1 bytes"
    );
    assert_eq!(
        first, again,
        "the same snapshot projects the same bytes twice"
    );
    projection_exactness::assert_rust_projection_bytes_stay_exact();
}

/// Every source one Go snapshot holds, as the normalized path and the exact
/// bytes read at it, in the order the walk stored them.
fn snapshot_sources(resolved: &GoResolved) -> Vec<String> {
    resolved
        .snapshot
        .sources()
        .iter()
        .map(|source| format!("{}|{:02x?}", source.path(), source.digest()))
        .collect()
}

/// The sources each package context instantiates, in snapshot unit order.
fn instantiated_sources(resolved: &GoResolved) -> Vec<String> {
    resolved
        .snapshot
        .units()
        .iter()
        .map(|unit| {
            unit.sources()
                .iter()
                .map(|path| &**path)
                .collect::<Vec<&str>>()
                .join(",")
        })
        .collect()
}

/// A Go graph serializes to the version-1 object and to no new branch of it.
pub fn assert_go_graph_uses_schema_v1() {
    let (_resolved, graph) = project_go(GO_CORPUS);
    assert_eq!(graph.schema_version(), CodeGraph::SCHEMA_VERSION);
    assert_eq!(CodeGraph::SCHEMA_VERSION, 1, "the wire contract stays at 1");

    let bytes = compact(&graph);
    assert_eq!(
        outermost_keys(&bytes),
        WIRE_KEYS,
        "a version-1 object states six keys in one order"
    );
    let value: Value = serde_json::from_str(&bytes).expect("the graph serializes to JSON");
    assert_eq!(
        value.get("schema_version"),
        Some(&Value::from(1u32)),
        "the serialized version is the one this crate emits"
    );

    assert_tagged(&value, "/nodes/*/kind/category", NODE_CATEGORIES);
    assert_tagged(&value, "/nodes/*/location/kind", LOCATION_KINDS);
    assert_tagged(&value, "/references/*/kind", REFERENCE_KINDS);
    assert_tagged(&value, "/edges/*/kind", EDGE_KINDS);
    assert_tagged(&value, "/edges/*/certainty", CERTAINTIES);
    assert_tagged(&value, "/edges/*/origin/kind", ORIGIN_KINDS);
}

/// Every key the outermost object states, in the order the bytes state them.
///
/// Read from the bytes rather than from a parsed map: a map sorts its keys, and
/// what a version-1 consumer reads is the order the writer emitted.
fn outermost_keys(bytes: &str) -> Vec<&str> {
    let mut keys = Vec::new();
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut opened = None;
    for (at, character) in bytes.char_indices() {
        match (quoted, character) {
            (false, '{' | '[') => depth = depth.saturating_add(1),
            (false, '}' | ']') => depth = depth.saturating_sub(1),
            (false, '"') => {
                quoted = true;
                opened = Some(at.saturating_add(1));
            }
            (true, '"') => {
                quoted = false;
                keys.extend(outermost_key(bytes, (depth, opened, at)));
            }
            _ => (),
        }
    }
    keys
}

/// The key one closed string states, when it is a key of the outermost object.
fn outermost_key(bytes: &str, closed: (usize, Option<usize>, usize)) -> Option<&str> {
    let (depth, opened, at) = closed;
    let named = bytes.get(opened?..at)?;
    let follows = bytes.get(at.saturating_add(1)..at.saturating_add(2))?;
    match depth == 1 && follows == ":" {
        true => Some(named),
        false => None,
    }
}

/// Every value one slash-separated path selects is a tag this graph owns.
fn assert_tagged(value: &Value, path: &str, allowed: &[&str]) {
    let stated = selected(value, path);
    assert!(
        !stated.is_empty(),
        "{path} selects the values this case reads"
    );
    let unknown: Vec<&String> = stated
        .iter()
        .filter(|tag| !allowed.contains(&tag.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "{path} states only the tags the graph owns, not {unknown:?}"
    );
}

/// Every string one path selects, descending arrays through `*`.
fn selected(value: &Value, path: &str) -> BTreeSet<String> {
    let mut held = vec![value];
    for step in path.split('/').filter(|step| !step.is_empty()) {
        held = held
            .into_iter()
            .flat_map(|value| descend(value, step))
            .collect();
    }
    held.into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// The values one step of a path selects.
fn descend<'value>(value: &'value Value, step: &str) -> Vec<&'value Value> {
    match step {
        "*" => value.as_array().map(|held| held.iter().collect()),
        key => value.get(key).map(|held| vec![held]),
    }
    .unwrap_or_default()
}

/// Every existing query answers over a Go graph with no language dispatch, and
/// the retained Rust cache answers are unchanged.
pub fn assert_existing_queries_consume_a_go_graph() {
    let (_resolved, graph) = project_go(GO_CORPUS);
    let analysis = GraphAnalysis::new(&graph, GraphEdgeSelection::code_relations(), query_limits())
        .unwrap_or_else(|error| panic!("a Go graph opens one analysis: {error}"));

    let roots = analysis.declared_partition().roots().to_vec();
    assert!(
        !roots.is_empty(),
        "the declared partition finds the containers a Go graph states"
    );
    let start = roots[0];
    let subgraph = analysis
        .subgraph(start, 0, GraphDirection::Outgoing)
        .unwrap_or_else(|error| panic!("a Go graph answers an induced subgraph: {error}"));
    assert_eq!(
        subgraph.nodes(),
        &[start],
        "the induced subgraph reached in no steps is the seed alone"
    );

    let reaching = reaching_node(&graph);
    let neighbors = analysis
        .neighbors(reaching, 3, GraphDirection::Outgoing)
        .unwrap_or_else(|error| panic!("a Go graph answers a bounded neighborhood: {error}"));
    assert!(
        neighbors.iter().next().is_some(),
        "a Go graph answers a non-empty neighborhood"
    );

    let components = analysis.strongly_connected_components();
    assert!(
        !components.components().is_empty(),
        "a Go graph condenses into components"
    );
    let condensation = analysis.condensation();
    assert_eq!(
        condensation.topological_order().len(),
        components.components().len(),
        "every component takes one place in the condensation order"
    );
    let divergence = analysis.divergence();
    assert!(
        !divergence.cohesion().is_empty(),
        "a Go graph's declared partition carries cohesion evidence"
    );
    let layout = analysis
        .layout_assist()
        .unwrap_or_else(|error| panic!("a Go graph is described for a renderer: {error}"));
    assert_eq!(
        layout.nodes().len(),
        graph.nodes().len(),
        "layout metadata describes every node once"
    );
    assert_eq!(
        layout.edges().len(),
        graph
            .edges()
            .iter()
            .filter(|edge| GraphEdgeSelection::code_relations().allows(edge))
            .count(),
        "layout metadata describes every admitted edge once"
    );
    for reached in neighbors.iter() {
        assert!(
            analysis.path(reaching, reached.node()).is_ok(),
            "every reached node is reachable by the path query too"
        );
    }
    cache_exact::assert_exact_build_matches_direct();
}

/// The first node this selection gives an outgoing edge.
///
/// The bounded walk is seeded from here rather than from a declared-partition
/// root. A root is a container, and a container states no code relation of its
/// own — the one edge two containers can share is a dependency, which this
/// selection excludes. A walk from a root therefore reaches nothing at all, and
/// every claim about what it found would hold over an empty answer.
fn reaching_node(graph: &CodeGraph) -> GraphNodeId {
    graph
        .edges()
        .iter()
        .find(|edge| GraphEdgeSelection::code_relations().allows(edge))
        .map(|edge| edge.source())
        .unwrap_or_else(|| panic!("the corpus states an edge this selection admits"))
}

/// The compact version-1 bytes one graph serializes to.
fn compact(graph: &CodeGraph) -> String {
    serde_json::to_string(graph).expect("a graph serializes")
}
