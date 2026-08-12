//! Node inventory, unit-qualified source association, and the containment
//! forest.

use std::collections::{BTreeMap, BTreeSet};

use pedant_core::resolution::rust::CargoTargetKind;
use pedant_graph::{CodeGraph, GraphNodeId, GraphNodeKind, GraphNodeLocation};

use super::corpus::{SHARED_SOURCE_CORPUS, TARGET_KIND_CORPUS};
use super::fixture;
use super::render;

/// The container level every remaining Cargo target kind states, beside the
/// target the kind corpus declares for it.
///
/// Library, binary, and build-script levels are pinned by the unit inventory
/// and the serialized build-script graph; these three are reachable from no
/// other corpus, so a copy-paste in the level table would otherwise make two
/// target kinds one indistinguishable container.
const EXPECTED_TARGET_LEVELS: &[(CargoTargetKind, &str, &str)] = &[
    (CargoTargetKind::Example, "demo", "container:example"),
    (CargoTargetKind::Test, "case", "container:test"),
    (CargoTargetKind::Benchmark, "measure", "container:benchmark"),
];

/// The exact graph category and attribute every Rust symbol kind takes.
const EXPECTED_DEFINITION_KINDS: &[&str] = &[
    "plain|function:function",
    "alpha|container:module",
    "LIMIT|value:constant",
    "NAME|value:static",
    "Root|type:struct",
    "Mode|type:enum",
    "Bits|type:union",
    "Shape|type:trait",
    "area|function:method",
    "Alias|type:type_alias",
    "area|function:method",
    "make|function:function",
    "tick|function:method",
    "inner|container:module",
    "nested|function:function",
    "run|function:function",
    "gate|function:function",
    "check|function:function",
    "assist|function:function",
];

/// Every container and file node the shared-source corpus produces, with the
/// unit container that owns it.
///
/// The container level is the unit's Cargo target kind, so a package's binary
/// and its library remain distinguishable when both carry the crate name.
const EXPECTED_UNIT_INVENTORY: &[&str] = &[
    "0|Rust|tool|container:binary|-",
    "1|Rust|app|container:library|-",
    "2|Rust|src/common.rs|file|file:src/common.rs|owner=0",
    "3|Rust|src/main.rs|file|file:src/main.rs|owner=0",
    "4|Rust|src/common.rs|file|file:src/common.rs|owner=1",
    "5|Rust|src/lib.rs|file|file:src/lib.rs|owner=1",
];

/// One container per report unit, and one file node per source that unit
/// instantiates, even when two units read one normalized path.
pub fn assert_unit_roots_and_shared_sources() {
    let (_fixture, _resolved, graph) = fixture::project_target(
        SHARED_SOURCE_CORPUS,
        ("app", CargoTargetKind::Binary, "tool"),
    );

    let owners = containment_parents(&graph);
    let inventory: Vec<String> = graph
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.kind(),
                GraphNodeKind::File | GraphNodeKind::Container { .. }
            ) && (node.location().is_none() || render::is_file(node))
        })
        .map(|node| match node.location() {
            None => render::node(node),
            Some(_) => format!(
                "{}|owner={}",
                render::node(node),
                owners
                    .get(&node.id())
                    .map(|parent| parent.index().to_string())
                    .unwrap_or_else(|| "-".to_owned()),
            ),
        })
        .collect();
    assert_eq!(
        inventory, EXPECTED_UNIT_INVENTORY,
        "each unit owns one target-levelled container and its own file node per source"
    );

    let shared = graph
        .nodes()
        .iter()
        .filter(|node| node.name() == "src/common.rs")
        .count();
    assert_eq!(
        shared, 2,
        "one physical source read by two units produces two file nodes"
    );

    assert_target_levels();
}

/// Every remaining Cargo target kind states its own container level.
fn assert_target_levels() {
    for (kind, name, level) in EXPECTED_TARGET_LEVELS {
        let (_fixture, _resolved, graph) =
            fixture::project_target(TARGET_KIND_CORPUS, ("app", *kind, name));
        let root = graph
            .nodes()
            .iter()
            .find(|node| node.location().is_none() && node.name() == *name)
            .unwrap_or_else(|| panic!("the {kind:?} corpus states no container named {name}"));
        assert_eq!(
            render::node_kind(root.kind()),
            *level,
            "the {kind:?} root container states its own level"
        );
    }
}

/// Every report definition produces one node, and the ten Rust symbol kinds
/// take exactly the specified categories and attributes.
pub fn assert_symbol_kinds_map_once() {
    let (_fixture, resolved, graph) = fixture::project_corpus_library();
    let report = resolved.resolution.report();

    let kinds: BTreeSet<String> = report
        .definitions()
        .iter()
        .map(|definition| format!("{:?}", definition.kind()))
        .collect();
    assert_eq!(
        kinds.len(),
        10,
        "the corpus must state every Rust symbol kind, found {kinds:?}"
    );

    let definitions: Vec<String> = graph
        .nodes()
        .iter()
        .filter(|node| render::is_definition(node))
        .map(|node| format!("{}|{}", node.name(), render::node_kind(node.kind())))
        .collect();
    assert_eq!(
        definitions.len(),
        report.definitions().len(),
        "every report definition produces exactly one node"
    );
    assert_eq!(
        definitions, EXPECTED_DEFINITION_KINDS,
        "the Rust declaration table changed"
    );
}

/// Containment is one unit-local forest, and it never leaks into the edges.
pub fn assert_containment_is_a_unit_local_forest() {
    let (_fixture, _resolved, graph) = fixture::project_corpus_library();

    let parents = containment_parents(&graph);
    let roots: BTreeSet<GraphNodeId> = graph
        .nodes()
        .iter()
        .filter(|node| node.location().is_none())
        .map(|node| node.id())
        .collect();
    assert_eq!(roots.len(), 4, "each report unit contributes one root");
    assert_eq!(
        graph.containment().len(),
        graph.nodes().len() - roots.len(),
        "every non-root node has exactly one containment parent"
    );
    for node in graph.nodes() {
        assert_eq!(
            parents.contains_key(&node.id()),
            !roots.contains(&node.id()),
            "node {} is parented exactly when it is not a unit root",
            node.id().index()
        );
    }

    let owners = unit_owners(&graph, &parents, &roots);
    for edge in graph.containment() {
        assert_eq!(
            owners.get(&edge.parent()),
            owners.get(&edge.child()),
            "containment edge {}>{} crosses units",
            edge.parent().index(),
            edge.child().index()
        );
    }
    assert_eq!(
        owners.values().copied().collect::<BTreeSet<GraphNodeId>>(),
        roots,
        "the unit roots are exactly the owners the containment walk reaches"
    );

    assert!(
        graph
            .containment()
            .iter()
            .map(|edge| edge.child().index())
            .is_sorted(),
        "containment edges are sorted by child"
    );

    assert_containment_stays_out_of_edges(&graph);
}

/// No pair the containment forest states appears among the graph's edges.
///
/// Both relations are collected whole and compared as sets, because the claim
/// is about the relation rather than about one edge kind: a projection that
/// pushed a containment pair into `CodeGraph::edges` under any kind is what
/// this must reject.
fn assert_containment_stays_out_of_edges(graph: &CodeGraph) {
    let contained: BTreeSet<(u32, u32)> = graph
        .containment()
        .iter()
        .map(|edge| (edge.parent().index(), edge.child().index()))
        .collect();
    let joined: BTreeSet<(u32, u32)> = graph
        .edges()
        .iter()
        .map(|edge| (edge.source().index(), edge.target().index()))
        .collect();
    assert!(
        !contained.is_empty() && !joined.is_empty(),
        "the corpus must state both containment ({}) and edges ({})",
        contained.len(),
        joined.len()
    );
    let shared: Vec<(u32, u32)> = contained.intersection(&joined).copied().collect();
    assert!(
        shared.is_empty(),
        "containment never appears in the reference and dependency edges: {shared:?}"
    );
}

/// Logical parentage follows report parents; source location follows spans.
pub fn assert_parentage_is_separate_from_location() {
    let (_fixture, _resolved, graph) = fixture::project_corpus_library();
    let parents = containment_parents(&graph);

    let external = node_named(&graph, "plain");
    let module = node_named(&graph, "alpha");
    assert_eq!(
        parents.get(&external),
        Some(&module),
        "an external module's item is owned by the module that declares it"
    );
    assert_ne!(
        span_file(&graph, external),
        span_file(&graph, module),
        "that item's bytes sit in another source than its logical parent's"
    );
    assert_eq!(
        graph
            .node(span_file(&graph, external))
            .map(|node| node.name().to_owned()),
        Some("src/alpha.rs".to_owned()),
        "the item's span identifies its own unit-qualified file node"
    );

    let inline = node_named(&graph, "nested");
    let inline_parent = node_named(&graph, "inner");
    assert_eq!(
        parents.get(&inline),
        Some(&inline_parent),
        "an inline module's item is owned by that module"
    );
    assert_eq!(
        span_file(&graph, inline),
        span_file(&graph, inline_parent),
        "an inline module's item shares its parent's source"
    );
    assert_ne!(
        parents.get(&inline),
        Some(&span_file(&graph, inline)),
        "a file node is never a containment parent of a definition"
    );
}

/// Each node's containment parent, keyed by child.
pub fn containment_parents(graph: &CodeGraph) -> BTreeMap<GraphNodeId, GraphNodeId> {
    graph
        .containment()
        .iter()
        .map(|edge| (edge.child(), edge.parent()))
        .collect()
}

/// The unit root each node is reachable from.
fn unit_owners(
    graph: &CodeGraph,
    parents: &BTreeMap<GraphNodeId, GraphNodeId>,
    roots: &BTreeSet<GraphNodeId>,
) -> BTreeMap<GraphNodeId, GraphNodeId> {
    let mut owners = BTreeMap::new();
    for node in graph.nodes() {
        let mut current = node.id();
        let mut steps = 0;
        while !roots.contains(&current) {
            current = *parents
                .get(&current)
                .unwrap_or_else(|| panic!("node {} reaches no unit root", node.id().index()));
            steps += 1;
            assert!(steps <= graph.nodes().len(), "containment is cyclic");
        }
        owners.insert(node.id(), current);
    }
    owners
}

fn node_named(graph: &CodeGraph, name: &str) -> GraphNodeId {
    let found: Vec<GraphNodeId> = graph
        .nodes()
        .iter()
        .filter(|node| node.name() == name && render::is_definition(node))
        .map(|node| node.id())
        .collect();
    match found.as_slice() {
        [only] => *only,
        other => panic!(
            "the corpus declares {} definitions named {name}",
            other.len()
        ),
    }
}

fn span_file(graph: &CodeGraph, node: GraphNodeId) -> GraphNodeId {
    match graph.node(node).and_then(|found| found.location()) {
        Some(GraphNodeLocation::Span { file, .. }) => *file,
        other => panic!("node {} has no span location: {other:?}", node.index()),
    }
}
