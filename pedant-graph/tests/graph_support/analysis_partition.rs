//! The declared module partition: nearest containing container, never source
//! association.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{
    CodeGraph, DeclaredModulePartition, GraphEdgeSelection, GraphNodeId, GraphNodeKind,
};

use super::analysis_fixture as given;

/// Every node of the nested-module corpus beside the container that owns it.
///
/// Written from the corpus source: `outer` and `inner` nest inside
/// `src/lib.rs`, `nested` nests inside `src/detached.rs`, and both file nodes
/// belong to the unit root that instantiates them rather than to the modules
/// whose bytes they hold.
const EXPECTED_OWNERS: &[(&str, &str)] = &[
    ("app", "app"),
    ("src/lib.rs", "app"),
    ("src/detached.rs", "app"),
    ("top", "app"),
    ("outer", "outer"),
    ("shallow", "outer"),
    ("inner", "inner"),
    ("deep", "inner"),
    ("detached", "detached"),
    ("away", "detached"),
    ("nested", "nested"),
    ("far", "nested"),
];

/// Every partition root beside the members it owns, named in sorted order.
///
/// Written from the corpus nesting: the unit root owns both files and the
/// top-level function it instantiates, and each module owns itself and the
/// definitions declared inside it until the next module begins. Which member a
/// root lists first is decided by the identities the builder mints, so the
/// members are stated as a set here and their node-id order is proved as a
/// property instead.
const EXPECTED_MEMBERS: &[(&str, &[&str])] = &[
    ("app", &["app", "src/detached.rs", "src/lib.rs", "top"]),
    ("outer", &["outer", "shallow"]),
    ("inner", &["deep", "inner"]),
    ("detached", &["away", "detached"]),
    ("nested", &["far", "nested"]),
];

/// Nodes whose bytes sit in one source while their owner is declared in
/// another, as `node|source|owner`.
const EXPECTED_CONTRARY_SOURCES: &[&str] = &[
    "deep|src/lib.rs|inner",
    "away|src/detached.rs|detached",
    "far|src/detached.rs|nested",
];

/// Every node belongs to its nearest containing container, containers own
/// themselves, and no file's source association reassigns anything.
pub fn assert_partition_follows_nearest_container() {
    let graph = given::partition_graph();
    let analysis = given::analysis(&graph, GraphEdgeSelection::code_relations());
    let partition = analysis.declared_partition();

    let owners: BTreeMap<String, String> = graph
        .nodes()
        .iter()
        .map(|node| {
            let owner = partition
                .owner(node.id())
                .unwrap_or_else(|| panic!("{} belongs to no partition", node.name()));
            (node.name().to_owned(), given::name(&graph, owner))
        })
        .collect();
    assert_eq!(
        owners,
        EXPECTED_OWNERS
            .iter()
            .map(|(node, owner)| ((*node).to_owned(), (*owner).to_owned()))
            .collect::<BTreeMap<String, String>>(),
        "each node's owner is the nearest container above it"
    );

    assert_roots_are_every_container(&graph, partition.roots());
    assert_members_cover_every_node(&graph, partition);
    assert_foreign_identities_belong_nowhere(&graph, partition);
    assert_source_association_never_reassigns(&graph);
}

/// The partition roots are exactly the container nodes, in node id order.
fn assert_roots_are_every_container(graph: &CodeGraph, roots: &[GraphNodeId]) {
    assert!(
        roots.windows(2).all(|pair| pair[0] < pair[1]),
        "partition roots rise strictly, so each container is a root once"
    );
    let declared: Vec<GraphNodeId> = graph
        .nodes()
        .iter()
        .filter(|node| matches!(node.kind(), GraphNodeKind::Container { .. }))
        .map(|node| node.id())
        .collect();
    assert_eq!(
        roots,
        declared.as_slice(),
        "every container is a root and nothing else is: {:?}",
        given::names(graph, roots)
    );
}

/// Every node is a member of exactly one root, and each root's members are its
/// own subtree in node id order.
fn assert_members_cover_every_node(graph: &CodeGraph, partition: &DeclaredModulePartition) {
    let mut seen: BTreeSet<GraphNodeId> = BTreeSet::new();
    let mut members: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for root in partition.roots() {
        let held = partition
            .members(*root)
            .unwrap_or_else(|| panic!("{} is a root with no members", given::name(graph, *root)));
        assert!(
            held.windows(2).all(|pair| pair[0] < pair[1]),
            "{}: members rise strictly, so each is listed once, in node id order",
            given::name(graph, *root)
        );
        for node in held {
            assert!(
                seen.insert(*node),
                "{} is a member of two partitions",
                given::name(graph, *node)
            );
        }
        let mut named = given::names(graph, held);
        named.sort();
        members.insert(given::name(graph, *root), named);
    }
    assert_eq!(
        seen.len(),
        graph.nodes().len(),
        "every node is a member of exactly one partition"
    );
    assert_eq!(
        members,
        EXPECTED_MEMBERS
            .iter()
            .map(|(root, held)| (
                (*root).to_owned(),
                held.iter().map(|name| (*name).to_owned()).collect()
            ))
            .collect::<BTreeMap<String, Vec<String>>>(),
        "each container owns itself and its descendants until another begins"
    );
}

/// A node this graph holds no record for owns nothing and belongs to nothing.
fn assert_foreign_identities_belong_nowhere(
    graph: &CodeGraph,
    partition: &DeclaredModulePartition,
) {
    let foreign = given::foreign_node(graph);
    assert!(
        partition.owner(foreign).is_none() && partition.members(foreign).is_none(),
        "an identity from another graph belongs to no partition here"
    );
    assert!(
        partition.members(given::definition(graph, "top")).is_none(),
        "a node that is not a container owns no members"
    );
}

/// The source a node's bytes sit in is never the container that owns it.
fn assert_source_association_never_reassigns(graph: &CodeGraph) {
    let analysis = given::analysis(graph, GraphEdgeSelection::code_relations());
    let partition = analysis.declared_partition();
    let contrary: Vec<String> = ["deep", "away", "far"]
        .iter()
        .map(|name| {
            let node = given::definition(graph, name);
            let owner = partition
                .owner(node)
                .unwrap_or_else(|| panic!("{name} belongs to no partition"));
            format!(
                "{name}|{}|{}",
                given::name(graph, given::span_file(graph, node)),
                given::name(graph, owner)
            )
        })
        .collect();
    assert_eq!(
        contrary, EXPECTED_CONTRARY_SOURCES,
        "logical ownership follows containment while the span follows the bytes"
    );
    assert_eq!(
        partition.owner(given::file_node(graph, "src/detached.rs")),
        Some(given::unit_root(graph)),
        "a file node follows containment into its unit root"
    );
}
