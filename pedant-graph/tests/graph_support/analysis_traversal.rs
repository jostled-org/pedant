//! Bounded neighborhoods, shortest paths, and induced subgraph selections over
//! one shared analysis view.
//!
//! Every case reads the diamond-with-a-cycle call corpus, whose selected `Call`
//! topology is small enough to state by hand: `seed` calls `left` twice and
//! `right` once, both arms call `sink`, `sink` calls `seed`, `wheel` calls
//! itself, `stranded` is isolated, and `user` calls `part::helper`.

use pedant_graph::{
    CodeGraph, ContainmentEdge, GraphAnalysis, GraphAnalysisError, GraphAnalysisLimits,
    GraphDirection, GraphEdgeId, GraphEdgeSelection, GraphNodeId,
};

use super::analysis_fixture as given;

/// One neighborhood request and the `name:distance` answers it must produce.
struct NeighborCase {
    label: &'static str,
    seed: &'static str,
    depth: u32,
    direction: GraphDirection,
    expected: &'static [&'static str],
}

/// Reachable nodes come back once, at their minimum distance, in distance then
/// node order, for every direction.
pub fn assert_neighbors_are_bounded_directed_and_ordered() {
    let graph = given::traversal_graph();
    let analysis = given::analysis(&graph, given::calls_only());
    for case in NEIGHBOR_CASES {
        let seed = given::definition(&graph, case.seed);
        let reached = analysis
            .neighbors(seed, case.depth, case.direction)
            .unwrap_or_else(|error| panic!("{}: {error}", case.label));
        assert_eq!(
            given::neighbor_texts(&graph, &reached),
            case.expected,
            "{}",
            case.label
        );
    }
}

/// Every neighborhood the call corpus states, hand-written from its source.
const NEIGHBOR_CASES: &[NeighborCase] = &[
    NeighborCase {
        label: "parallel calls reach one node once",
        seed: "seed",
        depth: 1,
        direction: GraphDirection::Outgoing,
        expected: &["left:1", "right:1"],
    },
    NeighborCase {
        label: "a diamond meets at its minimum distance",
        seed: "seed",
        depth: 2,
        direction: GraphDirection::Outgoing,
        expected: &["left:1", "right:1", "sink:2"],
    },
    NeighborCase {
        label: "a cycle never returns the seed",
        seed: "seed",
        depth: 5,
        direction: GraphDirection::Outgoing,
        expected: &["left:1", "right:1", "sink:2"],
    },
    NeighborCase {
        label: "depth zero reaches nothing",
        seed: "seed",
        depth: 0,
        direction: GraphDirection::Outgoing,
        expected: &[],
    },
    NeighborCase {
        label: "the cycle continues past the seed",
        seed: "sink",
        depth: 2,
        direction: GraphDirection::Outgoing,
        expected: &["seed:1", "left:2", "right:2"],
    },
    NeighborCase {
        label: "incoming walks the arrows backwards",
        seed: "seed",
        depth: 2,
        direction: GraphDirection::Incoming,
        expected: &["sink:1", "left:2", "right:2"],
    },
    NeighborCase {
        label: "both directions shorten the cycle",
        seed: "seed",
        depth: 3,
        direction: GraphDirection::Both,
        expected: &["left:1", "right:1", "sink:1"],
    },
    NeighborCase {
        label: "a self-loop reaches only the seed",
        seed: "wheel",
        depth: 3,
        direction: GraphDirection::Both,
        expected: &[],
    },
    NeighborCase {
        label: "an isolated definition reaches nothing",
        seed: "stranded",
        depth: 3,
        direction: GraphDirection::Both,
        expected: &[],
    },
];

/// Every path the call corpus states, hand-written from its source, as a
/// label, a source, a target, and the route the answer must walk.
const PATH_CASES: &[(&str, &str, &str, &[&str])] = &[
    (
        "a tied diamond takes the least edge sequence",
        "seed",
        "sink",
        &["seed", "left", "sink"],
    ),
    (
        "one selected edge is one step",
        "seed",
        "left",
        &["seed", "left"],
    ),
    (
        "a reversed pair walks the whole cycle",
        "left",
        "seed",
        &["left", "sink", "seed"],
    ),
    (
        "the cycle continues to the other arm",
        "sink",
        "right",
        &["sink", "seed", "right"],
    ),
    (
        "a source is its own zero-edge path",
        "seed",
        "seed",
        &["seed"],
    ),
];

/// Paths are shortest, outgoing, aligned, and least by raw edge id.
pub fn assert_path_is_shortest_directed_and_deterministic() {
    let graph = given::traversal_graph();
    let analysis = given::analysis(&graph, given::calls_only());
    for (label, source, target, expected) in PATH_CASES {
        let route = analysis
            .path(
                given::definition(&graph, source),
                given::definition(&graph, target),
            )
            .unwrap_or_else(|error| panic!("{label}: {error}"))
            .unwrap_or_else(|| panic!("{label}: no route"));
        assert_eq!(given::names(&graph, route.nodes()), *expected, "{label}");
        assert_eq!(
            route.nodes().len(),
            route.edges().len() + 1,
            "{label}: a route states one more node than edges"
        );
    }
    assert_ties_take_the_least_edges(&graph, &analysis);
    assert_unreachable_targets_are_absent(&graph, &analysis);
}

/// Among the three shortest `seed`-to-`sink` routes, the answer is the one
/// whose raw edge ids are lexicographically least.
fn assert_ties_take_the_least_edges(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let selection = given::calls_only();
    let named = |name: &str| given::definition(graph, name);
    let parallel = given::admitted_between(graph, selection, (named("seed"), named("left")));
    let single = given::admitted_between(graph, selection, (named("seed"), named("right")));
    assert_eq!(
        parallel.len(),
        2,
        "the corpus states two parallel calls from seed to left"
    );
    let left = arm(graph, selection, &parallel, named("left"));
    let right = arm(graph, selection, &single, named("right"));
    assert_eq!(
        (left.len(), right.len()),
        (2, 2),
        "both arms are shortest, so the answer is decided by edge id alone"
    );
    let least = left.min(right);

    let route = analysis
        .path(named("seed"), named("sink"))
        .expect("both endpoints are in this graph")
        .expect("sink is reachable from seed");
    assert_eq!(
        route.edges(),
        least.as_slice(),
        "a tie takes the lexicographically least raw edge sequence"
    );
    assert!(
        !route.edges().contains(&parallel[1]),
        "the second of two parallel edges is never taken over the first"
    );
}

/// One two-step route from `seed` into `sink`: the first of the calls out of
/// `seed`, then the arm's own call.
///
/// The leading calls are handed in rather than looked up again, because the
/// caller already states how many of them the corpus holds.
fn arm(
    graph: &CodeGraph,
    selection: GraphEdgeSelection,
    leading: &[GraphEdgeId],
    through: GraphNodeId,
) -> Vec<GraphEdgeId> {
    let mut route: Vec<GraphEdgeId> = leading.iter().take(1).copied().collect();
    route.extend(given::admitted_between(
        graph,
        selection,
        (through, given::definition(graph, "sink")),
    ));
    route
}

/// A target no selected route reaches answers with no path at all.
fn assert_unreachable_targets_are_absent(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    for (source, target) in [("seed", "stranded"), ("stranded", "seed"), ("user", "seed")] {
        let route = analysis
            .path(
                given::definition(graph, source),
                given::definition(graph, target),
            )
            .expect("both endpoints are in this graph");
        assert!(
            route.is_none(),
            "{source} reaches {target} through no selected edge"
        );
    }
}

/// A subgraph is the exact induced selection over the nodes its walk reached.
pub fn assert_subgraph_is_exact_induced_selection() {
    let graph = given::traversal_graph();
    let analysis = given::analysis(&graph, given::calls_only());

    let near = analysis
        .subgraph(
            given::definition(&graph, "seed"),
            1,
            GraphDirection::Outgoing,
        )
        .expect("the admitted depth is below the ceiling");
    assert_eq!(
        given::names(&graph, near.nodes()),
        ["seed", "left", "right"],
        "the seed and its immediate calls, in node id order"
    );
    assert_eq!(
        given::edge_texts(&graph, near.edges()),
        [
            "seed>left|Call|Resolved",
            "seed>left|Call|Resolved",
            "seed>right|Call|Resolved",
        ],
        "both parallel edges are induced and the arms' own calls are not"
    );
    assert!(
        near.containment().is_empty(),
        "the unit root is outside this node set, so it contains nothing here"
    );

    assert_induced_edges_are_internal(&graph, &analysis);
    assert_self_loops_survive_depth_zero(&graph, &analysis);
    assert_internal_containment_is_copied(&graph);
}

/// Every direction induces exactly the selected edges whose endpoints the walk
/// reached, compared against an independent scan of the raw graph.
fn assert_induced_edges_are_internal(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let selection = given::calls_only();
    for direction in [
        GraphDirection::Outgoing,
        GraphDirection::Incoming,
        GraphDirection::Both,
    ] {
        for seed in ["seed", "sink", "user", "stranded"] {
            let induced = analysis
                .subgraph(given::definition(graph, seed), 5, direction)
                .expect("the admitted depth is below the ceiling");
            let held: &[GraphNodeId] = induced.nodes();
            assert!(
                held.contains(&given::definition(graph, seed)),
                "{seed}: a subgraph always holds its seed"
            );
            assert!(
                held.windows(2).all(|pair| pair[0] < pair[1]),
                "{seed}: node ids rise strictly, so each node is stated once: {:?}",
                given::names(graph, held)
            );
            let expected: Vec<_> = graph
                .edges()
                .iter()
                .filter(|edge| {
                    selection.allows(edge)
                        && held.contains(&edge.source())
                        && held.contains(&edge.target())
                })
                .map(|edge| edge.id())
                .collect();
            assert_eq!(
                induced.edges(),
                expected.as_slice(),
                "{seed} {direction:?}: the induced edges are exactly the internal selected edges"
            );
        }
    }
}

/// A seed-only walk still states the seed's own self-loop.
fn assert_self_loops_survive_depth_zero(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let alone = analysis
        .subgraph(given::definition(graph, "wheel"), 0, GraphDirection::Both)
        .expect("the admitted depth is below the ceiling");
    assert_eq!(
        given::names(graph, alone.nodes()),
        ["wheel"],
        "depth zero reaches the seed alone"
    );
    assert_eq!(
        given::edge_texts(graph, alone.edges()),
        ["wheel>wheel|Call|Resolved"],
        "a self-loop has both endpoints inside a one-node set"
    );
}

/// Containment internal to the node set is copied; containment leaving it is
/// not.
///
/// The corpus states `pub mod part;` and `use part::helper;` beside each other
/// in `src/lib.rs`, so two code-relation steps from `part` reach the file that
/// declares it and, from that file, the function it imports. Which of those
/// three nodes holds the lower identity is the builder's business, so the set
/// is stated by name and the ordering is proved as a property.
fn assert_internal_containment_is_copied(graph: &CodeGraph) {
    let analysis = given::analysis(graph, GraphEdgeSelection::code_relations());
    let induced = analysis
        .subgraph(given::definition(graph, "part"), 2, GraphDirection::Both)
        .expect("the admitted depth is below the ceiling");
    let held = induced.nodes();
    assert_eq!(
        given::sorted_names(graph, held),
        "helper,part,src/lib.rs",
        "the module declaration and the import beside it reach the module and \
         the function it holds"
    );
    assert!(
        held.windows(2).all(|pair| pair[0] < pair[1]),
        "the reached nodes are stated once, in node id order"
    );
    assert_eq!(
        containment_texts(graph, induced.containment()),
        raw_internal_containment(graph, held),
        "the copied containment is exactly the raw containment internal to the \
         held nodes"
    );
    assert_eq!(
        containment_texts(graph, induced.containment()),
        ["part>helper"],
        "the corpus states one internal pair: the module and the function it \
         declares"
    );
}

/// One containment edge as `parent>child`, by node name.
fn containment_text(graph: &CodeGraph, edge: &ContainmentEdge) -> String {
    format!(
        "{}>{}",
        given::name(graph, edge.parent()),
        given::name(graph, edge.child())
    )
}

/// Every containment edge as `parent>child`, in the order supplied.
fn containment_texts(graph: &CodeGraph, edges: &[ContainmentEdge]) -> Vec<String> {
    edges
        .iter()
        .map(|edge| containment_text(graph, edge))
        .collect()
}

/// The raw graph's own containment edges whose parent and child are both held,
/// in child order, scanned independently of the analysis under test.
fn raw_internal_containment(graph: &CodeGraph, held: &[GraphNodeId]) -> Vec<String> {
    let mut internal: Vec<&ContainmentEdge> = graph
        .containment()
        .iter()
        .filter(|edge| held.contains(&edge.parent()) && held.contains(&edge.child()))
        .collect();
    internal.sort_by_key(|edge| edge.child());
    internal
        .into_iter()
        .map(|edge| containment_text(graph, edge))
        .collect()
}

/// Depth above the ceiling and a node from another graph are exact typed
/// refusals, and neither answers with a partial result.
pub fn assert_query_limits_refuse() {
    let graph = given::traversal_graph();
    let ceilings = GraphAnalysisLimits::new(u32::MAX, u32::MAX, 2, u64::MAX);
    let bounded = GraphAnalysis::new(&graph, given::calls_only(), ceilings)
        .expect("the corpus is far below every other ceiling");
    let seed = given::definition(&graph, "seed");

    assert_eq!(
        bounded.limits(),
        ceilings,
        "an analysis reports back the exact ceilings it was admitted under, \
         which is the depth the refusals below name"
    );

    assert!(
        bounded
            .neighbors(seed, 2, GraphDirection::Both)
            .is_ok_and(|reached| !reached.is_empty()),
        "a depth equal to the ceiling is admitted"
    );
    for refused in [
        bounded.neighbors(seed, 3, GraphDirection::Both).err(),
        bounded.subgraph(seed, 3, GraphDirection::Both).err(),
    ] {
        assert_eq!(
            refused.map(|error| error.to_string()),
            Some("a depth of 3 is above the ceiling of 2".to_owned()),
            "a depth above the ceiling refuses before it walks"
        );
    }

    assert_foreign_nodes_refuse(&graph, &bounded);
}

/// A node identity minted by another graph names nothing here.
fn assert_foreign_nodes_refuse(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let foreign = given::foreign_node(graph);
    let expected = format!("node {} is not in this graph", foreign.index());
    let seed = given::definition(graph, "seed");
    let refusals = [
        analysis.neighbors(foreign, 1, GraphDirection::Both).err(),
        analysis.subgraph(foreign, 1, GraphDirection::Both).err(),
        analysis.path(foreign, seed).err(),
        analysis.path(seed, foreign).err(),
    ];
    for refused in refusals {
        assert_eq!(
            refused.map(|error: GraphAnalysisError| error.to_string()),
            Some(expected.clone()),
            "an unknown node refuses before any walk"
        );
    }
}
