//! Strongly connected components, their condensation, and the iterative shape
//! both are answered with.
//!
//! The component corpus states every shape at once: two nodes a call selection
//! never touches, one plain caller, one two-node cycle, one self-loop, one sink,
//! and one unreachable definition. Every crossing pair is parallel, so a
//! condensation that lost multiplicity would be visible here.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, CondensationEdge, GraphAnalysis, GraphAnalysisLimits, GraphComponentId,
    GraphDirection, GraphEdgeSelection,
};

use super::analysis_fixture as given;
use super::analysis_oracle as oracle;
use super::corpus_generated::{linear_corpus, linear_name};

/// How many functions the chain corpus states.
const CHAIN_LENGTH: usize = 1000;

/// How far a chain's accumulated score may sit from its closed form.
const TOLERANCE: f64 = 1e-6;

/// Every component of the component corpus, as `id|cyclic|members`.
///
/// Written from the corpus source: the unit root and its source file are
/// untouched by a call selection, `entry` calls into the `ring_a`/`ring_b`
/// cycle, `ring_b` calls the `tail` sink, `wheel` calls itself, and `alone` is
/// reached by nothing.
const EXPECTED_COMPONENTS: &[&str] = &[
    "0|false|app",
    "1|false|src/lib.rs",
    "2|false|entry",
    "3|true|ring_a,ring_b",
    "4|false|tail",
    "5|true|wheel",
    "6|false|alone",
];

/// Every condensation edge of the component corpus, as `source>target|edges`.
///
/// Both crossing pairs are stated twice in the corpus, so each coalesced edge
/// carries two raw identities and neither of the cycle's own edges appears.
const EXPECTED_CONDENSATION: &[&str] = &[
    "2>3|entry>ring_a|Call|Resolved,entry>ring_a|Call|Resolved",
    "3>4|ring_b>tail|Call|Resolved,ring_b>tail|Call|Resolved",
];

/// Components are exact, dense, and sorted, and their condensation coalesces
/// without losing raw evidence.
pub fn assert_components_and_condensation_are_exact() {
    let graph = given::component_graph();
    let analysis = given::analysis(&graph, given::calls_only());
    let components = analysis.strongly_connected_components();

    assert_eq!(
        given::component_texts(&graph, components.components()),
        EXPECTED_COMPONENTS,
        "every node belongs to one component, dense in smallest-member order"
    );
    assert_membership_is_total(&graph, &analysis);
    assert_components_read_back_their_own_identities(&analysis);

    let condensation = analysis.condensation();
    assert_eq!(
        given::condensation_texts(&graph, condensation.edges()),
        EXPECTED_CONDENSATION,
        "parallel crossing edges coalesce and internal edges do not appear"
    );
    assert_eq!(
        given::component_texts(&graph, condensation.components().components()),
        EXPECTED_COMPONENTS,
        "a condensation carries the same components it was built from"
    );
    assert_order_is_a_linearization(condensation.topological_order(), condensation.edges());
    assert_eq!(
        indexes(condensation.topological_order().iter().copied()),
        (0..EXPECTED_COMPONENTS.len()).collect::<Vec<usize>>(),
        "simultaneous zero-indegree components are consumed by component id"
    );
}

/// Every raw node has exactly one component, and every component's members are
/// exactly the nodes that name it.
fn assert_membership_is_total(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) {
    let components = analysis.strongly_connected_components();
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for component in components.components() {
        for member in component.members() {
            assert!(
                seen.insert(member.index()),
                "node {} belongs to two components",
                member.index()
            );
            assert_eq!(
                components.component_of(*member),
                Some(component.id()),
                "a member's component is the component that lists it"
            );
        }
        assert!(
            component.members().windows(2).all(|pair| pair[0] < pair[1]),
            "members rise strictly, so each is listed once, in node-id order"
        );
    }
    assert_eq!(
        seen.len(),
        graph.nodes().len(),
        "every raw node belongs to exactly one component"
    );
    assert!(
        components
            .component_of(given::foreign_node(graph))
            .is_none(),
        "an identity from another graph belongs to no component here"
    );
}

/// Component identities are dense, in order, and select their own record.
fn assert_components_read_back_their_own_identities(analysis: &GraphAnalysis<'_>) {
    let components = analysis.strongly_connected_components();
    assert_eq!(
        indexes(components.components().iter().map(|found| found.id())),
        (0..components.components().len()).collect::<Vec<usize>>(),
        "component ids are dense and rise with the components that carry them"
    );
    for component in components.components() {
        assert_eq!(
            components
                .component(component.id())
                .map(|found| found.members()),
            Some(component.members()),
            "a component identity selects its own record"
        );
    }
}

/// Every component appears once, after every component that points at it.
fn assert_order_is_a_linearization(order: &[GraphComponentId], edges: &[CondensationEdge]) {
    let listed: BTreeSet<u32> = order.iter().map(|component| component.index()).collect();
    assert_eq!(
        listed.len(),
        order.len(),
        "a topological order states each component once"
    );
    for edge in edges {
        assert_ne!(
            edge.source(),
            edge.target(),
            "a condensation states no edge inside one component"
        );
        assert!(
            position_of(order, edge.source()) < position_of(order, edge.target()),
            "a condensation edge must run forwards through the order"
        );
    }
}

/// Where one component sits in an order.
fn position_of(order: &[GraphComponentId], component: GraphComponentId) -> usize {
    order
        .iter()
        .position(|listed| *listed == component)
        .unwrap_or_else(|| panic!("component {} is not ordered", component.index()))
}

/// Every listed component identity as its dense position.
fn indexes(components: impl IntoIterator<Item = GraphComponentId>) -> Vec<usize> {
    components
        .into_iter()
        .map(|component| component.index() as usize)
        .collect()
}

/// Components and condensation answer over the selection their analysis was
/// built from.
pub fn assert_component_selection_reuses_indexes() {
    let mixed = given::selection_graph();
    let cyclic = given::component_graph();
    for graph in [&mixed, &cyclic] {
        for (label, selection) in given::metric_selections() {
            assert_components_match_model(graph, selection, label);
        }
    }
    assert_selections_condense_differently(&mixed);
    assert_empty_selection_is_discrete(&mixed);
}

/// One graph's components and condensation, compared with the model built from
/// the same selection.
fn assert_components_match_model(graph: &CodeGraph, selection: GraphEdgeSelection, label: &str) {
    let nodes = graph.nodes().len();
    let analysis = given::analysis(graph, selection);
    let edges = oracle::selected(graph, selection);
    let modelled = oracle::components(nodes, &edges);
    assert_eq!(
        given::component_texts(graph, analysis.strongly_connected_components().components()),
        modelled_component_texts(graph, &modelled, &edges),
        "{label}: components and cyclic flags read the selected edges"
    );
    assert_eq!(
        given::membership_texts(graph, &analysis.strongly_connected_components()),
        modelled_membership_texts(graph, &modelled, nodes),
        "{label}: every node's component is the one the model places it in"
    );
    assert_eq!(
        given::condensation_texts(graph, analysis.condensation().edges()),
        modelled_condensation_texts(graph, &modelled, &edges, nodes),
        "{label}: condensation coalesces the selected edges"
    );
    assert_eq!(
        indexes(analysis.condensation().topological_order().iter().copied()),
        oracle::topological_order(
            modelled.len(),
            &oracle::condensation(&oracle::assignment(nodes, &modelled), &edges),
        ),
        "{label}: the condensation is ordered as the model orders it"
    );
}

/// No two stated selections coalesce into the same condensation.
fn assert_selections_condense_differently(graph: &CodeGraph) {
    let rendered: BTreeSet<Vec<String>> = given::metric_selections()
        .iter()
        .map(|(_, selection)| {
            given::condensation_texts(
                graph,
                given::analysis(graph, *selection).condensation().edges(),
            )
        })
        .collect();
    assert_eq!(
        rendered.len(),
        given::metric_selections().len(),
        "each stated selection condenses into an edge set of its own"
    );
}

/// Every modelled component rendered exactly as the analysis renders its own.
fn modelled_component_texts(
    graph: &CodeGraph,
    components: &[Vec<usize>],
    edges: &[oracle::SelectedEdge],
) -> Vec<String> {
    components
        .iter()
        .enumerate()
        .map(|(at, members)| {
            format!(
                "{at}|{}|{}",
                oracle::is_cyclic(members, edges),
                named_members(graph, members).join(",")
            )
        })
        .collect()
}

/// Every modelled member named as the graph names it.
fn named_members(graph: &CodeGraph, members: &[usize]) -> Vec<String> {
    members
        .iter()
        .map(|member| given::name(graph, given::node_at(graph, *member)))
        .collect()
}

/// Every node's modelled component as `name|component`, in raw node-id order.
fn modelled_membership_texts(
    graph: &CodeGraph,
    components: &[Vec<usize>],
    nodes: usize,
) -> Vec<String> {
    let placed = oracle::assignment(nodes, components);
    graph
        .nodes()
        .iter()
        .enumerate()
        .map(|(at, node)| format!("{}|{}", node.name(), placed[at]))
        .collect()
}

/// Every modelled condensation edge rendered as the analysis renders its own.
fn modelled_condensation_texts(
    graph: &CodeGraph,
    components: &[Vec<usize>],
    edges: &[oracle::SelectedEdge],
    nodes: usize,
) -> Vec<String> {
    oracle::condensation(&oracle::assignment(nodes, components), edges)
        .iter()
        .map(|pair| {
            format!(
                "{}>{}|{}",
                pair.source,
                pair.target,
                given::edge_texts(graph, &pair.edges).join(",")
            )
        })
        .collect()
}

/// An empty selection leaves every node alone in its own acyclic component.
fn assert_empty_selection_is_discrete(graph: &CodeGraph) {
    let nodes = graph.nodes().len();
    let analysis = given::analysis(graph, GraphEdgeSelection::new(&[], &[]));
    let components = analysis.strongly_connected_components();
    assert_eq!(
        components.components().len(),
        nodes,
        "no selected edge leaves every node in a component of its own"
    );
    assert!(
        components
            .components()
            .iter()
            .all(|component| !component.is_cyclic()),
        "no selected edge leaves no cycle"
    );
    assert!(
        analysis.condensation().edges().is_empty(),
        "no selected edge coalesces into no condensation edge"
    );
    assert_eq!(
        indexes(analysis.condensation().topological_order().iter().copied()),
        (0..nodes).collect::<Vec<usize>>(),
        "an edgeless condensation is ordered by component id alone"
    );
}

/// Every traversal and component operation answers over a chain as long as its
/// own admitted node ceiling.
pub fn assert_traversal_and_components_are_iterative() {
    let graph = given::generated_graph(&linear_corpus(CHAIN_LENGTH));
    let nodes = graph.nodes().len();
    assert_eq!(
        nodes,
        CHAIN_LENGTH + 2,
        "the chain states one unit root, one source, and one function per step"
    );
    let analysis = at_exact_ceiling(&graph, nodes);
    assert_chain_traversals(&graph, &analysis, nodes as u32);
    assert_chain_metrics(&graph, &analysis, nodes);
}

/// Every bounded query walks the whole chain without recursing on it.
fn assert_chain_traversals(graph: &CodeGraph, analysis: &GraphAnalysis<'_>, depth: u32) {
    let first = given::definition(graph, &linear_name(0));
    let last = given::definition(graph, &linear_name(CHAIN_LENGTH - 1));
    assert_eq!(
        analysis
            .neighbors(first, depth, GraphDirection::Outgoing)
            .expect("the ceiling admits the whole chain")
            .len(),
        CHAIN_LENGTH - 1,
        "a walk from the head reaches every later step once"
    );
    assert_eq!(
        analysis
            .neighbors(last, depth, GraphDirection::Both)
            .expect("the ceiling admits the whole chain")
            .len(),
        CHAIN_LENGTH - 1,
        "a two-way walk from the tail reaches every earlier step once"
    );
    let route = analysis
        .path(first, last)
        .expect("both endpoints are in this graph")
        .expect("the chain runs from head to tail");
    assert_eq!(
        (route.nodes().len(), route.edges().len()),
        (CHAIN_LENGTH, CHAIN_LENGTH - 1),
        "the route walks the whole chain"
    );
    assert_eq!(
        analysis
            .subgraph(first, depth, GraphDirection::Outgoing)
            .expect("the ceiling admits the whole chain")
            .nodes()
            .len(),
        CHAIN_LENGTH,
        "the induced selection holds the head and every step after it"
    );
}

/// Degree, betweenness, components, and condensation over the same chain.
fn assert_chain_metrics(graph: &CodeGraph, analysis: &GraphAnalysis<'_>, nodes: usize) {
    assert_eq!(
        analysis
            .degree_centrality()
            .iter()
            .filter(|record| record.outgoing() == 1)
            .count(),
        CHAIN_LENGTH - 1,
        "every step but the last calls exactly one successor"
    );
    let scores = analysis
        .betweenness_centrality()
        .expect("the chain is below the stated work ceiling");
    for at in [1, CHAIN_LENGTH / 2, CHAIN_LENGTH - 2] {
        let node = given::definition(graph, &linear_name(at));
        let expected = (at * (CHAIN_LENGTH - 1 - at)) as f64;
        let measured = scores[node.index() as usize].raw();
        assert!(
            (measured - expected).abs() <= TOLERANCE,
            "step {at} sits between every earlier and every later step: \
             {measured} against {expected}"
        );
    }

    assert_eq!(
        analysis.strongly_connected_components().components().len(),
        nodes,
        "a chain has no cycle, so every node is its own component"
    );
    let condensation = analysis.condensation();
    assert_eq!(
        condensation.edges().len(),
        CHAIN_LENGTH - 1,
        "every call crosses a component boundary"
    );
    assert_eq!(
        indexes(condensation.topological_order().iter().copied()),
        (0..nodes).collect::<Vec<usize>>(),
        "the chain's condensation is ordered by component id"
    );
}

/// One analysis whose node ceiling is exactly the graph it admits.
fn at_exact_ceiling(graph: &CodeGraph, nodes: usize) -> GraphAnalysis<'_> {
    GraphAnalysis::new(
        graph,
        given::calls_only(),
        GraphAnalysisLimits::new(nodes as u32, u32::MAX, nodes as u32, u64::MAX),
    )
    .expect("a ceiling equal to the node count admits the whole graph")
}
