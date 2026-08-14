//! Coordinate-free layout metadata: every admitted node and selected edge once,
//! carrying what a renderer or a ranker would otherwise derive itself.
//!
//! Every value is compared against the answer the analysis already publishes —
//! the raw graph's containment and edge records, the declared partition, the
//! degrees, and the same bounded betweenness result — so the projection is
//! proved to restate them rather than to compute a second answer. The absence of
//! a coordinate, a route, a rank, or any other renderer state is structural and
//! belongs to `graph_analysis_public_boundary_is_exact`.

use std::collections::{BTreeMap, BTreeSet};

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphAnalysisError, GraphAnalysisLimits, GraphEdgeId,
    GraphEdgeSelection, GraphNodeId, LayoutAssistMetadata,
};

use super::analysis_fixture as given;
use super::analysis_oracle as oracle;

/// Layout metadata restates the graph, the partition, the degrees, and the
/// bounded betweenness result, and refuses whole when that pass refuses.
pub fn assert_layout_is_complete_and_coordinate_free() {
    let graph = given::divergence_graph();
    for (label, selection) in given::metric_selections() {
        let analysis = given::analysis(&graph, selection);
        let layout = analysis
            .layout_assist()
            .expect("the fixture graph is far below every ceiling");
        assert_nodes_restate_the_analysis(&graph, &analysis, &layout, label);
        assert_edges_restate_the_selection(&graph, &layout, (label, selection));
    }
    assert_work_limit_propagates(&graph);
}

/// Every admitted node appears once, in raw id order, with the containment
/// parent, partition, degrees, and betweenness the analysis already answers
/// with.
fn assert_nodes_restate_the_analysis(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    layout: &LayoutAssistMetadata,
    label: &str,
) {
    let stated: Vec<GraphNodeId> = layout.nodes().iter().map(|node| node.node()).collect();
    let admitted: Vec<GraphNodeId> = graph.nodes().iter().map(|node| node.id()).collect();
    assert_eq!(
        stated, admitted,
        "{label}: every admitted node is described once, in raw id order"
    );

    let parents = containment_parents(graph);
    let partition = analysis.declared_partition();
    let degrees = analysis.degree_centrality();
    let weights = analysis
        .betweenness_centrality()
        .expect("the fixture graph is far below every ceiling");
    for (at, node) in layout.nodes().iter().enumerate() {
        let named = given::name(graph, node.node());
        assert_eq!(
            node.containment_parent(),
            parents.get(&node.node()).copied(),
            "{label}: {named} states the containment parent the graph does"
        );
        assert_eq!(
            Some(node.partition()),
            partition.owner(node.node()),
            "{label}: {named} states the partition the analysis derived"
        );
        assert_eq!(
            (node.incoming_degree(), node.outgoing_degree()),
            (degrees[at].incoming(), degrees[at].outgoing()),
            "{label}: {named} states its selected degrees"
        );
        assert_eq!(
            (
                given::bits(node.raw_betweenness()),
                given::bits(node.normalized_betweenness())
            ),
            (
                given::bits(weights[at].raw()),
                given::bits(weights[at].normalized())
            ),
            "{label}: {named} states the bounded betweenness result exactly"
        );
        assert!(
            node.raw_betweenness().is_finite() && node.normalized_betweenness().is_finite(),
            "{label}: {named} states finite weights"
        );
    }
}

/// Every selected edge appears once, in raw id order, with the endpoints, kind,
/// and certainty the raw record states.
fn assert_edges_restate_the_selection(
    graph: &CodeGraph,
    layout: &LayoutAssistMetadata,
    case: (&str, GraphEdgeSelection),
) {
    let (label, selection) = case;
    let stated: Vec<GraphEdgeId> = layout.edges().iter().map(|edge| edge.edge()).collect();
    let admitted: Vec<GraphEdgeId> = oracle::selected(graph, selection)
        .iter()
        .map(|edge| edge.id)
        .collect();
    assert_eq!(
        stated, admitted,
        "{label}: every selected edge is described once, in raw id order"
    );
    assert_eq!(
        given::layout_edge_texts(graph, layout.edges()),
        given::edge_texts(graph, &admitted),
        "{label}: every described edge restates its own raw record"
    );
}

/// Each node's containment parent, taken from the raw graph.
fn containment_parents(graph: &CodeGraph) -> BTreeMap<GraphNodeId, GraphNodeId> {
    graph
        .containment()
        .iter()
        .map(|edge| (edge.child(), edge.parent()))
        .collect()
}

/// A work ceiling below the bound refuses the layout exactly as it refuses
/// betweenness, and answers with no metadata at all.
fn assert_work_limit_propagates(graph: &CodeGraph) {
    let limits = GraphAnalysisLimits::new(u32::MAX, u32::MAX, u32::MAX, 1);
    let analysis = GraphAnalysis::new(graph, GraphEdgeSelection::code_relations(), limits)
        .expect("only the betweenness work ceiling is lowered");
    let refused = analysis
        .layout_assist()
        .expect_err("the lowered work ceiling was admitted");
    let expected = analysis
        .betweenness_centrality()
        .expect_err("the lowered work ceiling was admitted");
    assert!(
        matches!(
            refused,
            GraphAnalysisError::BetweennessWorkLimitExceeded { .. }
        ),
        "the layout refuses with the bounded pass's own refusal: {refused:?}"
    );
    assert_eq!(
        refused.to_string(),
        expected.to_string(),
        "the layout propagates that refusal unchanged"
    );
    assert!(
        analysis.divergence().cohesion().len() > 1,
        "a refusal consumes nothing: the same analysis still answers"
    );
}

/// Layout metadata is a function of the selection the analysis was built with.
pub fn assert_layout_selection_reuses_indexes() {
    let graph = given::divergence_graph();
    let mut answers: BTreeSet<Vec<String>> = BTreeSet::new();
    for (label, selection) in given::metric_selections() {
        let analysis = given::analysis(&graph, selection);
        let layout = analysis
            .layout_assist()
            .expect("the fixture graph is far below every ceiling");
        let selected = oracle::selected(&graph, selection);
        assert_eq!(
            layout.edges().len(),
            selected.len(),
            "{label}: the layout describes exactly the selected edges"
        );
        let degrees = oracle::degrees(graph.nodes().len(), &selected);
        let stated: Vec<(u32, u32)> = layout
            .nodes()
            .iter()
            .map(|node| (node.incoming_degree(), node.outgoing_degree()))
            .collect();
        assert_eq!(
            stated, degrees,
            "{label}: the described degrees are the selected degrees"
        );
        assert_weights_match_the_selection(&graph, &layout, (label, &selected));
        answers.insert(given::layout_node_texts(&graph, layout.nodes()));
    }
    assert!(
        answers.len() > 1,
        "the selections compared must not all describe the same weights"
    );
}

/// Every described weight equals the independent shortest-route model of the
/// same selection.
fn assert_weights_match_the_selection(
    graph: &CodeGraph,
    layout: &LayoutAssistMetadata,
    case: (&str, &[oracle::SelectedEdge]),
) {
    let (label, selected) = case;
    let nodes = graph.nodes().len();
    let modelled = oracle::raw_betweenness(nodes, selected);
    for (at, node) in layout.nodes().iter().enumerate() {
        let named = given::name(graph, node.node());
        assert!(
            (node.raw_betweenness() - modelled[at]).abs() <= 1e-12,
            "{label}: {named} states {} rather than {}",
            node.raw_betweenness(),
            modelled[at]
        );
        assert!(
            (node.normalized_betweenness() - oracle::normalized(nodes, modelled[at])).abs()
                <= 1e-12,
            "{label}: {named} states an unexpected normalized weight"
        );
    }
}
