//! Equal graphs answer equally, whatever order their repository was written in.
//!
//! Each case materializes one corpus three ways. Twice as written — once more
//! into a third temporary directory, and once with its files created in the
//! opposite order — which differ in creation order and absolute path and in
//! nothing else, so the projected graphs must be equal and every derived answer
//! must render identically, down to the exact bits of each score. Then once
//! with the declarations of every source written in the opposite order, which
//! states the same library but makes the graph mint its identities in another
//! order: there every answer that is a fact about the topology rather than
//! about mint order must still be the same answer.
//!
//! Exactness belongs to the metric and component cases, which compare hand
//! written expectations. What is proved here is that neither the order a
//! repository is written out in nor the order its declarations are stated in
//! reaches an answer. The perturbations themselves live in
//! [`super::analysis_perturbation`], and the derived evidence built on these
//! answers is proved in [`super::analysis_derived_determinism`].

use pedant_graph::{
    CodeGraph, CondensationEdge, CondensationGraph, GraphAnalysis, GraphComponent,
    GraphComponentId, GraphComponents, GraphDirection, GraphEdgeSelection, GraphNodeId, GraphPath,
};

use super::analysis_fixture as given;
use super::analysis_perturbation::{
    assert_perturbation_reaches_minted_identities, created_in_reverse, declared_in_reverse, sorted,
};
use super::corpus::FixtureFile;
use super::corpus_analysis::{ANALYSIS_COMPONENT_CORPUS, ANALYSIS_TRAVERSAL_CORPUS};

/// How deep every compared neighborhood and subgraph walk goes.
const WALK_DEPTH: u32 = 4;

/// Equal graphs produce identical ids, counts, orders, and score bits, and
/// reordered declarations produce the same answers about the same topology.
pub fn assert_analysis_results_are_deterministic() {
    for corpus in [ANALYSIS_TRAVERSAL_CORPUS, ANALYSIS_COMPONENT_CORPUS] {
        let written = given::graph_of(corpus);
        let reversed = given::graph_of(&created_in_reverse(corpus));
        let repeated = given::graph_of(corpus);
        assert_eq!(
            written, reversed,
            "the order a repository's files are created in is not part of its graph"
        );
        assert_eq!(written, repeated, "one corpus projects one graph");
        for (label, selection) in given::metric_selections() {
            let answers = rendered(&written, selection);
            assert!(
                !answers.is_empty(),
                "{label}: a rendering compares something"
            );
            assert_eq!(
                answers,
                rendered(&repeated, selection),
                "{label}: a repeated run changes no answer"
            );
        }
        assert_declaration_order_changes_no_answer(corpus);
    }
}

/// The same declarations, stated in the opposite order, answer the same.
fn assert_declaration_order_changes_no_answer(corpus: &[FixtureFile]) {
    let written = given::graph_of(corpus);
    let reordered = given::generated_graph(&declared_in_reverse(corpus));
    assert_perturbation_reaches_minted_identities(&written, &reordered);
    for (label, selection) in given::metric_selections() {
        let answers = named_answers(&written, selection);
        assert!(
            !answers.is_empty(),
            "{label}: a rendering compares something"
        );
        assert_eq!(
            answers,
            named_answers(&reordered, selection),
            "{label}: the order declarations are stated in changes no answer"
        );
    }
}

/// Every answer one analysis gives, written with no minted identity in it.
///
/// A name keys each answer and every set inside one is sorted, so two graphs
/// stating the same declarations in different orders render the same text —
/// and an answer that depended on the order they were minted in would not.
fn named_answers(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<String> {
    let analysis = given::analysis(graph, selection);
    let mut answers = named_traversals(graph, &analysis);
    answers.extend(labelled(
        "degree",
        given::degree_texts(graph, &analysis.degree_centrality()),
    ));
    answers.extend(labelled(
        "between",
        given::betweenness_texts(
            graph,
            &analysis
                .betweenness_centrality()
                .expect("the fixture graph is far below every ceiling"),
        ),
    ));
    let components = analysis.strongly_connected_components();
    answers.extend(named_components(graph, &components));
    answers.extend(named_memberships(graph, &components));
    answers.extend(named_condensation(graph, &analysis.condensation()));
    answers.sort();
    answers
}

/// One label before each entry of a rendering.
fn labelled(label: &str, texts: Vec<String>) -> Vec<String> {
    texts
        .into_iter()
        .map(|text| format!("{label}|{text}"))
        .collect()
}

/// Every neighborhood, route length, and induced subgraph, keyed by name.
fn named_traversals(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<String> {
    let mut answers: Vec<String> = Vec::new();
    for node in graph.nodes() {
        answers.extend(named_walks(graph, analysis, node.id()));
        answers.extend(
            graph
                .nodes()
                .iter()
                .map(|target| named_route(graph, analysis, (node.id(), target.id()))),
        );
    }
    answers
}

/// One seed's neighborhood and induced subgraph, in every direction, named.
fn named_walks(graph: &CodeGraph, analysis: &GraphAnalysis<'_>, seed: GraphNodeId) -> Vec<String> {
    let mut answers: Vec<String> = Vec::new();
    let named = given::name(graph, seed);
    for direction in [
        GraphDirection::Outgoing,
        GraphDirection::Incoming,
        GraphDirection::Both,
    ] {
        let reached = analysis
            .neighbors(seed, WALK_DEPTH, direction)
            .expect("the walk depth is below the ceiling");
        answers.push(format!(
            "near|{named}|{direction:?}|{}",
            sorted(&given::neighbor_texts(graph, &reached)).join(",")
        ));
        let induced = analysis
            .subgraph(seed, WALK_DEPTH, direction)
            .expect("the walk depth is below the ceiling");
        answers.push(format!(
            "induced|{named}|{direction:?}|{}|{}",
            sorted(&given::names(graph, induced.nodes())).join(","),
            sorted(&given::edge_texts(graph, induced.edges())).join(",")
        ));
    }
    answers
}

/// One ordered pair's shortest route length, or the absence of a route.
///
/// Which of two equally short routes a walk takes is settled by the identities
/// the graph minted, and reordered declarations mint them differently. How far
/// apart two nodes are is a fact about the topology alone, and the exact tied
/// route belongs to the path case.
fn named_route(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    route: (GraphNodeId, GraphNodeId),
) -> String {
    let (source, target) = route;
    let found = analysis
        .path(source, target)
        .expect("both endpoints are in this graph");
    format!(
        "route|{}>{}|{}",
        given::name(graph, source),
        given::name(graph, target),
        steps(&found)
    )
}

/// How many selected edges one route takes, or that there is no route.
fn steps(found: &Option<GraphPath>) -> String {
    match found {
        Some(walked) => walked.edges().len().to_string(),
        None => "none".to_owned(),
    }
}

/// Every component as its cyclic flag and its members, named.
fn named_components(graph: &CodeGraph, components: &GraphComponents) -> Vec<String> {
    components
        .components()
        .iter()
        .map(|component| {
            format!(
                "component|{}|{}",
                component.is_cyclic(),
                member_names(graph, component)
            )
        })
        .collect()
}

/// Every node beside the component it belongs to, both named.
fn named_memberships(graph: &CodeGraph, components: &GraphComponents) -> Vec<String> {
    graph
        .nodes()
        .iter()
        .map(|node| {
            format!(
                "member|{}|{}",
                node.name(),
                named_component(graph, components, held_by(components, node.id()))
            )
        })
        .collect()
}

/// The component one node belongs to.
fn held_by(components: &GraphComponents, node: GraphNodeId) -> GraphComponentId {
    components
        .component_of(node)
        .unwrap_or_else(|| panic!("node {} belongs to no component", node.index()))
}

/// One component identity as the members it holds.
fn named_component(
    graph: &CodeGraph,
    components: &GraphComponents,
    component: GraphComponentId,
) -> String {
    member_names(
        graph,
        components
            .component(component)
            .unwrap_or_else(|| panic!("this result holds no component {}", component.index())),
    )
}

/// One component's members, named and sorted.
fn member_names(graph: &CodeGraph, component: &GraphComponent) -> String {
    sorted(&given::names(graph, component.members())).join(",")
}

/// Every coalesced pair and every ordering it imposes, named.
fn named_condensation(graph: &CodeGraph, condensation: &CondensationGraph) -> Vec<String> {
    let components = condensation.components();
    let mut answers: Vec<String> = condensation
        .edges()
        .iter()
        .map(|edge| named_crossing(graph, components, edge))
        .collect();
    answers.extend(named_order(graph, condensation));
    answers
}

/// One coalesced pair as the components it joins and the raw edges it kept.
fn named_crossing(
    graph: &CodeGraph,
    components: &GraphComponents,
    edge: &CondensationEdge,
) -> String {
    format!(
        "crossing|{}>{}|{}",
        named_component(graph, components, edge.source()),
        named_component(graph, components, edge.target()),
        sorted(&given::edge_texts(graph, edge.edges())).join(",")
    )
}

/// How many components the order consumes, and which side of each coalesced
/// pair it consumes first.
///
/// Which of two components that become ready together is consumed first is
/// settled by the identities the graph minted; that a component is consumed
/// before the ones it reaches is a fact about the topology. The exact order
/// belongs to the component case.
fn named_order(graph: &CodeGraph, condensation: &CondensationGraph) -> Vec<String> {
    let order = condensation.topological_order();
    let components = condensation.components();
    let mut answers = vec![format!("order|consumed|{}", order.len())];
    answers.extend(condensation.edges().iter().map(|edge| {
        format!(
            "order|{}>{}|{}",
            named_component(graph, components, edge.source()),
            named_component(graph, components, edge.target()),
            consumed_before(order, edge)
        )
    }));
    answers
}

/// Whether the order consumes one coalesced pair's source before its target.
fn consumed_before(order: &[GraphComponentId], edge: &CondensationEdge) -> bool {
    consumed_at(order, edge.source()) < consumed_at(order, edge.target())
}

/// Where the order consumes one component.
fn consumed_at(order: &[GraphComponentId], component: GraphComponentId) -> usize {
    order
        .iter()
        .position(|consumed| *consumed == component)
        .unwrap_or_else(|| panic!("the order omits component {}", component.index()))
}

/// Every answer one analysis gives, as comparable text.
fn rendered(graph: &CodeGraph, selection: GraphEdgeSelection) -> Vec<String> {
    let analysis = given::analysis(graph, selection);
    let mut answers: Vec<String> = Vec::new();
    answers.extend(rendered_traversals(graph, &analysis));
    answers.extend(given::degree_texts(graph, &analysis.degree_centrality()));
    answers.extend(given::betweenness_texts(
        graph,
        &analysis
            .betweenness_centrality()
            .expect("the fixture graph is far below every ceiling"),
    ));
    let components = analysis.strongly_connected_components();
    answers.extend(given::component_texts(graph, components.components()));
    answers.extend(given::membership_texts(graph, &components));
    let condensation = analysis.condensation();
    answers.extend(given::condensation_texts(graph, condensation.edges()));
    answers.extend(
        condensation
            .topological_order()
            .iter()
            .map(|component| format!("order|{}", component.index())),
    );
    answers
}

/// Every selection, neighborhood, path, and induced subgraph answer.
fn rendered_traversals(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<String> {
    let mut answers: Vec<String> = Vec::new();
    for node in graph.nodes() {
        answers.extend(rendered_walks(graph, analysis, node.id()));
        answers.extend(
            graph
                .nodes()
                .iter()
                .map(|target| rendered_path(graph, analysis, (node.id(), target.id()))),
        );
    }
    answers
}

/// One seed's neighborhood and induced subgraph, in every direction.
fn rendered_walks(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    seed: GraphNodeId,
) -> Vec<String> {
    let mut answers: Vec<String> = Vec::new();
    for direction in [
        GraphDirection::Outgoing,
        GraphDirection::Incoming,
        GraphDirection::Both,
    ] {
        let reached = analysis
            .neighbors(seed, WALK_DEPTH, direction)
            .expect("the walk depth is below the ceiling");
        answers.push(format!(
            "near|{direction:?}|{}",
            given::neighbor_texts(graph, &reached).join(",")
        ));
        let induced = analysis
            .subgraph(seed, WALK_DEPTH, direction)
            .expect("the walk depth is below the ceiling");
        answers.push(format!(
            "induced|{direction:?}|{}|{}",
            given::names(graph, induced.nodes()).join(","),
            given::edge_texts(graph, induced.edges()).join(",")
        ));
    }
    answers
}

/// One ordered pair's route, or the absence of one.
fn rendered_path(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    route: (GraphNodeId, GraphNodeId),
) -> String {
    let (source, target) = route;
    let found = analysis
        .path(source, target)
        .expect("both endpoints are in this graph");
    match found {
        Some(walked) => format!("route|{}", written_route(graph, &walked)),
        None => "route|none".to_owned(),
    }
}

/// One route as the nodes it stops at and the edges it takes.
fn written_route(graph: &CodeGraph, route: &GraphPath) -> String {
    format!(
        "{}|{}",
        given::names(graph, route.nodes()).join(","),
        given::edge_texts(graph, route.edges()).join(",")
    )
}
