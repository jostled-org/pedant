//! Degree and directed betweenness over the shared selected indexes.
//!
//! Every score is compared against [`super::analysis_oracle`], which enumerates
//! shortest routes instead of accumulating dependencies, so agreement is
//! agreement between two implementations of one definition.

use std::collections::BTreeSet;

use pedant_graph::{
    CodeGraph, GraphAnalysis, GraphAnalysisLimits, GraphEdgeSelection, GraphNodeId,
};

use super::analysis_fixture as given;
use super::analysis_oracle as oracle;
use super::corpus_analysis::ANALYSIS_PAIR_CORPUS;
use super::corpus_generated::{
    TOPOLOGY_MODULES, TOPOLOGY_WIDTH, diamond_corpus, topology_corpus, topology_name,
    topology_states,
};

/// How far a compared score may sit from the model's own answer.
const TOLERANCE: f64 = 1e-12;

/// The branch multiplicities the diamond corpus is stated at.
const MULTIPLICITIES: [usize; 3] = [1, 2, 3];

/// Degree and betweenness match the slow models on every stated topology.
pub fn assert_degree_and_betweenness_match_oracles() {
    let exhaustive = given::generated_graph(&topology_corpus());
    assert_topology_states_every_subset(&exhaustive);
    assert_metrics_match(
        &exhaustive,
        given::calls_only(),
        "every three-node topology",
    );

    for multiplicity in MULTIPLICITIES {
        let diamond = given::generated_graph(&diamond_corpus(multiplicity));
        assert_metrics_match(
            &diamond,
            given::calls_only(),
            &format!("a diamond of multiplicity {multiplicity}"),
        );
    }

    assert_parallel_and_self_loop_degrees();
    assert_small_graphs_normalize_to_zero();
}

/// The generated corpus states exactly the subsets it claims to.
///
/// Read from the raw graph rather than from the analysis, so the corpus is
/// proved to cover every topology before any score computed over it is trusted.
fn assert_topology_states_every_subset(graph: &CodeGraph) {
    let selection = given::calls_only();
    assert_eq!(
        graph.nodes().len(),
        2 + TOPOLOGY_MODULES * (1 + TOPOLOGY_WIDTH),
        "one unit root, one source, and one container and three functions per \
         stated subset"
    );
    let mut realized: Vec<(String, String)> = graph
        .edges()
        .iter()
        .filter(|edge| selection.allows(edge))
        .map(|edge| {
            (
                given::name(graph, edge.source()),
                given::name(graph, edge.target()),
            )
        })
        .collect();
    realized.sort();

    let mut stated: Vec<(String, String)> = (0..TOPOLOGY_MODULES).flat_map(stated_calls).collect();
    stated.sort();

    assert_eq!(
        realized.len(),
        TOPOLOGY_MODULES * TOPOLOGY_WIDTH * TOPOLOGY_WIDTH / 2,
        "each ordered pair is stated by exactly half of the subsets"
    );
    assert_eq!(
        realized, stated,
        "the projected call topology is exactly the subsets the corpus states"
    );
}

/// Every call one topology subset states, by function name.
fn stated_calls(subset: usize) -> Vec<(String, String)> {
    (0..TOPOLOGY_WIDTH)
        .flat_map(|from| (0..TOPOLOGY_WIDTH).map(move |to| (from, to)))
        .filter(|(from, to)| topology_states(subset, *from, *to))
        .map(|(from, to)| (topology_name(subset, from), topology_name(subset, to)))
        .collect()
}

/// Both metrics over one graph equal the models computed from its raw edges.
fn assert_metrics_match(graph: &CodeGraph, selection: GraphEdgeSelection, subject: &str) {
    let analysis = given::analysis(graph, selection);
    let edges = oracle::selected(graph, selection);
    assert_degrees_match(graph, &analysis, &edges, subject);
    assert_betweenness_matches(graph, &analysis, &edges, subject);
    assert_some_route_has_an_interior(&analysis, subject);
}

/// The corpus states at least one route a third node sits inside.
///
/// Two implementations agreeing that every score is zero would agree about
/// nothing, so each compared corpus is proved to state a route worth measuring.
fn assert_some_route_has_an_interior(analysis: &GraphAnalysis<'_>, subject: &str) {
    let scores = analysis
        .betweenness_centrality()
        .unwrap_or_else(|error| panic!("{subject}: {error}"));
    assert!(
        scores.iter().any(|record| record.raw() > 0.0),
        "{subject}: a compared corpus must route through something"
    );
}

/// Degree counts every selected edge once at each of its ends.
fn assert_degrees_match(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    edges: &[oracle::SelectedEdge],
    subject: &str,
) {
    let counted = analysis.degree_centrality();
    assert_records_are_dense(counted.iter().map(|record| record.node()), subject);
    assert_eq!(
        counted
            .iter()
            .map(|record| (record.incoming(), record.outgoing()))
            .collect::<Vec<(u32, u32)>>(),
        oracle::degrees(graph.nodes().len(), edges),
        "{subject}: degree reads exactly the selected edges"
    );
}

/// Raw and normalized betweenness equal the enumerating model's answers.
fn assert_betweenness_matches(
    graph: &CodeGraph,
    analysis: &GraphAnalysis<'_>,
    edges: &[oracle::SelectedEdge],
    subject: &str,
) {
    let nodes = graph.nodes().len();
    let scores = analysis
        .betweenness_centrality()
        .unwrap_or_else(|error| panic!("{subject}: {error}"));
    assert_records_are_dense(scores.iter().map(|record| record.node()), subject);
    let modelled = oracle::raw_betweenness(nodes, edges);
    assert_eq!(
        scores.len(),
        modelled.len(),
        "{subject}: one score per raw node"
    );
    for (record, expected) in scores.iter().zip(&modelled) {
        assert_close(record.raw(), *expected, subject, "raw");
        assert_close(
            record.normalized(),
            oracle::normalized(nodes, *expected),
            subject,
            "normalized",
        );
    }
}

/// One record per raw node, in raw node-id order.
fn assert_records_are_dense(nodes: impl Iterator<Item = GraphNodeId>, subject: &str) {
    let listed: Vec<u32> = nodes.map(|node| node.index()).collect();
    assert_eq!(
        listed,
        (0..listed.len() as u32).collect::<Vec<u32>>(),
        "{subject}: one record per raw node, in raw node-id order"
    );
}

/// One measured score sits within tolerance of the model, and both are finite.
fn assert_close(measured: f64, modelled: f64, subject: &str, label: &str) {
    assert!(
        measured.is_finite(),
        "{subject}: the {label} score {measured} is not finite"
    );
    assert!(
        (measured - modelled).abs() <= TOLERANCE,
        "{subject}: the {label} score {measured} differs from the model {modelled}"
    );
}

/// Parallel calls count separately and a self-loop counts once at each end.
fn assert_parallel_and_self_loop_degrees() {
    let graph = given::traversal_graph();
    let analysis = given::analysis(&graph, given::calls_only());
    let degrees = analysis.degree_centrality();
    let counted = |name: &str| {
        let node = given::definition(&graph, name);
        let record = degrees[node.index() as usize];
        (record.incoming(), record.outgoing())
    };
    assert_eq!(
        counted("seed"),
        (1, 3),
        "two parallel calls to left and one to right count as three"
    );
    assert_eq!(
        counted("left"),
        (2, 1),
        "both parallel calls arrive, and the one call out leaves"
    );
    assert_eq!(
        counted("wheel"),
        (1, 1),
        "a self-loop counts once incoming and once outgoing"
    );
    assert_eq!(counted("stranded"), (0, 0), "an isolate counts nothing");
}

/// A graph too small for an interior node normalizes every score to zero.
fn assert_small_graphs_normalize_to_zero() {
    let graph = given::graph_of(ANALYSIS_PAIR_CORPUS);
    assert_eq!(
        graph.nodes().len(),
        2,
        "the smallest real repository states one unit root and one source"
    );
    let analysis = given::analysis(&graph, GraphEdgeSelection::all());
    let scores = analysis
        .betweenness_centrality()
        .expect("the smallest graph is far below every ceiling");
    assert_eq!(
        scores
            .iter()
            .map(|record| (record.raw(), record.normalized()))
            .collect::<Vec<(f64, f64)>>(),
        vec![(0.0, 0.0); 2],
        "below three nodes no ordered pair has an interior, so every score is zero"
    );
}

/// Both metrics answer over the selection their analysis was built from.
pub fn assert_metric_selection_reuses_indexes() {
    let graph = given::selection_graph();
    let mut rendered: BTreeSet<Vec<String>> = BTreeSet::new();
    for (label, selection) in given::metric_selections() {
        let analysis = given::analysis(&graph, selection);
        let edges = oracle::selected(&graph, selection);
        assert_degrees_match(&graph, &analysis, &edges, label);
        assert_betweenness_matches(&graph, &analysis, &edges, label);
        rendered.insert(given::degree_texts(&graph, &analysis.degree_centrality()));
    }
    assert_eq!(
        rendered.len(),
        given::metric_selections().len(),
        "each stated selection answers with degrees of its own"
    );
}

/// Betweenness refuses its stated work ceiling before it walks, and no answer
/// and no refusal is spent by taking it.
///
/// One admitted analysis answers on both sides of the refusals, and each
/// refusing analysis is asked twice, so a query that consumed its own indexes
/// would be caught rather than hidden behind a fresh view.
pub fn assert_betweenness_refuses_work() {
    let graph = given::traversal_graph();
    let selection = given::calls_only();
    let nodes = graph.nodes().len() as u64;
    let selected = oracle::selected(&graph, selection).len() as u64;
    let required = nodes * (nodes + selected);

    let admitted = bounded(&graph, selection, required);
    let before = admitted_scores(&graph, &admitted);
    assert_eq!(
        before.len() as u64,
        nodes,
        "a ceiling equal to the required work admits every score"
    );

    for lowered in [required - 1, required / 2, 0] {
        assert_refusal_repeats(&graph, selection, lowered, required);
    }

    assert_eq!(
        admitted_scores(&graph, &admitted),
        before,
        "a refusal consumes nothing: the analysis that already answered answers \
         the same again"
    );
}

/// One admitted analysis's betweenness scores, as comparable text.
fn admitted_scores(graph: &CodeGraph, analysis: &GraphAnalysis<'_>) -> Vec<String> {
    let scores = analysis
        .betweenness_centrality()
        .unwrap_or_else(|error| panic!("this ceiling admits every score: {error}"));
    given::betweenness_texts(graph, &scores)
}

/// One lowered ceiling names the same work and the same ceiling every time it
/// is asked.
fn assert_refusal_repeats(
    graph: &CodeGraph,
    selection: GraphEdgeSelection,
    lowered: u64,
    required: u64,
) {
    let refusing = bounded(graph, selection, lowered);
    let expected = format!("betweenness needs {required} steps, above the ceiling of {lowered}");
    for attempt in ["asked once", "asked again"] {
        let refused = refusing
            .betweenness_centrality()
            .err()
            .unwrap_or_else(|| panic!("{attempt}: a ceiling of {lowered} was admitted"));
        assert_eq!(
            refused.to_string(),
            expected,
            "{attempt}: the refusal names the work it needed and the ceiling it \
             was given"
        );
    }
}

/// One analysis whose only meaningful ceiling is the betweenness work bound.
fn bounded(graph: &CodeGraph, selection: GraphEdgeSelection, work: u64) -> GraphAnalysis<'_> {
    GraphAnalysis::new(
        graph,
        selection,
        GraphAnalysisLimits::new(u32::MAX, u32::MAX, u32::MAX, work),
    )
    .expect("the corpus is far below every other ceiling")
}
