//! One allocation per repeated claim, and what states a different claim.
//!
//! A retained product is shared rather than copied, so a repeated operation
//! must answer with the allocation the first one produced. Every dimension of
//! the claim — the graph, the selection, the operation, and each argument it
//! takes — must state a different product instead.

use std::sync::Arc;

use pedant_graph::{
    CachedCodeGraph, CachedGraphAnalysis, CodeGraph, GraphAnalysis, GraphAnalysisError, GraphCache,
    GraphDirection, GraphEdgeSelection, GraphNeighbor, GraphNodeId,
};

use super::analysis_fixture::generous_limits;
use super::cache_analysis_reading::{first_node, next_node, node_ids, ordered_pairs};
use super::cache_counting::{
    DERIVED_PRODUCT_HITS, DERIVED_PRODUCT_MISSES, SELECTED_INDEX_MISSES, assert_delta,
};
use super::cache_fixture::{admitted, cached_workspace, generous, pair};
use super::corpus::GRAPH_CORPUS;
use super::corpus_analysis::ANALYSIS_TRAVERSAL_CORPUS;
use super::fixture::{self, CORPUS_LIBRARY};

/// Every repeated data-returning operation answers with the same allocation,
/// and every key dimension invalidates.
pub fn assert_cached_analysis_reuses_exact_arc_products_and_none() {
    let (_resolved, mut cache, held) = cached_workspace(GRAPH_CORPUS, generous());
    let selection = GraphEdgeSelection::all();
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("the mixed-edge corpus admits an analysis");
    let seed = first_node(held.graph());
    assert_repeats_share_allocation(&held, &analysis, seed);
    assert_unreachable_path_is_retained(&held, &analysis);
    assert_every_key_dimension_invalidates(&held, seed);
    assert_another_graph_retains_nothing(&mut cache, &held);
}

/// Each data-returning operation, asked twice, answers with one allocation and
/// one product hit.
fn assert_repeats_share_allocation(
    held: &CachedCodeGraph,
    analysis: &CachedGraphAnalysis,
    seed: GraphNodeId,
) {
    let (node, depth, direction) = (seed, 2_u32, GraphDirection::Both);
    shared_twice(held, "neighbors", || {
        analysis.neighbors(node, depth, direction)
    });
    shared_twice(held, "subgraph", || {
        analysis.subgraph(node, depth, direction)
    });
    shared_twice(held, "degree", || Ok(analysis.degree_centrality()));
    shared_twice(held, "betweenness", || analysis.betweenness_centrality());
    shared_twice(held, "components", || {
        Ok(analysis.strongly_connected_components())
    });
    shared_twice(held, "condensation", || Ok(analysis.condensation()));
    shared_twice(held, "divergence", || Ok(analysis.divergence()));
    shared_twice(held, "layout", || analysis.layout_assist());
}

/// One operation asked twice: one allocation, one miss, and one hit.
fn shared_twice<T: ?Sized>(
    held: &CachedCodeGraph,
    label: &str,
    ask: impl Fn() -> Result<Arc<T>, GraphAnalysisError>,
) {
    let before = held.stats();
    let first =
        ask().unwrap_or_else(|error| panic!("{label}: the warm operation answers: {error}"));
    let second =
        ask().unwrap_or_else(|error| panic!("{label}: the repeated operation answers: {error}"));
    assert!(
        Arc::ptr_eq(&first, &second),
        "{label}: a repeated operation shares its answer"
    );
    assert_delta(
        before,
        held.stats(),
        &[(DERIVED_PRODUCT_MISSES, 1), (DERIVED_PRODUCT_HITS, 1)],
        label,
    );
}

/// A route that does not exist is retained, so asking again is a hit.
fn assert_unreachable_path_is_retained(held: &CachedCodeGraph, analysis: &CachedGraphAnalysis) {
    let (source, target) = unreachable_pair(held.graph(), analysis.selection());
    let before = held.stats();
    let first = analysis
        .path(source, target)
        .expect("the route is answered");
    let second = analysis
        .path(source, target)
        .expect("the route is answered");
    assert!(
        first.is_none() && second.is_none(),
        "the chosen pair states no route"
    );
    assert_delta(
        before,
        held.stats(),
        &[(DERIVED_PRODUCT_MISSES, 1), (DERIVED_PRODUCT_HITS, 1)],
        "a repeated unreachable route",
    );
}

/// The first ordered node pair with no route between them.
///
/// Found through the borrowed analysis, so the search itself retains nothing
/// and the pair the case then asks about is one the cached store has never
/// seen.
fn unreachable_pair(
    graph: &CodeGraph,
    selection: GraphEdgeSelection,
) -> (GraphNodeId, GraphNodeId) {
    let direct = GraphAnalysis::new(graph, selection, generous_limits())
        .expect("the direct analysis builds");
    let held = node_ids(graph);
    ordered_pairs(&held)
        .find(|(source, target)| {
            direct
                .path(*source, *target)
                .expect("the route is answered")
                .is_none()
        })
        .unwrap_or_else(|| panic!("this corpus states a route between every ordered pair"))
}

/// Changing the graph, the selection, the operation, or any argument states a
/// different product.
///
/// Each varied argument is read as a miss followed by a hit. A pointer
/// inequality on its own is satisfied by a store that retains nothing at all,
/// so what separates "this key is a different key" from "there is no store" is
/// the counter pair: the varied row must derive once and then answer from what
/// it retained.
fn assert_every_key_dimension_invalidates(held: &CachedCodeGraph, seed: GraphNodeId) {
    let analysis = held
        .analyze(GraphEdgeSelection::all(), generous_limits())
        .expect("the analysis is admitted");
    let warm = analysis
        .neighbors(seed, 2, GraphDirection::Outgoing)
        .expect("the warm neighborhood");
    let second = next_node(held.graph(), seed);
    for (label, node, depth, direction) in [
        ("a different node", second, 2_u32, GraphDirection::Outgoing),
        ("a different depth", seed, 3, GraphDirection::Outgoing),
        ("a different direction", seed, 2, GraphDirection::Incoming),
    ] {
        let missed = held.stats();
        let other = analysis
            .neighbors(node, depth, direction)
            .expect("answered");
        assert_delta(
            missed,
            held.stats(),
            &[(DERIVED_PRODUCT_MISSES, 1)],
            &format!("{label} is derived rather than reused"),
        );
        assert!(
            !Arc::ptr_eq(&warm, &other),
            "{label} states a different product"
        );

        let retained = held.stats();
        let repeated = analysis
            .neighbors(node, depth, direction)
            .expect("answered");
        assert_delta(
            retained,
            held.stats(),
            &[(DERIVED_PRODUCT_HITS, 1)],
            &format!("{label} takes its own entry"),
        );
        assert!(
            Arc::ptr_eq(&other, &repeated),
            "{label} answers again from the entry it took"
        );
    }
    assert_selection_invalidates(held, &analysis, (seed, &warm));
}

/// A second selection over the same graph states its own products.
///
/// Read as two misses and then a hit, for the same reason the argument rows
/// are: a store holding nothing would satisfy every pointer inequality here.
fn assert_selection_invalidates(
    held: &CachedCodeGraph,
    analysis: &CachedGraphAnalysis,
    warm: (GraphNodeId, &Arc<[GraphNeighbor]>),
) {
    let (seed, neighbors) = warm;
    let narrowed = held
        .analyze(GraphEdgeSelection::code_relations(), generous_limits())
        .expect("a second selection is admitted");

    let missed = held.stats();
    let elsewhere = narrowed
        .neighbors(seed, 2, GraphDirection::Outgoing)
        .expect("answered");
    let metric = narrowed.degree_centrality();
    assert_delta(
        missed,
        held.stats(),
        &[(DERIVED_PRODUCT_MISSES, 2)],
        "a second selection derives its own products",
    );
    assert!(
        !Arc::ptr_eq(neighbors, &elsewhere),
        "a different selection states a different product"
    );
    assert!(
        !Arc::ptr_eq(&analysis.degree_centrality(), &metric),
        "a different selection states a different metric"
    );

    let retained = held.stats();
    let repeated = narrowed
        .neighbors(seed, 2, GraphDirection::Outgoing)
        .expect("answered");
    assert_delta(
        retained,
        held.stats(),
        &[(DERIVED_PRODUCT_HITS, 1)],
        "the second selection takes its own entry",
    );
    assert!(
        Arc::ptr_eq(&elsewhere, &repeated),
        "the second selection answers again from the entry it took"
    );
}

/// A second graph in the same cache derives everything itself, whatever the
/// first graph retained.
///
/// Both corpora are built through one [`GraphCache`], so the store the second
/// graph queries is the store the first graph filled. A product claim carrying
/// only the selection and the operation would let the first graph's retained
/// metric answer here; what this row requires is a miss on each derived
/// category, read around the second graph alone.
fn assert_another_graph_retains_nothing(cache: &mut GraphCache, first: &CachedCodeGraph) {
    let selection = GraphEdgeSelection::all();
    let warm = first
        .analyze(selection, generous_limits())
        .expect("the first graph is admitted");
    warm.degree_centrality();

    let (_repository, resolved) =
        fixture::resolve_target(ANALYSIS_TRAVERSAL_CORPUS, CORPUS_LIBRARY);
    let elsewhere = admitted(cache, pair(&resolved), "the second graph");
    assert!(
        !std::ptr::eq(first.graph(), elsewhere.graph()),
        "one cache holds two distinct graphs"
    );

    let before = elsewhere.stats();
    let analysis = elsewhere
        .analyze(selection, generous_limits())
        .expect("the second graph is admitted");
    analysis.degree_centrality();
    assert_delta(
        before,
        elsewhere.stats(),
        &[(SELECTED_INDEX_MISSES, 1), (DERIVED_PRODUCT_MISSES, 1)],
        "another graph in the same cache retains nothing this graph derived",
    );
}
