//! A cached analysis answers exactly as the direct analysis answers, and every
//! applicable ceiling is proved again before a retained value is returned.
//!
//! Every case enters through the published API over a real temporary Cargo
//! repository. The repository is released before the assertions run, because a
//! projected graph owns everything it answers with; the only resources a case
//! here owns are the handles it holds.

use pedant_graph::{
    CachedCodeGraph, GraphAnalysis, GraphAnalysisLimits, GraphDirection, GraphEdgeSelection,
    GraphNodeId,
};

use super::analysis_fixture::{foreign_node, generous_limits, metric_selections};
use super::cache_analysis_reading::{AnalysisReading, Asked, Walk, first_node, rows};
use super::cache_counting::{SELECTED_INDEX_HITS, assert_delta};
use super::cache_fixture::{cached_workspace, generous};
use super::corpus::GRAPH_CORPUS;
use super::corpus_analysis::ANALYSIS_TRAVERSAL_CORPUS;

/// The cached and direct analyses answer identically for every operation,
/// argument, and refusal a caller can state.
pub fn assert_cached_analysis_matches_every_direct_operation() {
    for (label, files) in [
        ("the mixed-edge corpus", GRAPH_CORPUS),
        ("the traversal corpus", ANALYSIS_TRAVERSAL_CORPUS),
    ] {
        let (_resolved, _cache, held) = cached_workspace(files, generous());
        let asked = Asked::over(held.graph());
        for (selection_label, selection) in metric_selections() {
            let subject = format!("{label} at {selection_label}");
            assert_selection_matches(&held, selection, &asked, &subject);
        }
    }
    assert_refusals_match_direct();
}

/// One selection, answered the same way by both analyses.
fn assert_selection_matches(
    held: &CachedCodeGraph,
    selection: GraphEdgeSelection,
    asked: &Asked,
    subject: &str,
) {
    let limits = generous_limits();
    let direct = GraphAnalysis::new(held.graph(), selection, limits)
        .unwrap_or_else(|error| panic!("{subject}: the direct analysis should build: {error}"));
    let cached = held
        .analyze(selection, limits)
        .unwrap_or_else(|error| panic!("{subject}: the cached analysis should build: {error}"));
    assert_eq!(
        (cached.selection(), cached.limits()),
        (selection, limits),
        "{subject}: the cached analysis states the arguments it was built with"
    );
    assert_eq!(
        (direct.selection(), direct.limits()),
        (selection, limits),
        "{subject}: the direct analysis states the arguments it was built with"
    );
    assert!(
        std::ptr::eq(cached.graph(), held.graph()),
        "{subject}: a cached analysis reads the graph its handle holds"
    );
    let expected = rows(&direct, asked);
    let observed = rows(&cached, asked);
    for (stated, answered) in expected.iter().zip(&observed) {
        assert_eq!(
            stated, answered,
            "{subject}: the cached and direct answers differ"
        );
    }
}

/// Every refusal a caller can provoke is the refusal the direct analysis
/// returns.
fn assert_refusals_match_direct() {
    let (_resolved, _cache, held) = cached_workspace(ANALYSIS_TRAVERSAL_CORPUS, generous());
    let selection = GraphEdgeSelection::code_relations();
    let unknown = foreign_node(held.graph());
    let shallow = GraphAnalysisLimits::new(u32::MAX, u32::MAX, 1, u64::MAX);
    for (label, limits, node, depth) in [
        ("an unknown node", generous_limits(), unknown, 1_u32),
        (
            "a depth above the ceiling",
            shallow,
            first_node(held.graph()),
            4,
        ),
        // Both refusals at once. Each analysis states one of them, and which
        // one is the order the walk owner proves them in: a node this graph
        // holds no record for is refused as unknown, whatever depth was asked
        // of it.
        ("an unknown node above the ceiling", shallow, unknown, 4),
    ] {
        let direct = GraphAnalysis::new(held.graph(), selection, limits)
            .unwrap_or_else(|error| panic!("{label}: the direct analysis should build: {error}"));
        let cached = held
            .analyze(selection, limits)
            .unwrap_or_else(|error| panic!("{label}: the cached analysis should build: {error}"));
        let asked = Asked::one(
            Walk::new(node, depth, GraphDirection::Outgoing),
            (node, node),
        );
        assert_eq!(
            rows(&cached, &asked),
            rows(&direct, &asked),
            "{label}: both analyses refuse identically"
        );
    }
    assert_refusal_parity(&held, selection);
}

/// Every admission ceiling below the graph refuses through both constructors,
/// in the same words, and examines nothing the cache retained.
///
/// Shared: the operation owner reads this over a cold graph and the ceiling
/// owner reads it over a warmed one, and both ask the same question of the same
/// three ceilings. Each row states its counter delta, so a refusal that reached
/// a retained index or product before it refused is caught here rather than
/// left to the row that names the ceiling.
fn assert_refusal_parity(held: &CachedCodeGraph, selection: GraphEdgeSelection) {
    for (label, limits) in [
        (
            "a node ceiling of zero",
            GraphAnalysisLimits::new(0, u32::MAX, u32::MAX, u64::MAX),
        ),
        (
            "a node ceiling below the graph",
            GraphAnalysisLimits::new(1, u32::MAX, u32::MAX, u64::MAX),
        ),
        (
            "a selected-edge ceiling below the selection",
            GraphAnalysisLimits::new(u32::MAX, 0, u32::MAX, u64::MAX),
        ),
    ] {
        let before = held.stats();
        let refused = held
            .analyze(selection, limits)
            .err()
            .unwrap_or_else(|| panic!("{label} must refuse"));
        let directly = GraphAnalysis::new(held.graph(), selection, limits)
            .err()
            .unwrap_or_else(|| panic!("{label} must refuse directly"));
        assert_eq!(
            format!("{refused:?}"),
            format!("{directly:?}"),
            "{label}: the cached refusal is the direct refusal"
        );
        assert_delta(before, held.stats(), &[], label);
    }
}

/// Every applicable ceiling is proved again before a retained value answers.
pub fn assert_cached_analysis_rechecks_every_limit_before_hits() {
    let (_resolved, _cache, held) = cached_workspace(GRAPH_CORPUS, generous());
    let selection = GraphEdgeSelection::all();
    let seed = first_node(held.graph());
    warm(&held, selection, seed);
    assert_refusal_parity(&held, selection);
    assert_query_ceilings_dominate(&held, selection, seed);
}

/// Every bounded operation answered once under permissive ceilings, so each
/// case below has a retained value to try to bypass its ceiling with.
fn warm(held: &CachedCodeGraph, selection: GraphEdgeSelection, seed: GraphNodeId) {
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("permissive ceilings admit the analysis");
    analysis
        .neighbors(seed, 3, GraphDirection::Both)
        .expect("a warm neighborhood");
    analysis
        .subgraph(seed, 3, GraphDirection::Both)
        .expect("a warm subgraph");
    analysis.betweenness_centrality().expect("warm centrality");
    analysis.layout_assist().expect("warm layout metadata");
}

/// A stricter depth or work ceiling refuses before any retained product is
/// examined.
fn assert_query_ceilings_dominate(
    held: &CachedCodeGraph,
    selection: GraphEdgeSelection,
    seed: GraphNodeId,
) {
    let before = held.stats();
    assert_depth_ceiling_dominates(held, selection, seed);
    assert_work_ceiling_dominates(held, selection);
    assert_delta(
        before,
        held.stats(),
        &[(SELECTED_INDEX_HITS, 2)],
        "a refused query examines no product",
    );
}

/// A depth ceiling below the walk refuses it, whatever a deeper walk retained.
fn assert_depth_ceiling_dominates(
    held: &CachedCodeGraph,
    selection: GraphEdgeSelection,
    seed: GraphNodeId,
) {
    let limits = GraphAnalysisLimits::new(u32::MAX, u32::MAX, 1, u64::MAX);
    let cached = held
        .analyze(selection, limits)
        .expect("a lower depth ceiling still admits the analysis");
    let directly = GraphAnalysis::new(held.graph(), selection, limits)
        .expect("the direct analysis admits the same ceilings");
    let walk = Walk::new(seed, 3, GraphDirection::Both);
    assert_refuses_identically(
        "a warm neighborhood above the depth ceiling",
        &cached.neighbor_row(walk),
        &directly.neighbor_row(walk),
    );
    assert_refuses_identically(
        "a warm subgraph above the depth ceiling",
        &cached.subgraph_row(walk),
        &directly.subgraph_row(walk),
    );
}

/// A work ceiling below the answer refuses it, whatever a generous budget
/// retained.
fn assert_work_ceiling_dominates(held: &CachedCodeGraph, selection: GraphEdgeSelection) {
    let limits = GraphAnalysisLimits::new(u32::MAX, u32::MAX, u32::MAX, 1);
    let cached = held
        .analyze(selection, limits)
        .expect("a lower work ceiling still admits the analysis");
    let directly = GraphAnalysis::new(held.graph(), selection, limits)
        .expect("the direct analysis admits the same ceilings");
    assert_refuses_identically(
        "warm centrality above the work ceiling",
        &cached.betweenness_row(),
        &directly.betweenness_row(),
    );
    assert_refuses_identically(
        "warm layout metadata above the work ceiling",
        &cached.layout_row(),
        &directly.layout_row(),
    );
}

/// One operation refused by both analyses, in the same words.
fn assert_refuses_identically(label: &str, cached: &str, directly: &str) {
    assert_eq!(
        cached, directly,
        "{label}: both analyses refuse identically"
    );
    assert!(
        cached.starts_with("refused|"),
        "{label}: a retained answer cannot bypass the current ceiling"
    );
}
