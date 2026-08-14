//! What a caller still holds after the cache lets go, and what several threads
//! reading one handle converge on.
//!
//! The cache owns strong references, never the only ones. Clearing a graph's
//! derived state, clearing the cache, evicting the entry, and dropping the
//! cache itself must leave every handle and every product a caller kept valid,
//! immutable, and answering the same way.

use std::sync::Arc;
use std::thread;

use pedant_graph::{
    CachedCodeGraph, CachedGraphAnalysis, DegreeCentrality, GraphAnalysis, GraphDirection,
    GraphEdgeSelection, GraphLimits, GraphNodeId,
};

use super::analysis_fixture::{degree_texts, generous_limits, neighbor_texts};
use super::cache_analysis_reading::{first_node, readings};
use super::cache_counting::{
    DERIVED_PRODUCT_EVICTIONS, DERIVED_PRODUCT_HITS, DERIVED_PRODUCT_MISSES,
    SELECTED_INDEX_EVICTIONS, SELECTED_INDEX_HITS, SELECTED_INDEX_MISSES, assert_delta,
};
use super::cache_fixture::{cached_workspace, derived_only, generous};
use super::corpus::GRAPH_CORPUS;

/// How many threads read one cloned handle at once.
const WORKERS: u64 = 4;

/// What one worker returns: the metric allocation it was handed, beside every
/// answer it read through its own clone of the handle.
type WorkerReading = (Arc<[DegreeCentrality]>, Vec<(String, String)>);

/// Clearing, evicting, and dropping leave every caller-held value valid.
pub fn assert_clear_eviction_and_drop_keep_live_handles_valid() {
    assert_clearing_and_dropping_keep_held_values_valid();
    assert_eviction_keeps_held_values_valid();
}

/// Both clear methods and the drop of the cache itself leave every held value
/// answering as it did.
fn assert_clearing_and_dropping_keep_held_values_valid() {
    let (resolved, mut cache, held) = cached_workspace(GRAPH_CORPUS, generous());
    let selection = GraphEdgeSelection::all();
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("admitted");
    let clone = analysis.clone();
    let graph_clone = held.clone();
    let seed = first_node(held.graph());
    let neighbors = analysis
        .neighbors(seed, 2, GraphDirection::Both)
        .expect("answered");
    let degrees = analysis.degree_centrality();
    let expected = readings(&analysis, seed);

    held.clear_analysis_cache();
    assert_eq!(
        readings(&clone, seed),
        expected,
        "clearing the derived state changes no answer"
    );
    cache.clear();
    assert_eq!(
        readings(&clone, seed),
        expected,
        "clearing the cache changes no answer"
    );

    let rebuilt = cache
        .build_rust_graph(
            &resolved.snapshot,
            &resolved.resolution,
            GraphLimits::default(),
        )
        .expect("the same claim rebuilds");
    assert_eq!(
        rebuilt.graph(),
        graph_clone.graph(),
        "a rebuilt graph equals the graph a caller still holds"
    );
    let cumulative = graph_clone.stats();
    drop(cache);
    drop(rebuilt);
    assert_eq!(
        readings(&clone, seed),
        expected,
        "dropping the cache changes no answer"
    );
    assert_eq!(
        graph_clone.stats().exact_graph_misses(),
        cumulative.exact_graph_misses(),
        "cumulative statistics survive the cache that produced them"
    );
    assert_eq!(
        neighbor_texts(graph_clone.graph(), &neighbors),
        neighbor_texts(
            clone.graph(),
            &clone
                .neighbors(seed, 2, GraphDirection::Both)
                .expect("answered")
        ),
        "a product held across clear and drop still states its own answer"
    );
    // The metric is read against the direct one rather than against its own
    // length: an allocation's length cannot change when the cache lets go of
    // it, so a held metric whose scores were corrupted would satisfy a length.
    let direct = GraphAnalysis::new(graph_clone.graph(), selection, generous_limits())
        .expect("the direct analysis builds over the graph a caller still holds");
    assert_eq!(
        degree_texts(graph_clone.graph(), &direct.degree_centrality()),
        degree_texts(graph_clone.graph(), &degrees),
        "a metric held across clear and drop still states the direct metric"
    );
}

/// Bounded retention displaces an index set and a product a caller is holding,
/// and neither held value notices.
///
/// Both ceilings are one, so every entry this case retains is displaced by the
/// next one while the caller still holds it. The displacement is required by
/// its counters first: a ceiling that dropped nothing would leave the claim
/// below proving only that a live entry answers.
fn assert_eviction_keeps_held_values_valid() {
    let (_resolved, _cache, held) = cached_workspace(GRAPH_CORPUS, derived_only(1, 1));
    let selection = GraphEdgeSelection::all();
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("admitted");
    let seed = first_node(held.graph());

    let retained = held.stats();
    let neighbors = analysis
        .neighbors(seed, 2, GraphDirection::Both)
        .expect("answered");
    let degrees = analysis.degree_centrality();
    assert_delta(
        retained,
        held.stats(),
        &[(DERIVED_PRODUCT_MISSES, 2), (DERIVED_PRODUCT_EVICTIONS, 1)],
        "a second product displaces the neighborhood a caller still holds",
    );

    let indexed = held.stats();
    held.analyze(GraphEdgeSelection::code_relations(), generous_limits())
        .expect("a second selection is admitted");
    assert_delta(
        indexed,
        held.stats(),
        &[(SELECTED_INDEX_MISSES, 1), (SELECTED_INDEX_EVICTIONS, 1)],
        "a second selection displaces the index set a caller still holds",
    );

    let direct = GraphAnalysis::new(held.graph(), selection, generous_limits())
        .expect("the direct analysis builds");
    assert_eq!(
        readings(&analysis, seed),
        readings(&direct, seed),
        "an analysis held across the eviction of its index set answers as the direct analysis does"
    );
    assert_eq!(
        neighbor_texts(held.graph(), &neighbors),
        neighbor_texts(
            held.graph(),
            &direct
                .neighbors(seed, 2, GraphDirection::Both)
                .expect("answered")
        ),
        "a product held across its own eviction still states its answer"
    );
    assert_eq!(
        degree_texts(held.graph(), &direct.degree_centrality()),
        degree_texts(held.graph(), &degrees),
        "a metric held across a later eviction still states the direct metric"
    );
}

/// Cloned handles answer the same way from several threads, and converge on one
/// retained allocation.
pub fn assert_cached_analysis_is_thread_shareable_and_deterministic() {
    let (_resolved, _cache, held) = cached_workspace(GRAPH_CORPUS, generous());
    let selection = GraphEdgeSelection::all();
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("admitted");
    let seed = first_node(held.graph());
    let direct = GraphAnalysis::new(held.graph(), selection, generous_limits())
        .expect("the direct analysis builds");
    // Stated by the borrowed analysis, so the scope below starts with nothing
    // derived: a product this graph already retained would be a hit whatever
    // the threads did with it.
    let expected = readings(&direct, seed);
    let claims = claimed(expected.len());

    let before = held.stats();
    let answers = read_from_threads(&held, &analysis, (selection, seed));
    assert_delta(
        before,
        held.stats(),
        &[
            (SELECTED_INDEX_HITS, WORKERS),
            (DERIVED_PRODUCT_MISSES, claims),
            (DERIVED_PRODUCT_HITS, WORKERS * claims + WORKERS - claims),
        ],
        "every claim several threads ask for is derived exactly once",
    );

    let settled = analysis.degree_centrality();
    for (metric, answer) in &answers {
        assert_eq!(
            answer, &expected,
            "every thread reads the same derived answers"
        );
        assert!(
            Arc::ptr_eq(metric, &settled),
            "every thread answered with the one allocation the store retained"
        );
    }
    assert_eq!(
        degree_texts(held.graph(), &direct.degree_centrality()),
        degree_texts(held.graph(), &settled),
        "the shared metric equals the direct one"
    );
}

/// Every worker's own metric beside every answer it read, with the scope closed.
///
/// Each worker states its own analysis over a cloned graph handle and returns
/// the allocation it was given, so what the joined case compares is what the
/// threads themselves produced rather than what one later call answers with.
fn read_from_threads(
    held: &CachedCodeGraph,
    analysis: &CachedGraphAnalysis,
    asked: (GraphEdgeSelection, GraphNodeId),
) -> Vec<WorkerReading> {
    let (selection, seed) = asked;
    thread::scope(|scope| {
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let handle = analysis.clone();
                let graph = held.clone();
                scope.spawn(move || {
                    let reread = graph
                        .analyze(selection, generous_limits())
                        .expect("a cloned graph admits the same analysis");
                    (reread.degree_centrality(), readings(&handle, seed))
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("every worker finishes"))
            .collect()
    })
}

/// How many distinct products one reading asks for.
///
/// Every row but the declared partition is one product claim, and the partition
/// is derived with the indexes rather than retained beside them.
fn claimed(rows: usize) -> u64 {
    u64::try_from(rows - 1).expect("a reading states fewer rows than u64 can count")
}
