//! What one graph's derived state retains, what it drops first, and what it
//! counts.
//!
//! Both derived categories are bounded per graph, so a ceiling of zero must
//! retain nothing while still answering, eviction must take the least recently
//! used entry rather than the first retained, and one graph's ceilings must
//! bound that graph alone. Every classification is counted exactly once, and an
//! eviction is reported only for an entry a ceiling actually dropped.

use pedant_graph::{GraphCache, GraphCacheLimits, GraphEdgeSelection};

use super::analysis_fixture::generous_limits;
use super::cache_counting::{
    Classification, DERIVED_PRODUCT_EVICTIONS, DERIVED_PRODUCT_HITS, DERIVED_PRODUCT_MISSES,
    SELECTED_INDEX_EVICTIONS, SELECTED_INDEX_HITS, SELECTED_INDEX_MISSES, assert_build_classifies,
    assert_delta,
};
use super::cache_fixture::{
    admitted, cached_from, cached_workspace, derived_only, pair, projection_only, restated,
};
use super::corpus::GRAPH_CORPUS;
use super::corpus_analysis::ANALYSIS_TRAVERSAL_CORPUS;
use super::corpus_revision::{REVISION_CORPUS, REVISION_FRAGMENTS};
use super::fixture::{self, CORPUS_LIBRARY, Resolved};
use super::promotion::Restatement;

/// Both derived categories obey their ceilings, and eviction is least recently
/// used.
///
/// Every row below varies only the ceilings of one cache, so the two
/// repositories the rows read are materialized, loaded, snapshotted, and
/// resolved once here and each row builds its own cache from the pair.
pub fn assert_cached_analysis_retention_is_bounded_lru() {
    let (_repository, resolved) = fixture::resolve_target(GRAPH_CORPUS, CORPUS_LIBRARY);
    let (_other_repository, elsewhere) =
        fixture::resolve_target(ANALYSIS_TRAVERSAL_CORPUS, CORPUS_LIBRARY);
    assert_selected_index_retention_is_bounded(&resolved);
    assert_product_retention_is_bounded(&resolved);
    assert_per_graph_ceilings_are_independent(&resolved, &elsewhere);
}

/// Index retention at ceilings zero, one, and two, with the access order
/// perturbed.
fn assert_selected_index_retention_is_bounded(resolved: &Resolved) {
    let stated = [
        GraphEdgeSelection::all(),
        GraphEdgeSelection::code_relations(),
        GraphEdgeSelection::new(&[], &[]),
    ];
    for (ceiling, repeats, evictions) in [(0_u32, 0_u64, 0_u64), (1, 1, 2), (2, 1, 1)] {
        let (_cache, held) = cached_from(resolved, derived_only(ceiling, 0));
        let before = held.stats();
        for selection in stated {
            held.analyze(selection, generous_limits())
                .expect("every selection is admitted");
        }
        assert_delta(
            before,
            held.stats(),
            &[
                (SELECTED_INDEX_MISSES, 3),
                (SELECTED_INDEX_EVICTIONS, evictions),
            ],
            &format!("three selections at an index ceiling of {ceiling}"),
        );
        let warm = held.stats();
        held.analyze(stated[2], generous_limits())
            .expect("the most recent selection is admitted");
        assert_delta(
            warm,
            held.stats(),
            &[
                (SELECTED_INDEX_HITS, repeats),
                (SELECTED_INDEX_MISSES, 1 - repeats),
            ],
            &format!("the most recently used selection at a ceiling of {ceiling}"),
        );
    }
    assert_index_eviction_is_least_recently_used(resolved, stated);
}

/// The entry an index store drops is the least recently used one, not the
/// first retained.
fn assert_index_eviction_is_least_recently_used(
    resolved: &Resolved,
    stated: [GraphEdgeSelection; 3],
) {
    let (_cache, held) = cached_from(resolved, derived_only(2, 0));
    for selection in [stated[0], stated[1]] {
        held.analyze(selection, generous_limits())
            .expect("admitted");
    }
    held.analyze(stated[0], generous_limits())
        .expect("the first selection is used again");
    held.analyze(stated[2], generous_limits())
        .expect("a third selection evicts one");
    let before = held.stats();
    held.analyze(stated[0], generous_limits())
        .expect("the promoted selection is admitted");
    assert_delta(
        before,
        held.stats(),
        &[(SELECTED_INDEX_HITS, 1)],
        "a promoted selection survives the eviction a first-in store would have taken",
    );
    let missed = held.stats();
    held.analyze(stated[1], generous_limits())
        .expect("the evicted selection is rebuilt");
    assert_delta(
        missed,
        held.stats(),
        &[(SELECTED_INDEX_MISSES, 1), (SELECTED_INDEX_EVICTIONS, 1)],
        "the least recently used selection is the one that was dropped",
    );
}

/// Product retention at ceilings zero, one, and two, with three products.
fn assert_product_retention_is_bounded(resolved: &Resolved) {
    for (ceiling, evictions) in [(0_u32, 0_u64), (1, 2), (2, 1)] {
        let (_cache, held) = cached_from(resolved, derived_only(4, ceiling));
        let analysis = held
            .analyze(GraphEdgeSelection::all(), generous_limits())
            .expect("admitted");
        let before = held.stats();
        analysis.degree_centrality();
        analysis.strongly_connected_components();
        analysis.condensation();
        assert_delta(
            before,
            held.stats(),
            &[
                (DERIVED_PRODUCT_MISSES, 3),
                (DERIVED_PRODUCT_EVICTIONS, evictions),
            ],
            &format!("three products at a product ceiling of {ceiling}"),
        );
        let warm = held.stats();
        analysis.condensation();
        let expected = u64::from(ceiling.min(1));
        assert_delta(
            warm,
            held.stats(),
            &[
                (DERIVED_PRODUCT_HITS, expected),
                (DERIVED_PRODUCT_MISSES, 1 - expected),
            ],
            &format!("the most recent product at a ceiling of {ceiling}"),
        );
    }
}

/// One graph's ceilings bound one graph.
///
/// Both graphs live in one cache at a product ceiling of one, which is what
/// makes the difference observable: a store that bounded products across graphs
/// would have to drop the first graph's metric to make room for the second
/// graph's, and the re-ask below would report an eviction and a miss instead of
/// the hit it requires.
fn assert_per_graph_ceilings_are_independent(first: &Resolved, second: &Resolved) {
    let selection = GraphEdgeSelection::all();
    let mut cache = GraphCache::new(GraphCacheLimits::new(0, 2, 1, 1));
    let one = admitted(&mut cache, pair(first), "the first graph");
    let other = admitted(&mut cache, pair(second), "the second graph");

    let analysis = one.analyze(selection, generous_limits()).expect("admitted");
    analysis.degree_centrality();

    let filled = one.stats();
    let elsewhere = other
        .analyze(selection, generous_limits())
        .expect("admitted");
    elsewhere.degree_centrality();
    assert_delta(
        filled,
        one.stats(),
        &[(SELECTED_INDEX_MISSES, 1), (DERIVED_PRODUCT_MISSES, 1)],
        "a second graph fills its own ceiling without displacing the first",
    );

    let retained = one.stats();
    analysis.degree_centrality();
    assert_delta(
        retained,
        one.stats(),
        &[(DERIVED_PRODUCT_HITS, 1)],
        "the first graph's only product survives the second graph filling its own ceiling",
    );
}

/// A key the store already holds replaces its entry instead of doubling it.
///
/// The one reachable repeated key: a source whose bytes never moved keeps its
/// key, and a report that changed what a site in it resolves to fails the local
/// claim, so the build misses and retains under the key it just examined. A
/// store that pushed a second entry would hold a projection nothing can ever
/// answer from, and — at a ceiling a host sized to its own source count — would
/// pay for it by dropping a live one and reporting an eviction no ceiling
/// explains.
///
/// The ceiling is the corpus's own fragment count, which is what makes the
/// difference observable: at that budget the store is exactly full, so a
/// doubled key must evict and a replaced key must not.
fn assert_a_repeated_key_replaces_rather_than_doubles() {
    let (_repository, base) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(projection_only(
        u32::try_from(REVISION_FRAGMENTS).expect("the corpus states few enough fragments"),
    ));
    assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, REVISION_FRAGMENTS),
        "a store filled to its ceiling",
    );

    let restated = restated(&base, Restatement::Tied);
    assert_build_classifies(
        &mut cache,
        (&base.snapshot, &restated),
        Classification::retained(REVISION_FRAGMENTS - 1, 1),
        "one source restated under the key it already holds",
    );
    assert_build_classifies(
        &mut cache,
        (&base.snapshot, &restated),
        Classification::retained(REVISION_FRAGMENTS, 0),
        "every source still answers after the replacement",
    );
}

/// Every retention counter reports the exact delta its category owes.
pub fn assert_derived_counter_deltas_are_exact() {
    assert_a_repeated_key_replaces_rather_than_doubles();
    let (_resolved, mut cache, held) = cached_workspace(GRAPH_CORPUS, derived_only(1, 1));
    let selection = GraphEdgeSelection::all();
    let before = held.stats();
    let analysis = held
        .analyze(selection, generous_limits())
        .expect("admitted");
    assert_delta(
        before,
        held.stats(),
        &[(SELECTED_INDEX_MISSES, 1)],
        "one selection is indexed once",
    );
    let indexed = held.stats();
    held.analyze(selection, generous_limits())
        .expect("the same selection is admitted again");
    assert_delta(
        indexed,
        held.stats(),
        &[(SELECTED_INDEX_HITS, 1)],
        "the same selection is reused",
    );
    let queried = held.stats();
    analysis.degree_centrality();
    analysis.degree_centrality();
    analysis.condensation();
    assert_delta(
        queried,
        held.stats(),
        &[
            (DERIVED_PRODUCT_MISSES, 2),
            (DERIVED_PRODUCT_HITS, 1),
            (DERIVED_PRODUCT_EVICTIONS, 1),
        ],
        "each product is classified once and each eviction counted once",
    );
    let cleared = held.stats();
    held.clear_analysis_cache();
    cache.clear();
    // Every counter, not just the product misses: an exact delta of nothing
    // over both clears is what proves no cumulative statistic was reset.
    assert_delta(cleared, held.stats(), &[], "clearing counts nothing");
}
