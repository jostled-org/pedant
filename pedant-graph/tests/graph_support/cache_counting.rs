//! The published counter vocabulary, and the exact deltas a cache case reads
//! through it.
//!
//! One responsibility: what a cache did, read from the statistics it publishes.
//! [`super::cache_fixture`] owns the workspaces and the builders; every claim
//! about how those builds were classified is stated here, so a case names one
//! counter and this module proves the other eleven stood still.

use pedant_graph::{CachedCodeGraph, CodeGraph, GraphCache, GraphCacheStats, GraphNodeKind};

use super::cache_fixture::{Pair, admitted};

/// Where the source-unit projections a build reused are counted.
pub const SOURCE_PROJECTION_HITS: usize = 0;
/// Where the source-unit projections a build had to derive are counted.
pub const SOURCE_PROJECTION_MISSES: usize = 1;
/// Where the source-unit projections bounded retention dropped are counted.
pub const SOURCE_PROJECTION_EVICTIONS: usize = 2;

/// Where the exact graphs a lookup answered from retained state are counted.
pub const EXACT_GRAPH_HITS: usize = 3;
/// Where the exact graphs a lookup had to build are counted.
pub const EXACT_GRAPH_MISSES: usize = 4;
/// Where the exact graphs bounded retention dropped are counted.
pub const EXACT_GRAPH_EVICTIONS: usize = 5;

/// Where the edge-selection index sets a lookup reused are counted.
pub const SELECTED_INDEX_HITS: usize = 6;
/// Where the edge-selection index sets a lookup had to build are counted.
pub const SELECTED_INDEX_MISSES: usize = 7;
/// Where the edge-selection index sets bounded retention dropped are counted.
pub const SELECTED_INDEX_EVICTIONS: usize = 8;

/// Where the derived products a query reused are counted.
pub const DERIVED_PRODUCT_HITS: usize = 9;
/// Where the derived products a query had to compute are counted.
pub const DERIVED_PRODUCT_MISSES: usize = 10;
/// Where the derived products bounded retention dropped are counted.
pub const DERIVED_PRODUCT_EVICTIONS: usize = 11;

/// How many counters one statistics snapshot publishes.
pub const COUNTERS: usize = 12;

/// The name each counter is reported by, in reading order.
pub const COUNTER_NAMES: [&str; COUNTERS] = [
    "source_projection_hits",
    "source_projection_misses",
    "source_projection_evictions",
    "exact_graph_hits",
    "exact_graph_misses",
    "exact_graph_evictions",
    "selected_index_hits",
    "selected_index_misses",
    "selected_index_evictions",
    "derived_product_hits",
    "derived_product_misses",
    "derived_product_evictions",
];

/// How many source-unit fragments one graph states.
///
/// One file node is minted per unit-and-source pair, which is exactly the set a
/// build examines, so the public graph states how many classifications a build
/// owes.
pub fn fragments_of(graph: &CodeGraph) -> u64 {
    let counted = graph
        .nodes()
        .iter()
        .filter(|node| *node.kind() == GraphNodeKind::File)
        .count();
    u64::try_from(counted).expect("a graph states fewer file nodes than u64 can count")
}

/// Every published counter, in the order [`COUNTER_NAMES`] states them.
pub fn counters(stats: GraphCacheStats) -> [u64; COUNTERS] {
    [
        stats.source_projection_hits(),
        stats.source_projection_misses(),
        stats.source_projection_evictions(),
        stats.exact_graph_hits(),
        stats.exact_graph_misses(),
        stats.exact_graph_evictions(),
        stats.selected_index_hits(),
        stats.selected_index_misses(),
        stats.selected_index_evictions(),
        stats.derived_product_hits(),
        stats.derived_product_misses(),
        stats.derived_product_evictions(),
    ]
}

/// The exact delta between two readings, stated counter by counter.
///
/// Every counter the caller does not name must be unchanged, so a case that
/// claims one classification also proves the other eleven stood still. A
/// counter named twice is refused rather than resolved to the last amount: the
/// two statements are a disagreement about what the row claims, and silently
/// keeping one of them would change the meaning of the assertion.
pub fn assert_delta(
    before: GraphCacheStats,
    after: GraphCacheStats,
    stated: &[(usize, u64)],
    subject: &str,
) {
    let mut named = [None; COUNTERS];
    for (counter, amount) in stated {
        assert!(
            named[*counter].replace(*amount).is_none(),
            "{subject}: {} is stated twice",
            COUNTER_NAMES[*counter]
        );
    }
    let expected = named.map(|amount| amount.unwrap_or(0));
    let (before, after) = (counters(before), counters(after));
    let observed: [u64; COUNTERS] = std::array::from_fn(|at| after[at].saturating_sub(before[at]));
    assert_eq!(
        observed, expected,
        "{subject}: counters must read {expected:?}, over {COUNTER_NAMES:?}"
    );
    assert!(
        (0..COUNTERS).all(|at| after[at] >= before[at]),
        "{subject}: no counter may fall"
    );
}

/// The delta one cached miss owes, beside whatever else a case states.
///
/// A graph miss classifies every fragment of the graph it returns, so a case
/// whose store retained no fragment of that claim derives all of them. The
/// exact-graph miss is stated here too, because every row that reaches the
/// projection seam is a row that missed the graph.
pub fn assert_miss_delta(
    before: GraphCacheStats,
    after: GraphCacheStats,
    stated: &[(usize, u64)],
    built: &CodeGraph,
    subject: &str,
) {
    let mut expected = stated.to_vec();
    expected.push((EXACT_GRAPH_MISSES, 1));
    expected.push((SOURCE_PROJECTION_MISSES, fragments_of(built)));
    assert_delta(before, after, &expected, subject);
}

/// What one build owes its projection counters.
#[derive(Clone, Copy)]
pub struct Classification {
    /// Current fragments the build reused.
    hits: u64,
    /// Current fragments the build derived again.
    misses: u64,
    /// Retained fragments the ceiling dropped.
    evictions: u64,
}

impl Classification {
    /// One build that reuses `hits` fragments, derives `misses`, and evicts
    /// nothing.
    pub fn retained(hits: u64, misses: u64) -> Self {
        Self {
            hits,
            misses,
            evictions: 0,
        }
    }

    /// One build that also drops `evictions` retained fragments.
    pub fn bounded(hits: u64, misses: u64, evictions: u64) -> Self {
        Self {
            hits,
            misses,
            evictions,
        }
    }

    /// How many fragments this build examined.
    fn examined(self) -> u64 {
        self.hits.saturating_add(self.misses)
    }
}

/// One cached build, and the exact classification it owed.
///
/// The exact-graph miss is required first: every projection row states a zero
/// exact-graph ceiling, so a row that recorded an exact hit would be proving
/// nothing about the seam it names. Every fragment the build examined is
/// classified once, which is what the file nodes of the returned graph count.
pub fn assert_build_classifies(
    cache: &mut GraphCache,
    stated: Pair<'_>,
    expected: Classification,
    subject: &str,
) -> CachedCodeGraph {
    let before = cache.stats();
    let built = admitted(cache, stated, subject);
    assert_delta(
        before,
        cache.stats(),
        &[
            (EXACT_GRAPH_MISSES, 1),
            (SOURCE_PROJECTION_HITS, expected.hits),
            (SOURCE_PROJECTION_MISSES, expected.misses),
            (SOURCE_PROJECTION_EVICTIONS, expected.evictions),
        ],
        subject,
    );
    assert_eq!(
        expected.examined(),
        fragments_of(built.graph()),
        "{subject}: every current fragment is classified exactly once"
    );
    built
}

/// One cached build that classified every current fragment exactly once.
///
/// The split between reuse and derivation is left to the row that fixes what
/// the store already held; what is required here is that the build missed the
/// exact graph, examined the seam, and classified each fragment once. At least
/// one fragment must be classified: a graph stating none would satisfy the
/// equality below by counting nothing on either side.
pub fn assert_build_examines_every_fragment(
    cache: &mut GraphCache,
    stated: Pair<'_>,
    subject: &str,
) -> CachedCodeGraph {
    let before = counters(cache.stats());
    let built = admitted(cache, stated, subject);
    let after = counters(cache.stats());
    let examined = after[SOURCE_PROJECTION_HITS].saturating_sub(before[SOURCE_PROJECTION_HITS])
        + after[SOURCE_PROJECTION_MISSES].saturating_sub(before[SOURCE_PROJECTION_MISSES]);
    assert_eq!(
        after[EXACT_GRAPH_MISSES].saturating_sub(before[EXACT_GRAPH_MISSES]),
        1,
        "{subject}: a zero exact-graph ceiling builds every graph"
    );
    let fragments = fragments_of(built.graph());
    assert!(
        fragments > 0,
        "{subject}: the graph states at least one fragment to classify"
    );
    assert_eq!(
        examined, fragments,
        "{subject}: every current fragment is classified exactly once"
    );
    built
}
