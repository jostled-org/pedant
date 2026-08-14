//! Exact graph reuse: validation, identity, pointer sharing, current ceilings,
//! bounded retention, and equality with the direct builders.
//!
//! Every case drives the published cache API over real temporary Cargo
//! repositories. The reports a case pairs with one snapshot are restated
//! through the public resolution builder, so each claim dimension is a report a
//! caller could legitimately hold.

use pedant_graph::{
    GraphBuildError, GraphCache, GraphCollection, GraphLimits, build_rust_graph_with_limits,
};

use super::analysis_perturbation::created_in_reverse;
use super::cache_counting::{
    EXACT_GRAPH_EVICTIONS, EXACT_GRAPH_HITS, assert_delta, assert_miss_delta,
};
use super::cache_fixture::{
    self, admitted, assert_clear_keeps_the_held_graph, assert_direct_builders_agree,
    assert_matches_direct, assert_refused_without_observation, bounded, build, exact_only,
    generous, json, pair, restated, two_root_targets,
};
use super::corpus::{EDITED_MINIMAL_SOURCE, MINIMAL_CORPUS, OTHER_ROOT_CORPUS};
use super::defensive::assert_cached_bindings_take_their_own_entry;
use super::fixture::{self, Fixture};
use super::promotion::Restatement;

/// One lowered ceiling and the refusal a hit under it must return.
struct CeilingCase {
    label: &'static str,
    limits: GraphLimits,
    collection: GraphCollection,
    limit: u32,
}

/// How many members of one collection the warming graph states.
///
/// Every ceiling row below is that count less one, so an empty collection would
/// wrap into `u32::MAX` and report the failure at a row that reads the ceiling
/// rather than at the corpus that stopped stating the collection.
fn stated_count(collection: &str, counted: usize) -> u32 {
    assert!(
        counted > 0,
        "the warming graph states at least one {collection}"
    );
    u32::try_from(counted)
        .unwrap_or_else(|error| panic!("the warming graph states too many {collection}s: {error}"))
}

/// One lowered ceiling per collection, plus the pairing that lowers all three.
///
/// The counts are the graph's own, so each row states the exact ceiling one
/// admitted collection no longer fits under.
fn ceiling_cases(counts: (u32, u32, u32)) -> [CeilingCase; 4] {
    let (nodes, references, edges) = counts;
    [
        CeilingCase {
            label: "a lowered node ceiling",
            limits: GraphLimits::new(nodes - 1, u32::MAX, u32::MAX),
            collection: GraphCollection::Node,
            limit: nodes - 1,
        },
        CeilingCase {
            label: "a lowered reference ceiling",
            limits: GraphLimits::new(u32::MAX, references - 1, u32::MAX),
            collection: GraphCollection::Reference,
            limit: references - 1,
        },
        CeilingCase {
            label: "a lowered edge ceiling",
            limits: GraphLimits::new(u32::MAX, u32::MAX, edges - 1),
            collection: GraphCollection::Edge,
            limit: edges - 1,
        },
        CeilingCase {
            label: "three lowered ceilings",
            limits: GraphLimits::new(0, 0, 0),
            collection: GraphCollection::Node,
            limit: 0,
        },
    ]
}

/// Both identity refusals return before any counter moves.
pub fn assert_invalid_pairs_are_refused_before_observation() {
    let mut cache = GraphCache::new(generous());
    let (_minimal, first) = fixture::resolve_library(MINIMAL_CORPUS);
    let (_other, other) = fixture::resolve_library(OTHER_ROOT_CORPUS);
    let warm = cache.stats();
    let retained = admitted(&mut cache, pair(&first), "the warming build");
    assert_miss_delta(
        warm,
        cache.stats(),
        &[],
        retained.graph(),
        "the warming build",
    );

    assert_refused_without_observation(
        &mut cache,
        (&other.snapshot, &first.resolution),
        GraphBuildError::RootTargetMismatch,
        "another root target",
    );

    let mut edited = Fixture::build(MINIMAL_CORPUS);
    let before = edited.resolve_library();
    edited.rewrite("repo/src/lib.rs", EDITED_MINIMAL_SOURCE);
    let after = edited.resolve_library();
    assert_refused_without_observation(
        &mut cache,
        (&after.snapshot, &before.resolution),
        GraphBuildError::SnapshotFingerprintMismatch,
        "a stale resolution",
    );
}

/// Every distinct valid claim over one snapshot takes its own entry, and an
/// equal claim shares one.
pub fn assert_exact_identity_guards_the_claim() {
    let mut cache = GraphCache::new(exact_only(64));
    let (_corpus, base) = fixture::resolve_corpus_library();
    let warmed = admitted(&mut cache, pair(&base), "the base claim");
    assert_matches_direct(warmed.graph(), pair(&base), "the base claim");

    for restatement in [
        Restatement::Tier,
        Restatement::Promoted,
        Restatement::Certainty,
        Restatement::Candidates,
        Restatement::Gaps,
        Restatement::Definitions,
        Restatement::References,
    ] {
        assert_distinct_claim_misses(&mut cache, &base, restatement);
    }

    let restated_exactly = restated(&base, Restatement::Exact);
    assert_eq!(
        restated_exactly.report(),
        base.resolution.report(),
        "an exactly restated report equals the report it copied"
    );
    let before = cache.stats();
    let repeated = admitted(
        &mut cache,
        (&base.snapshot, &restated_exactly),
        "the exactly restated claim",
    );
    assert_delta(
        before,
        cache.stats(),
        &[(EXACT_GRAPH_HITS, 1)],
        "the exactly restated claim",
    );
    assert!(
        std::ptr::eq(warmed.graph(), repeated.graph()),
        "an equal claim shares the retained graph, whatever report value carried it"
    );

    assert_cached_bindings_take_their_own_entry();
    assert_root_target_is_part_of_identity();
}

/// One restated claim misses and returns the graph the direct builder would.
fn assert_distinct_claim_misses(
    cache: &mut GraphCache,
    base: &fixture::Resolved,
    restatement: Restatement,
) {
    let subject = restatement.label();
    let resolution = restated(base, restatement);
    assert_ne!(
        resolution.report(),
        base.resolution.report(),
        "{subject}: the restated report must differ, or this row proves nothing"
    );
    let stated = (&base.snapshot, &resolution);
    let before = cache.stats();
    let built = admitted(cache, stated, subject);
    assert_miss_delta(before, cache.stats(), &[], built.graph(), subject);
    assert_matches_direct(built.graph(), stated, subject);
}

/// Two valid pairings over one repository that differ in root target.
///
/// Validation proves the claim's fingerprint and root target are the ones the
/// resolution already carries, so neither varies against a fixed resolution: the
/// claim holds them as its cheap comparison prefix and as redundant defence,
/// while the bindings and the report are the dimensions a public input varies on
/// its own. What is observable here, and what this row requires, is that two
/// roots of one repository take separate entries and that crossing them is
/// refused before any counter moves — the same place a fingerprint disagreement
/// is stopped, one step before a claim is ever built.
fn assert_root_target_is_part_of_identity() {
    let mut cache = GraphCache::new(exact_only(64));
    let (_corpus, library, example) = two_root_targets();
    assert_ne!(
        library.snapshot.root_target(),
        example.snapshot.root_target(),
        "the two pairings name different root targets"
    );
    assert_ne!(
        library.resolution.snapshot_fingerprint(),
        example.resolution.snapshot_fingerprint(),
        "one repository under two roots states two snapshot identities"
    );
    for (subject, resolved) in [
        ("the library root", &library),
        ("the example root", &example),
    ] {
        let before = cache.stats();
        let built = admitted(&mut cache, pair(resolved), subject);
        assert_miss_delta(before, cache.stats(), &[], built.graph(), subject);
        assert_matches_direct(built.graph(), pair(resolved), subject);
    }

    assert_refused_without_observation(
        &mut cache,
        (&library.snapshot, &example.resolution),
        GraphBuildError::RootTargetMismatch,
        "a second root of the same repository",
    );
}

/// A repeated exact input returns the retained allocation and nothing else
/// moves.
pub fn assert_exact_hits_share_graph_and_short_circuit() {
    let mut cache = GraphCache::new(generous());
    let (_corpus, resolved) = fixture::resolve_corpus_library();
    let first = admitted(&mut cache, pair(&resolved), "the first build");

    let before = cache.stats();
    let second = admitted(&mut cache, pair(&resolved), "the repeated build");
    assert_delta(
        before,
        cache.stats(),
        &[(EXACT_GRAPH_HITS, 1)],
        "the repeated build",
    );
    assert!(
        std::ptr::eq(first.graph(), second.graph()),
        "a repeated exact input returns the retained allocation"
    );
    assert_eq!(
        cache.stats().exact_graph_misses(),
        1,
        "one input was built once"
    );
    assert_matches_direct(second.graph(), pair(&resolved), "the repeated build");
}

/// A hit under lower ceilings refuses exactly as direct construction does.
pub fn assert_hits_reapply_graph_limits() {
    let mut cache = GraphCache::new(generous());
    let (_corpus, resolved) = fixture::resolve_corpus_library();
    let warm = admitted(&mut cache, pair(&resolved), "the warming build");
    let counts = (
        stated_count("node", warm.graph().nodes().len()),
        stated_count("reference", warm.graph().references().len()),
        stated_count("edge", warm.graph().edges().len()),
    );

    for case in ceiling_cases(counts) {
        let before = cache.stats();
        let refused = build(&mut cache, pair(&resolved), case.limits)
            .err()
            .unwrap_or_else(|| panic!("{}: the lowered ceiling was admitted", case.label));
        let directly =
            build_rust_graph_with_limits(&resolved.snapshot, &resolved.resolution, case.limits)
                .err()
                .unwrap_or_else(|| panic!("{}: the direct build admitted it", case.label));
        match refused {
            GraphBuildError::CapacityExceeded { collection, limit } => assert_eq!(
                (collection, limit),
                (case.collection, case.limit),
                "{}: the refusal names its own collection and ceiling",
                case.label
            ),
            other => panic!("{}: unexpected refusal {other:?}", case.label),
        }
        assert_eq!(
            format!("{refused:?}"),
            format!("{directly:?}"),
            "{}: the cached and direct refusals agree",
            case.label
        );
        assert_delta(before, cache.stats(), &[(EXACT_GRAPH_HITS, 1)], case.label);
    }

    let admitted_again = admitted(&mut cache, pair(&resolved), "the readmitted build");
    assert!(
        std::ptr::eq(warm.graph(), admitted_again.graph()),
        "a refused ceiling leaves the retained graph in place"
    );
}

/// Exact retention obeys its ceiling, evicts least-recently-used, and leaves
/// every handle a caller holds valid.
pub fn assert_exact_retention_is_bounded_lru() {
    assert_zero_retains_nothing();
    assert_one_retains_the_last();
    assert_two_evict_least_recently_used();
}

/// A zero ceiling computes every answer and retains none of them.
fn assert_zero_retains_nothing() {
    let mut cache = GraphCache::new(exact_only(0));
    let (_corpus, resolved) = fixture::resolve_corpus_library();
    let first = admitted(&mut cache, pair(&resolved), "zero");
    let before = cache.stats();
    let second = admitted(&mut cache, pair(&resolved), "zero repeated");
    assert_miss_delta(
        before,
        cache.stats(),
        &[],
        second.graph(),
        "a zero ceiling retains nothing",
    );
    assert!(
        !std::ptr::eq(first.graph(), second.graph()),
        "a zero ceiling returns a freshly built graph"
    );
    assert_eq!(
        first.graph(),
        second.graph(),
        "a zero ceiling still answers with the same graph value"
    );
}

/// A ceiling of one keeps the most recent claim and evicts the other.
fn assert_one_retains_the_last() {
    let mut cache = GraphCache::new(exact_only(1));
    let (_corpus, base) = fixture::resolve_corpus_library();
    let other = restated(&base, Restatement::Tier);
    let held = admitted(&mut cache, pair(&base), "first");
    let before = cache.stats();
    let second = admitted(&mut cache, (&base.snapshot, &other), "second");
    assert_miss_delta(
        before,
        cache.stats(),
        &[(EXACT_GRAPH_EVICTIONS, 1)],
        second.graph(),
        "a second claim under a ceiling of one",
    );

    let evicted = cache.stats();
    let rebuilt = admitted(&mut cache, pair(&base), "rebuilt");
    assert_miss_delta(
        evicted,
        cache.stats(),
        &[(EXACT_GRAPH_EVICTIONS, 1)],
        rebuilt.graph(),
        "the evicted claim is rebuilt without a cache failure",
    );
    assert_eq!(
        held.graph(),
        rebuilt.graph(),
        "eviction leaves the caller's handle valid and equal"
    );
    assert_eq!(
        json(held.graph()),
        json(rebuilt.graph()),
        "an evicted handle still serializes to its own version-1 bytes"
    );
}

/// A ceiling of two evicts the least recently used entry, not the oldest.
fn assert_two_evict_least_recently_used() {
    let mut cache = GraphCache::new(exact_only(2));
    let (_corpus, base) = fixture::resolve_corpus_library();
    let second = restated(&base, Restatement::Tier);
    let third = restated(&base, Restatement::Gaps);
    let first_handle = admitted(&mut cache, pair(&base), "first");
    admitted(&mut cache, (&base.snapshot, &second), "second");

    let touched = cache.stats();
    let repeated = admitted(&mut cache, pair(&base), "touch");
    assert_delta(
        touched,
        cache.stats(),
        &[(EXACT_GRAPH_HITS, 1)],
        "touching the first claim",
    );
    assert!(
        std::ptr::eq(first_handle.graph(), repeated.graph()),
        "touching returns the retained allocation"
    );

    let filled = cache.stats();
    let third_graph = admitted(&mut cache, (&base.snapshot, &third), "third");
    assert_miss_delta(
        filled,
        cache.stats(),
        &[(EXACT_GRAPH_EVICTIONS, 1)],
        third_graph.graph(),
        "a third claim under a ceiling of two",
    );

    let evicted = cache.stats();
    let touched_again = admitted(&mut cache, pair(&base), "first again");
    assert_delta(
        evicted,
        cache.stats(),
        &[(EXACT_GRAPH_HITS, 1)],
        "the recently used claim survived",
    );
    assert!(
        std::ptr::eq(first_handle.graph(), touched_again.graph()),
        "least-recently-used eviction kept the touched entry, not the oldest one"
    );

    let dropped = cache.stats();
    let rebuilt = admitted(&mut cache, (&base.snapshot, &second), "second again");
    assert_miss_delta(
        dropped,
        cache.stats(),
        &[(EXACT_GRAPH_EVICTIONS, 1)],
        rebuilt.graph(),
        "the least recently used claim was the one dropped",
    );

    assert_clear_keeps_the_held_graph(
        &mut cache,
        &base,
        &first_handle,
        "a handle held across a clear",
    );
    assert_eq!(
        first_handle.stats().exact_graph_misses(),
        cache.stats().exact_graph_misses(),
        "a handle reports the cache's own cumulative activity"
    );
}

/// Cached misses agree with both direct builders over tiers and creation order.
pub fn assert_exact_build_matches_direct() {
    let mut cache = GraphCache::new(generous());
    let (_corpus, syntactic) = fixture::resolve_corpus_library();
    let semantic = restated(&syntactic, Restatement::Promoted);

    // The published direct surface has two entry points, and the shorter one
    // forwards the default ceilings to the other. Every cached comparison below
    // reads one of them; that the two agree is this row.
    assert_direct_builders_agree(pair(&syntactic), "the published direct builders");

    for (subject, resolution) in [
        ("the syntactic report", &syntactic.resolution),
        ("the semantic report", &semantic),
    ] {
        let stated = (&syntactic.snapshot, resolution);
        let built = admitted(&mut cache, stated, subject);
        assert_matches_direct(built.graph(), stated, subject);
        assert_eq!(
            built.graph().tier(),
            resolution.report().tier(),
            "{subject}: the graph carries the report's own tier"
        );
    }

    let (_reversed, reordered) = fixture::resolve_library(&created_in_reverse(MINIMAL_CORPUS));
    let subject = "a corpus created in the opposite order";
    let built = admitted(&mut cache, pair(&reordered), subject);
    assert_matches_direct(built.graph(), pair(&reordered), subject);

    let ceilings = GraphLimits::new(u32::MAX, u32::MAX, u32::MAX);
    let stated = pair(&syntactic);
    let explicit = bounded(&mut cache, stated, ceilings, "the explicitly bounded build");
    assert_eq!(
        explicit.graph(),
        &cache_fixture::direct(stated, ceilings, "the explicitly bounded build"),
        "an explicitly bounded cached build equals the bounded direct builder"
    );
}
