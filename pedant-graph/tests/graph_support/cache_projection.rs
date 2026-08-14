//! Source-unit reuse: which projections a graph miss may reuse, where that
//! decision is taken, and how many of them a cache may retain.
//!
//! Every row holds the exact-graph ceiling at zero, so each build misses the
//! exact graph and enters the projection seam. A retained graph would otherwise
//! answer a row and hide the classification it claims to prove. The counters
//! state which sources were reused; the structural half states that reuse is
//! what the production path did, because equal answers alone cannot tell reuse
//! apart from work repeated and thrown away.

use pedant_graph::{CachedCodeGraph, CodeGraph, GraphCache};
use pedant_types::{ResolutionGap, ResolutionReport};

use super::cache_counting::{Classification, assert_build_classifies, assert_delta, fragments_of};
use super::cache_fixture::{assert_matches_direct, pair, projection_only, restated};
use super::cache_remapping::declared_columns;
use super::cache_revision::{REVISIONS, Revision, revised};
use super::corpus_revision::{
    GAPPED_CORPUS, GAPPED_FRAGMENTS, PROJECTION_ALPHA_COMMENTED, PROJECTION_CORPUS,
    PROJECTION_MANIFEST, PROJECTION_MANIFEST_WITH_SPARE, REVISION_CORPUS, REVISION_FRAGMENTS,
    SPARE_MANIFEST, SPARE_SOURCE,
};
use super::fixture::{self, CORPUS_LIBRARY, Fixture};
use super::inventory::SOURCES;
use super::promotion::Restatement;
use super::scan::{code_only, compact, function_body, parsed, position_of, source, token_text};

/// The module that decides what a source's projection is.
const PLANNER: &str = "src/rust/projection.rs";

/// The module that states one source's complete local claim, both ways.
const CLAIM_OWNER: &str = "src/rust/source.rs";

/// The module that states the key a retained projection is selected by.
const KEY_OWNER: &str = "src/rust/claim.rs";

/// The module that owns retention, selection, and classification.
const REUSE_OWNER: &str = "src/rust/reuse.rs";

/// The derivation a reused source must never reach.
const DERIVATION: &str = "derived_projection";

/// The store lookup that decides whether a source is derived at all.
const LOOKUP: &str = "reused";

/// The one call that classifies an examined source, spelled without layout.
const CLASSIFICATION: &str = "record(CacheCategory::SourceProjection";

/// The spellings a key may never contain: each is part of a derived projection,
/// and a key that read one could not be stated before the derivation it selects.
const DERIVED_RECORDS: &[&str] = &[
    "SourceFragment",
    "DefinitionProjection",
    "ReferenceProjection",
    "CandidateProjection",
];

/// Every function the local-claim comparison is made of.
const CLAIM_COMPARISON: &[&str] = &[
    "states_current_claim",
    "states_definitions",
    "states_definition",
    "states_references",
    "states_reference",
    "states_join",
    "states_candidates",
];

/// Every retained record the comparison must read every column of.
const COMPARED_RECORDS: &[&str] = &[
    "SourceFragment",
    "DefinitionProjection",
    "ReferenceProjection",
    "CandidateProjection",
];

/// A fragment is reused only when its key and its complete local claim still
/// hold, and every unaffected fragment is reused.
pub fn assert_reuses_only_exact_source_unit_claims() {
    for revision in REVISIONS {
        assert_revision_reuses_its_unaffected_fragments(revision);
    }
    assert_a_restated_tier_reuses_nothing();
    assert_restated_gaps_reuse_every_other_source();
}

/// A source whose own bytes never moved misses when the answer to a site it
/// states changes gaps, and every other source of that report is reused.
///
/// The digest, the path, the unit key, and the tier are the base report's own,
/// so the gaps are the only part of the claim this row moves.
fn assert_restated_gaps_reuse_every_other_source() {
    let subject = "restated gaps";
    let (_repository, base) = fixture::resolve_target(GAPPED_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(projection_only(64));
    assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, GAPPED_FRAGMENTS),
        &format!("{subject}: the base build"),
    );

    let restated = restated(&base, Restatement::Gaps);
    assert_ne!(
        stated_gaps(restated.report()),
        stated_gaps(base.resolution.report()),
        "{subject}: the restated gaps must differ, or this row proves nothing"
    );
    let built = assert_build_classifies(
        &mut cache,
        (&base.snapshot, &restated),
        Classification::retained(GAPPED_FRAGMENTS - 1, 1),
        subject,
    );
    assert_matches_direct(built.graph(), (&base.snapshot, &restated), subject);
}

/// Every gap one report states, in record order.
fn stated_gaps(report: &ResolutionReport) -> Vec<Vec<ResolutionGap>> {
    report
        .resolutions()
        .iter()
        .map(|record| record.gaps().to_vec())
        .collect()
}

/// Reuse is decided before a projection is derived, and a reused source derives
/// nothing at all.
///
/// The counters state that a source was reused. This states that reuse is what
/// the production path did: the key is stated without reading a derived record,
/// derivation has one call site, that site is the arm the planner takes when the
/// store answered nothing, and the comparison that decides the arm reads every
/// column a retained projection holds.
pub fn assert_reuse_is_decided_before_derivation() {
    assert_the_key_reads_no_derived_record();
    assert_derivation_is_the_answer_to_a_miss();
    assert_every_retained_column_is_compared();
}

/// The key is stated from the snapshot and the plan, before the projection it
/// selects is decided.
fn assert_the_key_reads_no_derived_record() {
    let key = code_only(source(KEY_OWNER));
    for forbidden in DERIVED_RECORDS {
        assert!(
            !key.contains(forbidden),
            "{KEY_OWNER} must state its key without reading a {forbidden}"
        );
    }
    let body = function_body(PLANNER, "placed_fragment");
    let stated = position_of(&body, "SourceKey :: stated", "the placed source");
    let decided = position_of(&body, "stated_projection", "the placed source");
    assert!(
        stated < decided,
        "the key must be stated before the projection is decided"
    );
    assert!(
        !body.contains(DERIVATION),
        "placing a source must not derive its projection"
    );
}

/// Derivation is declared once, called once, and reached only when the store
/// answered nothing.
fn assert_derivation_is_the_answer_to_a_miss() {
    let sites: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| code_only(entry.text).contains(DERIVATION))
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        sites,
        vec![PLANNER, CLAIM_OWNER],
        "{DERIVATION} is declared by its owner and reached by the planner alone"
    );
    assert_eq!(
        code_only(source(CLAIM_OWNER)).matches(DERIVATION).count(),
        1,
        "{CLAIM_OWNER} declares {DERIVATION} exactly once"
    );
    assert_eq!(
        code_only(source(PLANNER)).matches(DERIVATION).count(),
        1,
        "{PLANNER} calls {DERIVATION} exactly once"
    );

    let (decided, arms) = sole_match(PLANNER, "stated_projection");
    assert!(
        decided.contains(LOOKUP),
        "the store must decide the projection, deciding on {decided}"
    );
    assert_eq!(arms.len(), 2, "the decision states an answer and a miss");
    for (pattern, body) in &arms {
        assert_eq!(
            pattern.starts_with("Some"),
            !body.contains(DERIVATION),
            "an answered source derives nothing and a missed source derives: {pattern} => {body}"
        );
    }

    let counted: Vec<&str> = SOURCES
        .iter()
        .filter(|entry| compact(entry.text).contains(CLASSIFICATION))
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        counted,
        vec![REUSE_OWNER],
        "one owner classifies every examined source"
    );
}

/// The comparison that decides reuse reads every column a retained projection
/// holds.
///
/// A column the comparison never reads is a change a later build could not see,
/// so the retained projection would answer for a claim it no longer states.
fn assert_every_retained_column_is_compared() {
    let compared = compared_text();
    for record in COMPARED_RECORDS {
        for column in declared_columns(record) {
            assert!(
                compared.contains(&column),
                "the claim comparison must read {record}::{column}"
            );
        }
    }
}

/// The exact text of every function the comparison is made of.
fn compared_text() -> String {
    CLAIM_COMPARISON
        .iter()
        .map(|name| function_body(CLAIM_OWNER, name))
        .collect::<Vec<String>>()
        .join(" ")
}

/// The scrutinee and the arms of the one `match` a free function states.
fn sole_match(path: &str, name: &str) -> (String, Vec<(String, String)>) {
    let file = parsed(path);
    let found = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} declares no fn {name}"));
    let decided = found
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            syn::Stmt::Expr(syn::Expr::Match(decided), _) => Some(decided),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} states no match in {name}"));
    let arms = decided
        .arms
        .iter()
        .map(|arm| (token_text(&arm.pat), token_text(&arm.body)))
        .collect();
    (token_text(&decided.expr), arms)
}

/// One revision's base build derives every fragment, and its revised build
/// reuses exactly the fragments the revision left alone.
fn assert_revision_reuses_its_unaffected_fragments(revision: Revision) {
    let subject = revision.label();
    let (_repository, base, after) = revised(revision);
    let mut cache = GraphCache::new(projection_only(64));
    let warmed = assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, REVISION_FRAGMENTS),
        &format!("{subject}: the base build"),
    );
    assert_eq!(
        fragments_of(warmed.graph()),
        REVISION_FRAGMENTS,
        "{subject}: the base corpus states its own fragments"
    );

    assert_build_classifies(
        &mut cache,
        pair(&after),
        Classification::retained(revision.hits(), revision.misses()),
        subject,
    );
}

/// A report restated at another tier reuses no fragment of the report it was
/// copied from.
///
/// The sources, the paths, the digests, and every local claim are the base
/// report's own, so the tier is the only part of the key that moved.
fn assert_a_restated_tier_reuses_nothing() {
    let subject = "a restated tier";
    let (_repository, base) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(projection_only(64));
    assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, REVISION_FRAGMENTS),
        &format!("{subject}: the base build"),
    );

    let promoted = restated(&base, Restatement::Tier);
    assert_ne!(
        promoted.report().tier(),
        base.resolution.report().tier(),
        "{subject}: the restated tier must differ, or this row proves nothing"
    );
    let built = assert_build_classifies(
        &mut cache,
        (&base.snapshot, &promoted),
        Classification::retained(0, REVISION_FRAGMENTS),
        subject,
    );
    assert_matches_direct(built.graph(), (&base.snapshot, &promoted), subject);
}

/// Projection retention obeys its ceiling, evicts least recently used, and
/// leaves every graph a caller holds valid.
pub fn assert_source_projection_retention_is_bounded_lru() {
    assert_zero_retains_nothing();
    assert_one_retains_the_last();
    assert_two_evict_least_recently_used();
}

/// A zero ceiling derives every fragment of every build and retains none.
fn assert_zero_retains_nothing() {
    let mut cache = GraphCache::new(projection_only(0));
    let (_repository, resolved) = fixture::resolve_target(PROJECTION_CORPUS, CORPUS_LIBRARY);
    assert_build_classifies(
        &mut cache,
        pair(&resolved),
        Classification::retained(0, 2),
        "a zero projection ceiling",
    );
    let repeated = assert_build_classifies(
        &mut cache,
        pair(&resolved),
        Classification::retained(0, 2),
        "a zero projection ceiling, repeated",
    );
    assert_matches_direct(
        repeated.graph(),
        pair(&resolved),
        "a zero projection ceiling",
    );
}

/// A ceiling of one keeps the fragment examined last, so a two-fragment build
/// never reaches the entry it retained.
fn assert_one_retains_the_last() {
    let mut cache = GraphCache::new(projection_only(1));
    let (_repository, resolved) = fixture::resolve_target(PROJECTION_CORPUS, CORPUS_LIBRARY);
    assert_build_classifies(
        &mut cache,
        pair(&resolved),
        Classification::bounded(0, 2, 1),
        "a projection ceiling of one",
    );
    let repeated = assert_build_classifies(
        &mut cache,
        pair(&resolved),
        Classification::bounded(0, 2, 2),
        "a projection ceiling of one, repeated",
    );
    assert_matches_direct(
        repeated.graph(),
        pair(&resolved),
        "a projection ceiling of one",
    );
}

/// A ceiling of two drops the least recently used fragment rather than the one
/// retained longest, and every graph a caller holds survives it.
///
/// The perturbation is required: while the fragments a build examines are the
/// fragments it inserted, in the order it inserted them, recency and age agree
/// and no observation could tell the two policies apart. Rewriting one source
/// re-inserts it after the fragment that was reused beside it, so the store's
/// insertion order and its recency order disagree from there on.
fn assert_two_evict_least_recently_used() {
    let mut cache = GraphCache::new(projection_only(2));
    let mut repository = Fixture::build(PROJECTION_CORPUS);
    let base = repository.resolve_declared(CORPUS_LIBRARY);
    let held = assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, 2),
        "the first build under a ceiling of two",
    );
    assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(2, 0),
        "the repeated build under a ceiling of two",
    );

    repository.rewrite("repo/src/alpha.rs", PROJECTION_ALPHA_COMMENTED);
    let commented = repository.resolve_declared(CORPUS_LIBRARY);
    assert_build_classifies(
        &mut cache,
        pair(&commented),
        Classification::bounded(1, 1, 1),
        "one rewritten source under a ceiling of two",
    );

    repository.revise(
        &[
            ("repo/Cargo.toml", PROJECTION_MANIFEST_WITH_SPARE),
            ("repo/crates/spare/Cargo.toml", SPARE_MANIFEST),
            ("repo/crates/spare/src/lib.rs", SPARE_SOURCE),
        ],
        &[],
    );
    let widened = repository.resolve_declared(CORPUS_LIBRARY);
    assert_build_classifies(
        &mut cache,
        pair(&widened),
        Classification::bounded(2, 1, 1),
        "one further fragment under a ceiling of two",
    );

    repository.revise(
        &[("repo/Cargo.toml", PROJECTION_MANIFEST)],
        &[
            "repo/crates/spare/Cargo.toml",
            "repo/crates/spare/src/lib.rs",
        ],
    );
    let narrowed = repository.resolve_declared(CORPUS_LIBRARY);
    let rebuilt = assert_build_classifies(
        &mut cache,
        pair(&narrowed),
        Classification::bounded(0, 2, 2),
        "the least recently used fragment was the one dropped",
    );
    assert_matches_direct(
        rebuilt.graph(),
        pair(&narrowed),
        "a rebuild after least-recently-used eviction",
    );
    assert_eq!(
        held.graph().nodes().len(),
        rebuilt.graph().nodes().len(),
        "eviction leaves the caller's first graph readable beside the last"
    );
    assert_matches_direct(
        held.graph(),
        pair(&base),
        "a graph held across every eviction",
    );

    assert_clearing_keeps_the_held_graph(&mut cache, &base, &held);
}

/// Clearing drops the cache's own fragments, keeps every counter, and leaves
/// the caller's graph valid.
fn assert_clearing_keeps_the_held_graph(
    cache: &mut GraphCache,
    base: &fixture::Resolved,
    held: &CachedCodeGraph,
) {
    let retained: &CodeGraph = held.graph();
    let before = cache.stats();
    cache.clear();
    assert_delta(before, cache.stats(), &[], "clearing the cache");
    assert!(
        std::ptr::eq(retained, held.graph()),
        "clearing does not move a caller's graph"
    );

    assert_build_classifies(
        cache,
        pair(base),
        Classification::retained(0, 2),
        "a cleared store derives every fragment again",
    );
    assert_matches_direct(
        held.graph(),
        pair(base),
        "a graph held across a top-level clear",
    );
}
