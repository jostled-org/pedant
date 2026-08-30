//! What the bounded Rust graph store changes, and what it must not.
//!
//! It changes cost. Indexing the same repository twice through one indexer
//! reuses every exact Rust graph, and indexing it after a source changed does
//! not. What it must never change is an answer: the two revisions state the
//! same identity, the same project keys, and the same graph bytes, and no
//! counter reaches a claim.

use pedant_snippet::{
    AnalysisAnswer, AnalysisMode, CodeIntelligenceIndexer, CodeIntelligenceLimits,
    CodeIntelligenceState, EdgeKind, GraphCacheLimits, NavigationEntity, PathQuery, ProjectSlice,
    RelationDirection, RelationQuery,
};

use super::fixture::{
    BINARIES, LIBRARY_SOURCE, LIBRARY_UNIT, RUST_LIBRARY, handle, project, repository, whole_page,
};
use super::oracles::analyzed;
use super::selection::{everything, kinds};
use crate::index::fixture::Repository;

/// A reused graph costs less and answers the same.
#[test]
fn rust_graph_cache_reuse_changes_cost_not_answer() {
    an_unchanged_repository_reuses_every_rust_graph();
    a_changed_source_misses_and_still_answers_the_same_shape();
    a_changed_host_limit_states_a_different_identity();
    eviction_changes_no_identity_and_no_answer();
    every_per_graph_ceiling_bounds_what_a_query_retains();
}

/// Every Rust graph of an unchanged repository is reused on the second pass,
/// and both passes state the same index revision.
///
/// The first pass also states which graphs the store ever saw. Go graphs are
/// built directly and never offered to it, so the miss count is the Rust project
/// count exactly — a claim the first pass already holds every number for, and
/// which a row of its own would have paid a third tree and a third index build
/// to restate.
fn an_unchanged_repository_reuses_every_rust_graph() {
    let repository = repository();
    let mut indexer = CodeIntelligenceIndexer::new(CodeIntelligenceLimits::default());
    let first = index(&mut indexer, &repository);
    let after_first = indexer.graph_cache_stats();
    assert_eq!(after_first.exact_graph_hits(), 0, "nothing to reuse yet");
    assert!(
        after_first.exact_graph_misses() > 0,
        "and every Rust graph had to be built: {}",
        after_first.exact_graph_misses()
    );
    assert_eq!(
        after_first.exact_graph_misses(),
        rust_graphs(&first),
        "the store saw the Rust graphs and no Go graph"
    );

    let second = index(&mut indexer, &repository);
    let after_second = indexer.graph_cache_stats();
    assert_eq!(
        after_second.exact_graph_hits(),
        after_first.exact_graph_misses(),
        "the second pass reused exactly what the first pass built"
    );
    assert_eq!(
        after_second.exact_graph_misses(),
        after_first.exact_graph_misses(),
        "and built nothing new"
    );
    assert_eq!(
        first.index().revision(),
        second.index().revision(),
        "a hit and a miss publish the same identity"
    );
    assert_eq!(
        graph_bytes(&first),
        graph_bytes(&second),
        "and the same graph bytes"
    );
}

/// A changed source is a different claim, so it misses — and the answer it
/// states is still the answer the direct builder would state.
fn a_changed_source_misses_and_still_answers_the_same_shape() {
    let repository = repository();
    let mut indexer = CodeIntelligenceIndexer::new(CodeIntelligenceLimits::default());
    let first = index(&mut indexer, &repository);
    let before = indexer.graph_cache_stats().exact_graph_misses();

    repository.write(
        LIBRARY_SOURCE,
        &format!("{RUST_LIBRARY}\npub fn added() -> u32 {{\n    1\n}}\n"),
    );
    let second = index(&mut indexer, &repository);
    assert!(
        indexer.graph_cache_stats().exact_graph_misses() > before,
        "a changed source states a claim the store never retained"
    );
    assert_ne!(
        first.index().revision(),
        second.index().revision(),
        "and the index that admitted it is a different index"
    );
    assert_eq!(
        project_units(&first),
        project_units(&second),
        "while the projects it resolved are the same projects"
    );
}

/// Two indexers under different host ceilings state different identities, and
/// the store never lets one answer for the other.
fn a_changed_host_limit_states_a_different_identity() {
    let repository = repository();
    let mut host = CodeIntelligenceLimits::default();
    let baseline = index(&mut CodeIntelligenceIndexer::new(host), &repository);
    host.repository.max_files -= 1;
    let lowered = index(&mut CodeIntelligenceIndexer::new(host), &repository);
    assert_ne!(
        baseline.index().revision(),
        lowered.index().revision(),
        "every host ceiling is part of the identity a revision claims"
    );
}

/// A store that may retain one graph evicts, and the answers stay exact.
///
/// The identity is expected to differ, and that is the point: a cache ceiling is
/// a host limit, and every host limit is part of what a revision claims. What
/// eviction must not touch is the answer, so the graph bytes are compared
/// against the store that never evicted.
fn eviction_changes_no_identity_and_no_answer() {
    let repository = repository();
    let whole = index(
        &mut CodeIntelligenceIndexer::new(CodeIntelligenceLimits::default()),
        &repository,
    );

    let evicting = CodeIntelligenceLimits {
        graph_cache: GraphCacheLimits::new(1, 1, 1, 1),
        ..CodeIntelligenceLimits::default()
    };
    let mut indexer = CodeIntelligenceIndexer::new(evicting);
    let first = index(&mut indexer, &repository);
    let second = index(&mut indexer, &repository);
    assert!(
        indexer.graph_cache_stats().exact_graph_evictions() > 0,
        "a store that may retain one graph evicts the rest"
    );
    assert_eq!(
        first.index().revision(),
        second.index().revision(),
        "two passes of one indexer over one repository publish one identity"
    );
    assert_eq!(
        graph_bytes(&second),
        graph_bytes(&whole),
        "and an evicting store answers with the bytes a whole one answers with"
    );
    assert_ne!(
        first.index().revision(),
        whole.index().revision(),
        "while the cache ceiling itself is a host limit the identity claims"
    );
}

/// How many rows one whole graph answer states.
///
/// One neighborhood per project graph that states the seed, at each of the two
/// selections, then one route, then one row per analysis mode. Written down
/// because every comparison this rendering serves is an equality between two of
/// them: a configuration that answered fewer neighborhoods, or no analysis at
/// all, would render the same shorter list on both sides and agree with itself.
const ANSWER_ROWS: usize = 2 * (1 + BINARIES.len()) + 1 + ANALYSIS_MODES.len();

/// The analysis modes one whole graph answer renders, in the order it does.
const ANALYSIS_MODES: [AnalysisMode; 3] = [
    AnalysisMode::DegreeCentrality,
    AnalysisMode::BetweennessCentrality,
    AnalysisMode::Components,
];

/// Every answer a graph query states, rendered without an identity in it.
///
/// The two limit sets below are two host configurations, so they are two index
/// revisions and every handle differs between them. What must not differ is the
/// answer, so each row is rendered from the graph identities and the numbers
/// alone.
///
/// Every row is guarded by a count or a non-empty check before it is rendered,
/// the route included. A route rendered through its `Option` printed the same
/// text on every side of every comparison when no route was found at all.
fn graph_answers(state: &CodeIntelligenceState) -> Box<[String]> {
    let seed = handle(state, LIBRARY_SOURCE, "build");
    let target = handle(state, LIBRARY_SOURCE, "make");
    let mut rendered = Vec::new();
    for (label, edges) in [
        ("every-edge", everything()),
        ("calls-only", kinds(&[EdgeKind::Call])),
    ] {
        let answered = state
            .query_relations(
                &RelationQuery {
                    structure: seed,
                    project: None,
                    direction: RelationDirection::Both,
                    edges,
                    max_depth: 3,
                },
                &whole_page(),
            )
            .expect("the relation query answers")
            .into_result();
        assert_eq!(
            answered.len(),
            1 + BINARIES.len(),
            "{label}: one neighborhood per project graph that states the seed"
        );
        for held in &answered {
            rendered.push(format!(
                "{label}|{}|{}|{}|{}",
                held.seed().index(),
                held.nodes().len(),
                held.edges().len(),
                held.unresolved().len()
            ));
        }
    }
    let route = state
        .find_path(&PathQuery {
            from: seed,
            to: target,
            project: None,
            edges: everything(),
        })
        .expect("the path query answers")
        .into_result();
    rendered.push(format!(
        "path|{:?}",
        route
            .selected()
            .expect("the library states a route from build to make")
            .edges()
            .iter()
            .map(|edge| edge.id().index())
            .collect::<Vec<_>>()
    ));
    let library = project(state, LIBRARY_UNIT);
    for mode in ANALYSIS_MODES {
        let stated = measured(&analyzed(state, library, mode));
        assert!(
            !stated.is_empty(),
            "{}: the library graph states measurements to render",
            mode.token()
        );
        rendered.push(format!("{}|{}", mode.token(), stated));
    }
    assert_eq!(
        rendered.len(),
        ANSWER_ROWS,
        "one whole graph answer states every row the fixture has: {rendered:?}"
    );
    rendered.into_boxed_slice()
}

/// One analysis answer as the graph identities and the numbers alone.
fn measured(answer: &AnalysisAnswer) -> String {
    let node = |entity: &NavigationEntity| entity.node().index();
    match answer {
        AnalysisAnswer::DegreeCentrality(measured) => measured
            .iter()
            .map(|held| {
                format!(
                    "{}:{}:{}",
                    node(held.entity()),
                    held.incoming(),
                    held.outgoing()
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        AnalysisAnswer::BetweennessCentrality(measured) => measured
            .iter()
            .map(|held| format!("{}:{:.9}", node(held.entity()), held.raw()))
            .collect::<Vec<_>>()
            .join(","),
        AnalysisAnswer::Components(measured) => measured
            .iter()
            .map(|held| {
                format!(
                    "{}:{}:{:?}",
                    held.id().index(),
                    held.cyclic(),
                    held.members().iter().map(node).collect::<Vec<_>>()
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        other => panic!("this row states no such mode: {other:?}"),
    }
}

/// The two per-graph ceilings bound the indexes and products a query retains.
///
/// This is what stops them from being ceilings that move a revision and bound
/// nothing. Every graph answer is taken through the handle that owns those two
/// stores, so a repeated question is a lookup — and a store that may retain one
/// of each evicts, which costs a recomputation and never an answer.
fn every_per_graph_ceiling_bounds_what_a_query_retains() {
    let repository = repository();
    let mut indexer = CodeIntelligenceIndexer::new(CodeIntelligenceLimits::default());
    let state = index(&mut indexer, &repository);
    assert_eq!(
        (
            indexer.graph_cache_stats().selected_index_misses(),
            indexer.graph_cache_stats().derived_product_misses(),
        ),
        (0, 0),
        "a sealed build has derived nothing from its graphs yet"
    );

    let answers = graph_answers(&state);
    let first = indexer.graph_cache_stats();
    assert!(
        first.selected_index_misses() > 0 && first.derived_product_misses() > 0,
        "answering indexed each selection and derived each product once: {first:?}"
    );

    assert_eq!(
        graph_answers(&state),
        answers,
        "asking again states the same answers"
    );
    let second = indexer.graph_cache_stats();
    assert_eq!(
        (
            second.selected_index_misses(),
            second.derived_product_misses()
        ),
        (
            first.selected_index_misses(),
            first.derived_product_misses()
        ),
        "and indexed nothing and derived nothing a second time"
    );
    assert!(
        second.selected_index_hits() > first.selected_index_hits()
            && second.derived_product_hits() > first.derived_product_hits(),
        "because both stores answered from what the first pass retained: {second:?}"
    );

    let evicting = CodeIntelligenceLimits {
        graph_cache: GraphCacheLimits::new(4_096, 64, 1, 1),
        ..CodeIntelligenceLimits::default()
    };
    let mut bounded = CodeIntelligenceIndexer::new(evicting);
    let short = index(&mut bounded, &repository);
    assert_eq!(
        graph_answers(&short),
        answers,
        "a store that may retain one index set and one product answers the same"
    );
    let stats = bounded.graph_cache_stats();
    assert!(
        stats.selected_index_evictions() > 0,
        "while the selected-index ceiling evicted what it could not hold: {stats:?}"
    );
    assert!(
        stats.derived_product_evictions() > 0,
        "and so did the derived-product ceiling: {stats:?}"
    );
}

/// Every project slice one index retained, asserted to be some.
///
/// Both renderings below are mapped from this list on each side of an equality,
/// and two empty lists compare equal — so an index that resolved no project at
/// all would satisfy every claim this file makes about the graphs it kept. The
/// guard sits here rather than at each comparison, because a row holding its own
/// copy of it is a row that can be given a weaker one.
fn retained(state: &CodeIntelligenceState) -> &[ProjectSlice] {
    let projects = state.index().projects();
    assert!(
        !projects.is_empty(),
        "the graph repository resolves the projects these comparisons are over"
    );
    projects
}

/// How many of one index's project graphs are Rust ones.
///
/// Every other language builds its graph directly and offers the store nothing,
/// so this is the whole population the exact-graph counters can ever count.
fn rust_graphs(state: &CodeIntelligenceState) -> u64 {
    retained(state)
        .iter()
        .filter(|slice| slice.key().language() == pedant_types::Language::Rust)
        .count() as u64
}

/// One index revision of one repository.
fn index(indexer: &mut CodeIntelligenceIndexer, repository: &Repository) -> CodeIntelligenceState {
    indexer
        .index(repository.root(), &[])
        .expect("the graph repository indexes")
}

/// Every project's key unit, in project-key order.
fn project_units(state: &CodeIntelligenceState) -> Box<[String]> {
    retained(state)
        .iter()
        .map(|slice| slice.key().unit().to_owned())
        .collect()
}

/// Every project's graph, serialized in project-key order.
fn graph_bytes(state: &CodeIntelligenceState) -> Box<[String]> {
    retained(state)
        .iter()
        .map(|slice| serde_json::to_string(slice.graph()).expect("a version-1 graph serializes"))
        .collect()
}
