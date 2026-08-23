//! What the Rust answers still are once the assembler stopped being Rust's.
//!
//! The neutral family changed who mints a graph, not what a graph is. These
//! cases read the claim that would fail silently if it had: every Rust graph a
//! caller can obtain — directly, at a lowered ceiling, and through a cache miss
//! — is byte-for-byte what it was. What the retention surface around those
//! answers still is belongs to [`super::cache_rust_only`].

use pedant_graph::{
    CodeGraph, GraphBuildError, GraphCache, GraphCollection, GraphLimits,
    build_rust_graph_with_limits,
};

use super::analysis_perturbation::{
    assert_perturbation_reaches_minted_identities, created_in_reverse, declared_in_reverse, sorted,
};
use super::cache_counting::{
    Classification, EXACT_GRAPH_HITS, assert_build_classifies, assert_delta,
};
use super::cache_fixture::{
    admitted, assert_direct_builders_agree, assert_equals_direct, bounded, build, direct, generous,
    json, pair, projection_only,
};
use super::cache_revision::{REVISIONS, revised};
use super::corpus_revision::{REVISION_CORPUS, REVISION_FRAGMENTS};
use super::fixture::{self, CORPUS_LIBRARY, Resolved};
use super::render;

/// Direct, bounded, and cache-miss Rust graphs are byte-identical to what the
/// Rust-owned assembler returned, over every retained corpus.
pub fn assert_rust_projection_bytes_stay_exact() {
    assert_the_published_builders_agree();
    assert_direct_and_cached_revisions_agree();
    assert_lowered_ceilings_refuse_alike();
    assert_one_repository_states_one_snapshot_and_one_graph();
    assert_declaration_order_reaches_no_answer();
}

/// The two published direct builders answer one graph for one input.
///
/// One claim about the published surface — that the shorter entry point still
/// forwards the ceilings it names — so it is stated once over one resolved
/// corpus rather than at every cached row below.
fn assert_the_published_builders_agree() {
    let (_repository, resolved) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    assert_direct_builders_agree(pair(&resolved), "the two published direct builders");
}

/// Every revision of the retained corpus states one graph, whichever entry a
/// caller reached it through, and the projection seam classifies it exactly.
///
/// The revised build is run against a warmed store, so its fragments arrive
/// through the reuse path rather than through a fresh derivation. A retained
/// draft that no longer described the graph the assembler mints would show up
/// here as a difference from the direct build the same inputs produce.
fn assert_direct_and_cached_revisions_agree() {
    for revision in REVISIONS {
        let subject = revision.label();
        let (_repository, base, after) = revised(revision);
        let mut cache = GraphCache::new(projection_only(64));
        let warmed = assert_build_classifies(
            &mut cache,
            pair(&base),
            Classification::retained(0, REVISION_FRAGMENTS),
            &format!("{subject}: the base build"),
        );
        assert_exact_against_direct(warmed.graph(), &base, &format!("{subject}: the base build"));

        let rebuilt = assert_build_classifies(
            &mut cache,
            pair(&after),
            Classification::retained(revision.hits(), revision.misses()),
            subject,
        );
        assert_exact_against_direct(rebuilt.graph(), &after, subject);
    }
}

/// One graph equals the direct build column for column, byte for byte, and
/// through the reading surface a caller compares two graphs with.
///
/// The direct graph is projected once and every reading is taken from it. Four
/// projections of one input would be four chances for the same input to state
/// four different graphs, which no reading here could tell from agreement.
fn assert_exact_against_direct(built: &CodeGraph, resolved: &Resolved, subject: &str) {
    let minted = direct(pair(resolved), GraphLimits::default(), subject);
    assert_equals_direct(built, &minted, subject);
    for (reading, held, stated) in [
        ("nodes", render::nodes(built), render::nodes(&minted)),
        (
            "containment",
            render::containment(built),
            render::containment(&minted),
        ),
        (
            "reference sites",
            render::reference_sites(built),
            render::reference_sites(&minted),
        ),
    ] {
        assert_eq!(held, stated, "{subject}: the rendered {reading} differ");
    }
    assert_eq!(
        (
            built.nodes().len(),
            built.references().len(),
            built.edges().len(),
            built.containment().len(),
        ),
        (
            minted.nodes().len(),
            minted.references().len(),
            minted.edges().len(),
            minted.containment().len(),
        ),
        "{subject}: the two builds state different record counts"
    );
}

/// A lowered ceiling refuses the same collection and amount whichever entry
/// point takes it, and a hit reapplies it in construction order.
fn assert_lowered_ceilings_refuse_alike() {
    let (_repository, resolved) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let mut cache = GraphCache::new(generous());
    let warm = admitted(&mut cache, pair(&resolved), "the warming build");
    let counts = [
        ("node", warm.graph().nodes().len(), GraphCollection::Node),
        (
            "reference",
            warm.graph().references().len(),
            GraphCollection::Reference,
        ),
        ("edge", warm.graph().edges().len(), GraphCollection::Edge),
    ];

    for (label, counted, collection) in counts {
        assert!(counted > 0, "the warming graph states at least one {label}");
        let ceiling = u32::try_from(counted)
            .unwrap_or_else(|error| panic!("{label}s outnumber a dense identity: {error}"))
            - 1;
        let limits = lowered(collection, ceiling);
        let before = cache.stats();
        let cached = build(&mut cache, pair(&resolved), limits)
            .err()
            .unwrap_or_else(|| panic!("{label}: the lowered ceiling was admitted"));
        let directly =
            build_rust_graph_with_limits(&resolved.snapshot, &resolved.resolution, limits)
                .err()
                .unwrap_or_else(|| panic!("{label}: the direct build admitted it"));
        match cached {
            GraphBuildError::CapacityExceeded {
                collection: refused,
                limit,
            } => assert_eq!(
                (refused, limit),
                (collection, ceiling),
                "{label}: the refusal names its own collection and ceiling"
            ),
            other => panic!("{label}: unexpected refusal {other:?}"),
        }
        assert_eq!(
            format!("{cached:?}"),
            format!("{directly:?}"),
            "{label}: the cached and direct refusals agree"
        );
        assert_delta(before, cache.stats(), &[(EXACT_GRAPH_HITS, 1)], label);
    }

    let readmitted = bounded(
        &mut cache,
        pair(&resolved),
        GraphLimits::default(),
        "the readmitted build",
    );
    assert!(
        std::ptr::eq(warm.graph(), readmitted.graph()),
        "a refused ceiling leaves the retained graph in place"
    );
}

/// The ceilings that admit every collection but one.
fn lowered(collection: GraphCollection, ceiling: u32) -> GraphLimits {
    match collection {
        GraphCollection::Node => GraphLimits::new(ceiling, u32::MAX, u32::MAX),
        GraphCollection::Reference => GraphLimits::new(u32::MAX, ceiling, u32::MAX),
        GraphCollection::Edge => GraphLimits::new(u32::MAX, u32::MAX, ceiling),
    }
}

/// One repository written in either direction states one snapshot, and one
/// snapshot states one graph.
///
/// Two claims, and the first is what makes the second worth reading. The
/// snapshot walk sorts every directory entry, so the order a caller's
/// filesystem happened to enumerate the corpus in is already gone by the time a
/// projection sees anything — which is asserted here rather than assumed,
/// because without it the row below would be the assembler called twice over
/// one input and could not fail. What the projection is then held to is that
/// one snapshot, read twice, states one set of version-1 bytes.
///
/// The fingerprint is not what answers the first claim, and must not be read as
/// though it were: it covers the canonical repository root, and two fixtures
/// are two temporary directories, so two snapshots of one corpus never share
/// one. What a projection reads is each unit's source membership and each
/// source's normalized path and exact bytes, and those are what already agree.
///
/// The perturbation a projection *can* observe is a declaration order, and it
/// is read by [`assert_declaration_order_reaches_no_answer`] beside it.
fn assert_one_repository_states_one_snapshot_and_one_graph() {
    let (_forward, forward) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let (_reverse, reverse) =
        fixture::resolve_target(&created_in_reverse(REVISION_CORPUS), CORPUS_LIBRARY);
    let subject = "a reversed enumeration order";
    assert_eq!(
        snapshot_sources(&forward),
        snapshot_sources(&reverse),
        "{subject}: both walks read the same sources, with the same bytes, in one order"
    );
    assert_eq!(
        instantiated_sources(&forward),
        instantiated_sources(&reverse),
        "{subject}: both walks give every unit the same source membership"
    );
    let first = direct(pair(&forward), GraphLimits::default(), subject);
    let second = direct(pair(&reverse), GraphLimits::default(), subject);
    assert_eq!(
        json(&first),
        json(&second),
        "{subject}: one snapshot states one set of version-1 bytes"
    );
}

/// Every source one snapshot holds, as the normalized path and the exact bytes
/// read at it, in the order the walk stored them.
fn snapshot_sources(resolved: &Resolved) -> Vec<String> {
    resolved
        .snapshot
        .sources()
        .iter()
        .map(|source| format!("{}|{:02x?}", source.path(), source.digest()))
        .collect()
}

/// The sources each planned unit instantiates, in snapshot unit order.
fn instantiated_sources(resolved: &Resolved) -> Vec<String> {
    resolved
        .snapshot
        .units()
        .iter()
        .map(|unit| {
            unit.sources()
                .iter()
                .map(|path| &**path)
                .collect::<Vec<&str>>()
                .join(",")
        })
        .collect()
}

/// The same library, its declarations restated in the opposite order, states
/// the same graph everywhere a minted identity does not appear.
///
/// This is the perturbation the projection can actually observe: item order
/// carries no meaning in Rust, so the reordered corpus is the same library, but
/// the report states its definitions in another order and every dense identity
/// after the first one moves.
/// [`assert_perturbation_reaches_minted_identities`] proves that the identities
/// did move before anything is compared, so what follows cannot be one graph
/// compared with itself.
fn assert_declaration_order_reaches_no_answer() {
    let subject = "a reversed declaration order";
    let (_written, written) = fixture::resolve_target(REVISION_CORPUS, CORPUS_LIBRARY);
    let restated = declared_in_reverse(REVISION_CORPUS);
    let borrowed: Vec<(&str, &str)> = restated
        .iter()
        .map(|(path, text)| (*path, text.as_str()))
        .collect();
    let (_reordered, reordered) = fixture::resolve_target(&borrowed, CORPUS_LIBRARY);

    let first = direct(pair(&written), GraphLimits::default(), subject);
    let second = direct(pair(&reordered), GraphLimits::default(), subject);
    assert_perturbation_reaches_minted_identities(&first, &second);
    assert_eq!(
        sorted(&named_nodes(&first)),
        sorted(&named_nodes(&second)),
        "{subject}: the same declarations state the same nodes"
    );
    assert_eq!(
        sorted(&named_containment(&first)),
        sorted(&named_containment(&second)),
        "{subject}: the same declarations state the same containment"
    );
    assert_eq!(
        (
            first.nodes().len(),
            first.references().len(),
            first.edges().len(),
            first.containment().len(),
        ),
        (
            second.nodes().len(),
            second.references().len(),
            second.edges().len(),
            second.containment().len(),
        ),
        "{subject}: the same declarations state the same record counts"
    );
}

/// Every node as `name|kind`, with no minted identity in it.
fn named_nodes(graph: &CodeGraph) -> Vec<String> {
    graph
        .nodes()
        .iter()
        .map(|node| format!("{}|{}", node.name(), render::node_kind(node.kind())))
        .collect()
}

/// Every containment pair as `parent>child`, both named.
fn named_containment(graph: &CodeGraph) -> Vec<String> {
    graph
        .containment()
        .iter()
        .map(|edge| {
            format!(
                "{}>{}",
                node_name(graph, edge.parent()),
                node_name(graph, edge.child())
            )
        })
        .collect()
}

/// The name one node of one graph states.
fn node_name(graph: &CodeGraph, node: pedant_graph::GraphNodeId) -> String {
    graph
        .node(node)
        .map(|held| held.name().to_owned())
        .unwrap_or_else(|| panic!("the graph holds node {}", node.index()))
}
