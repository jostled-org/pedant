//! What one relation answer keeps of the graph answer behind it.
//!
//! The claim is losslessness. Every node the induced selection states, every
//! edge between two of them, every containment row, every unresolved reference,
//! and every distance survives the projection — and each of them is compared
//! against the same question asked of `pedant-graph` directly, so the row is a
//! comparison rather than a restatement.

use std::collections::BTreeSet;

use pedant_snippet::{
    CodeIntelligenceState, EdgeKind, GraphDirection, GraphEdgeKind, GraphReferenceId,
    RelationDirection, RelationNeighborhood, RelationQuery, StructureCoverage,
};

use super::fixture::{
    BINARIES, LIBRARY_SOURCE, LIBRARY_UNIT, assert_ascending, handle, indexed_graph, project,
    whole_page,
};
use super::oracles::{direct_analysis, members};
use super::selection::{everything, kinds};

/// The depth every lossless row walks.
const DEPTH: u32 = 3;

/// Every neighbor, node, edge, containment row, and gap survives projection.
#[test]
fn relation_neighborhoods_preserve_every_instance_node_edge_and_gap() {
    let (_repository, state) = indexed_graph();

    an_omitted_project_expands_every_instance(&state);
    every_projected_member_equals_the_direct_graph_answer(&state);
    a_named_project_selects_exactly_that_graph(&state);
    each_direction_states_its_own_neighborhood(&state);
    an_edge_kind_selection_narrows_the_answer(&state);
    an_unresolved_reference_keeps_its_gaps(&state);
}

/// One page of relations for one seed.
///
/// The answer is asserted to hold a neighborhood before it is returned. Every
/// claim in this file is an equality or a `for` over what came back, and both
/// are satisfied by nothing coming back at all — so the one place every row
/// reaches the index through is the one place that has to ask.
fn relations(state: &CodeIntelligenceState, query: &RelationQuery) -> Box<[RelationNeighborhood]> {
    let answered = state
        .query_relations(query, &whole_page())
        .expect("the relation query answers")
        .into_result();
    assert!(
        !answered.is_empty(),
        "the seed states a neighborhood for this row to be about: {query:?}"
    );
    answered
}

/// One relation query over every edge at the stated direction and depth.
fn query(state: &CodeIntelligenceState, name: (&str, &str), depth: u32) -> RelationQuery {
    RelationQuery {
        structure: handle(state, name.0, name.1),
        project: None,
        direction: RelationDirection::Outgoing,
        edges: everything(),
        max_depth: depth,
    }
}

/// An omitted project answers one neighborhood per instance, in the order the
/// instances are sealed.
fn an_omitted_project_expands_every_instance(state: &CodeIntelligenceState) {
    let answered = relations(state, &query(state, (LIBRARY_SOURCE, "build"), DEPTH));
    assert_eq!(
        answered.len(),
        1 + BINARIES.len(),
        "one neighborhood per project graph that states the seed"
    );
    let ordered: Vec<(u32, u32)> = answered
        .iter()
        .map(|held| (held.project().id().position(), held.seed().index()))
        .collect();
    assert_ascending(&ordered, "in project then node order");
    assert!(
        answered
            .iter()
            .all(|held| held.coverage() == StructureCoverage::Resolved),
        "and each states the evidence its own slice carries"
    );
}

/// Every member of every neighborhood equals what the graph crate answers for
/// the same seed, selection, direction, and depth.
fn every_projected_member_equals_the_direct_graph_answer(state: &CodeIntelligenceState) {
    let answered = relations(state, &query(state, (LIBRARY_SOURCE, "build"), DEPTH));
    let index = state.index();
    for held in &answered {
        let slice = index
            .project(held.project())
            .expect("the neighborhood names a retained project");
        let analysis = direct_analysis(index, slice);
        let neighbors = analysis
            .neighbors(held.seed(), DEPTH, GraphDirection::Outgoing)
            .expect("the direct walk answers");
        let induced = analysis
            .subgraph(held.seed(), DEPTH, GraphDirection::Outgoing)
            .expect("the direct selection answers");

        assert_eq!(
            held.neighbors()
                .iter()
                .map(|reached| (reached.node(), reached.distance()))
                .collect::<Vec<_>>(),
            neighbors
                .iter()
                .map(|reached| (reached.node(), reached.distance()))
                .collect::<Vec<_>>(),
            "every reached node and distance survives"
        );
        assert_eq!(
            members(held.nodes()),
            induced.nodes().to_vec(),
            "every induced node survives, in node-id order"
        );
        assert_eq!(
            held.edges()
                .iter()
                .map(|edge| edge.id())
                .collect::<Vec<_>>(),
            induced.edges().to_vec(),
            "every induced edge survives, in edge-id order"
        );
        assert_eq!(
            held.containment().to_vec(),
            induced.containment().to_vec(),
            "every containment row survives"
        );
        assert!(
            held.edges()
                .iter()
                .all(|edge| slice.graph().edge(edge.id()) == Some(edge)),
            "and every edge is the graph's own record, certainty and origin included"
        );
    }
}

/// Naming a project answers about that graph and no other.
fn a_named_project_selects_exactly_that_graph(state: &CodeIntelligenceState) {
    let named = project(state, LIBRARY_UNIT);
    let mut query = query(state, (LIBRARY_SOURCE, "build"), DEPTH);
    query.project = Some(named);
    let answered = relations(state, &query);
    assert_eq!(answered.len(), 1, "one graph was named, so one answered");
    assert_eq!(
        answered[0].project(),
        named,
        "and it is the graph that was named"
    );
}

/// Following edges the other way answers about the other side of the topology.
///
/// Each set is required to hold something. `make` is called from the crate root
/// and from the second module and reaches its own return type, so both
/// directions state neighbors — and an inequality between an empty set and a
/// full one, with the empty side a subset of everything, is the shape a walk
/// that stopped following one direction would pass under.
fn each_direction_states_its_own_neighborhood(state: &CodeIntelligenceState) {
    let base = query(state, (LIBRARY_SOURCE, "make"), DEPTH);
    let reached = |direction: RelationDirection| -> BTreeSet<u32> {
        let mut stated = base.clone();
        stated.direction = direction;
        relations(state, &stated)
            .iter()
            .flat_map(|held| {
                held.neighbors()
                    .iter()
                    .map(|reached| reached.node().index())
            })
            .collect()
    };
    let outgoing = reached(RelationDirection::Outgoing);
    let incoming = reached(RelationDirection::Incoming);
    let both = reached(RelationDirection::Both);
    assert!(
        !outgoing.is_empty() && !incoming.is_empty(),
        "each direction reaches something: {outgoing:?} {incoming:?}"
    );
    assert_ne!(
        outgoing, incoming,
        "the two directions state different sets"
    );
    assert!(
        outgoing.is_subset(&both) && incoming.is_subset(&both),
        "and following either way reaches both: {outgoing:?} {incoming:?} {both:?}"
    );
}

/// Admitting fewer edge kinds admits fewer edges, and never more.
///
/// Both halves are stated as counts on purpose. A subset claim and an "every
/// kind is a call" claim are both satisfied by an empty answer, so a narrowing
/// that dropped every edge would pass the row whose whole subject is what
/// narrowing keeps.
fn an_edge_kind_selection_narrows_the_answer(state: &CodeIntelligenceState) {
    let mut whole = query(state, (LIBRARY_SOURCE, "build"), DEPTH);
    whole.project = Some(project(state, LIBRARY_UNIT));
    let mut narrowed = whole.clone();
    narrowed.edges = kinds(&[EdgeKind::Call]);

    let all_edges = edge_kinds(&relations(state, &whole));
    let call_edges = edge_kinds(&relations(state, &narrowed));
    assert_eq!(
        call_edges,
        BTreeSet::from([GraphEdgeKind::Call]),
        "the narrowed selection admits the kind it named, and admits nothing else"
    );
    assert!(
        call_edges.is_subset(&all_edges) && all_edges.len() > call_edges.len(),
        "and the wider selection admits those calls and strictly more: {all_edges:?}"
    );
}

/// The depth the gap row walks, wide enough that the whole graph is reached.
const GAP_DEPTH: u32 = 16;

/// A reference no edge answered stays in the answer with its gaps.
///
/// Required rather than conditional. A fixture that stopped stating an
/// unresolved reference would leave this the only owner of Invariant 10's gap
/// clause with nothing to own, so the count the graphs state is asserted to be
/// nonzero before the answer is asked to carry it — and what it carries is
/// compared row for row against the same references read straight off the
/// retained graph.
///
/// The node set the expectation is filtered by comes from the graph crate's own
/// selection rather than from the answer under test. Reading it off the answer
/// made the oracle a projection of the thing being projected: a build that
/// dropped a node here would drop that node's expected references with it, both
/// sides would shrink together, and the nonzero count would survive on whatever
/// was left.
fn an_unresolved_reference_keeps_its_gaps(state: &CodeIntelligenceState) {
    let index = state.index();
    let mut query = query(state, (LIBRARY_SOURCE, "build"), GAP_DEPTH);
    query.direction = RelationDirection::Both;
    let answered = relations(state, &query);

    let mut carried = 0_usize;
    for held in &answered {
        let slice = index
            .project(held.project())
            .expect("each neighborhood names a retained project");
        let reached = direct_analysis(index, slice)
            .subgraph(held.seed(), GAP_DEPTH, GraphDirection::Both)
            .expect("the direct selection answers")
            .nodes()
            .to_vec();
        let direct: Vec<GraphReferenceId> = slice
            .graph()
            .references()
            .iter()
            .filter(|reference| reference.edges().is_empty())
            .filter(|reference| reached.contains(&reference.source()))
            .map(|reference| reference.id())
            .collect();
        assert_eq!(
            held.unresolved()
                .iter()
                .map(|reference| reference.id())
                .collect::<Vec<_>>(),
            direct,
            "every reference the graph left unanswered survives, and no other"
        );
        carried += direct.len();
    }
    assert!(
        carried > 0,
        "the fixture states at least one reference no edge answered, and it is in the answer"
    );
    assert!(
        answered
            .iter()
            .flat_map(RelationNeighborhood::unresolved)
            .all(|reference| reference.edges().is_empty() && !reference.gaps().is_empty()),
        "and every carried row is one no edge answered, with the gaps that say why"
    );
}

/// Every edge kind one answer carries.
fn edge_kinds(answered: &[RelationNeighborhood]) -> BTreeSet<GraphEdgeKind> {
    answered
        .iter()
        .flat_map(|held| held.edges().iter().map(|edge| edge.kind()))
        .collect()
}
