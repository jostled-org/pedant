//! Which route a path query selects, and which graph it selects it in.
//!
//! Two claims. A route never crosses a project graph, because two graphs are
//! two compilations and a step between them is a relation no language states.
//! And among every eligible ordered instance pair, exactly one route is
//! selected, by a total order the same repository reproduces however its
//! authorities were walked.

use std::collections::BTreeSet;

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, PathAnswer, PathQuery, ProjectHandle,
    StructureHandle,
};
use pedant_types::Language;

use super::fixture::{BINARIES, GO_SOURCE, LIBRARY_SOURCE, handle, indexed_graph, project};
use super::oracles::direct_analysis;
use super::selection::everything;

/// A route stays inside one project graph and is selected exactly.
#[test]
fn path_queries_select_the_exact_common_project_and_endpoint_pair() {
    let (_repository, state) = indexed_graph();

    a_route_inside_one_library_is_the_graph_crate_s_own(&state);
    a_pair_with_no_common_graph_answers_with_no_route(&state);
    a_named_project_selects_that_graph_alone(&state);
    an_unconnected_pair_answers_with_no_route(&state);
    the_selected_route_is_the_shortest_over_every_eligible_pair(&state);
}

/// One path answer, or the refusal that stopped it.
fn attempted(
    state: &CodeIntelligenceState,
    query: &PathQuery,
) -> Result<PathAnswer, CodeIntelligenceError> {
    state
        .find_path(query)
        .map(pedant_snippet::NavigationResponse::into_result)
}

/// One path query over every edge, between two named declarations.
fn between(state: &CodeIntelligenceState, from: (&str, &str), to: (&str, &str)) -> PathQuery {
    PathQuery {
        from: handle(state, from.0, from.1),
        to: handle(state, to.0, to.1),
        project: None,
        edges: everything(),
    }
}

/// The route between two library declarations is the route the graph crate
/// answers for the same endpoints, in the graph the answer names.
fn a_route_inside_one_library_is_the_graph_crate_s_own(state: &CodeIntelligenceState) {
    let query = between(state, (LIBRARY_SOURCE, "build"), (LIBRARY_SOURCE, "make"));
    let answer = attempted(state, &query).expect("both endpoints share a graph");
    let selected = answer
        .selected()
        .expect("the library calls `make` from `build`");
    let index = state.index();
    let slice = index
        .project(selected.project())
        .expect("the route names a retained project");
    let analysis = direct_analysis(index, slice);
    let endpoints = (
        selected
            .nodes()
            .first()
            .expect("a route states its source")
            .node(),
        selected
            .nodes()
            .last()
            .expect("a route states its target")
            .node(),
    );
    let direct = analysis
        .path(endpoints.0, endpoints.1)
        .expect("the direct route answers")
        .expect("and states a route between the same endpoints");
    assert_eq!(
        selected
            .nodes()
            .iter()
            .map(pedant_snippet::NavigationEntity::node)
            .collect::<Vec<_>>(),
        direct.nodes().to_vec(),
        "every stop survives, in order"
    );
    assert_eq!(
        selected
            .edges()
            .iter()
            .map(|edge| edge.id())
            .collect::<Vec<_>>(),
        direct.edges().to_vec(),
        "and every step survives, in order"
    );
    assert_eq!(
        selected.nodes().len(),
        selected.edges().len() + 1,
        "a route states one more stop than it states steps"
    );
}

/// A Rust declaration and a Go declaration each sit in graphs of their own and
/// in no graph together, so the query answers with no route.
///
/// The premise is asserted rather than assumed. "No route was found" is the same
/// observation `an_unconnected_pair_answers_with_no_route` makes, so this row
/// states the thing that separates the two first: both endpoints are joined to
/// graph nodes, and the project graphs they are joined in share nothing. An
/// endpoint that had lost every instance would answer with no route too, and
/// would be a different failure entirely.
fn a_pair_with_no_common_graph_answers_with_no_route(state: &CodeIntelligenceState) {
    let query = between(state, (LIBRARY_SOURCE, "make"), (GO_SOURCE, "New"));
    let index = state.index();
    let graphs_of = |endpoint: StructureHandle| -> BTreeSet<u32> {
        index
            .structure(endpoint)
            .expect("the endpoint handle is this revision's")
            .instances()
            .iter()
            .map(|instance| instance.project().position())
            .collect()
    };
    let rust = graphs_of(query.from);
    let go = graphs_of(query.to);
    assert!(
        !rust.is_empty() && !go.is_empty(),
        "each endpoint states graph instances of its own: {rust:?} {go:?}"
    );
    assert!(
        rust.is_disjoint(&go),
        "and no project graph states both, so there is no graph to search: {rust:?} {go:?}"
    );

    let answer = attempted(state, &query).expect("both endpoints state graph instances");
    assert!(
        answer.selected().is_none(),
        "no route crosses from a Cargo target into a Go module"
    );
}

/// Naming a project answers inside that graph and no other.
fn a_named_project_selects_that_graph_alone(state: &CodeIntelligenceState) {
    let mut query = between(state, (LIBRARY_SOURCE, "build"), (LIBRARY_SOURCE, "make"));
    let named = project(
        state,
        &format!(
            "graph-lib::bin::{}",
            BINARIES.first().expect("the fixture states a binary")
        ),
    );
    query.project = Some(named);
    let answer = attempted(state, &query).expect("the binary graph states both endpoints");
    assert_eq!(
        answer.selected().map(pedant_snippet::RoutedPath::project),
        Some(named),
        "the route runs in the graph that was named"
    );
}

/// Two declarations in one graph with no route between them answer with none,
/// which is not the same as having no graph to look in.
fn an_unconnected_pair_answers_with_no_route(state: &CodeIntelligenceState) {
    let query = between(state, (LIBRARY_SOURCE, "make"), (LIBRARY_SOURCE, "build"));
    let answer = attempted(state, &query).expect("both endpoints share a graph");
    assert!(
        answer.selected().is_none(),
        "`make` does not call `build`, so no route runs that way"
    );
}

/// What one candidate route is ranked by: Invariant 12's order, spelled out.
///
/// Shortest edge count, then project key, then source node, then target node,
/// then the edge identities in order. Written here rather than borrowed from the
/// crate under test, because a comparison taken from the implementation would
/// agree with it whatever the implementation did.
///
/// The edge sequence and both key strings are boxed: each is built once from
/// what the oracle answered and never grows, and a `Vec` or a `String` invited
/// the comparison below to clone it rather than borrow it.
type Candidate = (
    usize,
    (Language, Box<str>, Box<str>),
    u32,
    u32,
    Box<[u32]>,
    ProjectHandle,
);

/// Every route the fixture states between the two endpoints, ranked.
fn every_eligible_route(state: &CodeIntelligenceState, query: &PathQuery) -> Vec<Candidate> {
    let index = state.index();
    let from = index
        .structure(query.from)
        .expect("the source handle is this revision's");
    let to = index
        .structure(query.to)
        .expect("the target handle is this revision's");
    let mut found = Vec::new();
    for slice in index.projects() {
        let analysis = direct_analysis(index, slice);
        let sources = from
            .instances()
            .iter()
            .filter(|held| held.project() == slice.id());
        for source in sources {
            let targets = to
                .instances()
                .iter()
                .filter(|held| held.project() == slice.id());
            for target in targets {
                let Some(route) = analysis
                    .path(source.node(), target.node())
                    .expect("the direct route answers")
                else {
                    continue;
                };
                found.push((
                    route.edges().len(),
                    (
                        slice.key().language(),
                        Box::from(slice.key().authority()),
                        Box::from(slice.key().unit()),
                    ),
                    source.node().index(),
                    target.node().index(),
                    route.edges().iter().map(|edge| edge.index()).collect(),
                    ProjectHandle::new(index.revision(), slice.id().position()),
                ));
            }
        }
    }
    found
}

/// The selected route is the first of every eligible route under Invariant 12's
/// order, and the fixture makes that order decide something.
///
/// `build` and `make` both live in the library source, which every project
/// graph in the workspace compiles — the library and each binary. So one route
/// of equal edge count exists per graph and only the project key separates them.
/// An implementation that took the last graph it walked, or the highest key,
/// states a different answer here, which is what a row asserting shortest length
/// alone cannot see.
///
/// The tie is counted exactly rather than bounded below. Every graph that
/// compiles the source states this route, so a graph that stopped stating it is
/// a route that went missing, and a floor would have absorbed it.
fn the_selected_route_is_the_shortest_over_every_eligible_pair(state: &CodeIntelligenceState) {
    let query = between(state, (LIBRARY_SOURCE, "build"), (LIBRARY_SOURCE, "make"));
    let answer = attempted(state, &query).expect("both endpoints share a graph");
    let selected = answer.selected().expect("a route is selected");

    let mut candidates = every_eligible_route(state, &query);
    candidates.sort();
    let best = candidates.first().expect("some route is eligible");
    let tied: Vec<&Candidate> = candidates.iter().filter(|held| held.0 == best.0).collect();
    assert_eq!(
        tied.len(),
        1 + BINARIES.len(),
        "the library and every binary tie one route each at equal edge count: {:?}",
        candidates
            .iter()
            .map(|held| (held.0, &held.1))
            .collect::<Vec<_>>()
    );
    assert!(
        tied.iter().any(|held| held.1 != best.1),
        "and they sit in different project graphs, so the key is what decides"
    );

    let steps: Vec<u32> = selected
        .edges()
        .iter()
        .map(|edge| edge.id().index())
        .collect();
    assert_eq!(
        (
            selected.project(),
            selected
                .nodes()
                .first()
                .expect("a route states its source")
                .node()
                .index(),
            selected
                .nodes()
                .last()
                .expect("a route states its target")
                .node()
                .index(),
            &steps[..],
        ),
        (best.5, best.2, best.3, &best.4[..]),
        "the route selected is the first under shortest length, project key, \
         source node, target node, then edge sequence"
    );

    assert_eq!(
        state
            .find_path(&query)
            .expect("the query answers again")
            .into_result()
            .selected()
            .map(|held| (held.project(), held.edges().len())),
        Some((selected.project(), selected.edges().len())),
        "and the same repository selects the same route twice"
    );
}
