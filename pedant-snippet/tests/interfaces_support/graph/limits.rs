//! The ceilings a graph query runs beneath, and the order they refuse in.
//!
//! Two owners, and this file states one of them. The repository clamps what a
//! graph build may retain, which `index::graphs` proves from a table covering
//! nodes, references, and edges alike — so nothing here restates it. The host
//! clamps what an analysis may cost, and a request may lower that ceiling and
//! never raise it, so a caller cannot spend more of the host's budget than the
//! host configured.
//!
//! The order is the claim: request shape, then request against host, then the
//! node count, then the selected-edge count, then the depth. Each row below
//! holds every later refusal available and proves the earlier one wins.

use pedant_snippet::{
    AnalysisLimitRequest, AnalysisMode, AnalysisQuery, CapacityCollection, CapacityOwner,
    CodeIntelligenceError, CodeIntelligenceLimits, CodeIntelligenceState, GraphAnalysisLimits,
    ProjectHandle, ProjectSlice, RelationDirection, RelationQuery,
};

use super::fixture::{
    LIBRARY_SOURCE, LIBRARY_UNIT, bounded, handle, indexed_graph, project, whole_page,
};
use super::selection::everything;
use crate::index::fixture::Repository;

/// Every graph ceiling refuses at its named owner, in the stated order.
///
/// The repository is bound rather than discarded: the last row indexes the same
/// tree a second time under a lowered ceiling, and a second tree would cost
/// sixteen more writes and a second walk of the workspace for the same sources.
#[test]
fn code_intelligence_graph_limits_and_request_lowering_are_exact() {
    let (repository, state) = indexed_graph();
    let library = project(&state, LIBRARY_UNIT);

    a_request_may_lower_every_analysis_ceiling(&state, library);
    a_request_above_the_host_refuses_before_construction(&state, library);
    the_request_comparison_precedes_every_count(&state, library);
    a_node_ceiling_refuses_before_the_selected_edge_ceiling(&state, library);
    a_depth_above_the_ceiling_refuses_the_walk(&state);
    a_path_query_evaluates_no_depth(&repository);
}

/// One analysis attempt under stated request ceilings.
fn attempted(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
    limits: AnalysisLimitRequest,
    mode: AnalysisMode,
) -> Result<(), CodeIntelligenceError> {
    state
        .analyze_graph(&AnalysisQuery {
            project,
            edges: everything(),
            mode,
            limits,
        })
        .map(|_| ())
}

/// The capacity refusal one outcome states.
fn capacity_of(
    outcome: Result<(), CodeIntelligenceError>,
    why: &str,
) -> (CapacityOwner, CapacityCollection, u64, u64) {
    match outcome {
        Err(CodeIntelligenceError::Capacity {
            owner,
            collection,
            observed,
            limit,
        }) => (owner, collection, observed, limit),
        Err(other) => panic!("{why}: refused for another reason: {other}"),
        Ok(()) => panic!("{why}: answered instead of refusing"),
    }
}

/// An omitted field is the host field, and a stated field at or below it is
/// admitted.
fn a_request_may_lower_every_analysis_ceiling(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
) {
    let host = state.index().limits().graph_analysis;
    let nodes = node_count(state, project);
    attempted(
        state,
        project,
        AnalysisLimitRequest::default(),
        AnalysisMode::DegreeCentrality,
    )
    .expect("an omitted request runs beneath the host's own ceilings");
    attempted(
        state,
        project,
        AnalysisLimitRequest {
            max_nodes: Some(nodes),
            max_selected_edges: Some(host.max_selected_edges()),
            max_depth: Some(host.max_depth()),
            max_betweenness_work: Some(host.max_betweenness_work()),
        },
        AnalysisMode::DegreeCentrality,
    )
    .expect("a request at exactly what the graph states is admitted");
}

/// Every field above its host field refuses, named, and before any count.
fn a_request_above_the_host_refuses_before_construction(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
) {
    let host = state.index().limits().graph_analysis;
    let rows: [(&str, AnalysisLimitRequest); 4] = [
        (
            "max_nodes",
            AnalysisLimitRequest {
                max_nodes: Some(host.max_nodes().saturating_add(1)),
                ..AnalysisLimitRequest::default()
            },
        ),
        (
            "max_selected_edges",
            AnalysisLimitRequest {
                max_selected_edges: Some(host.max_selected_edges().saturating_add(1)),
                ..AnalysisLimitRequest::default()
            },
        ),
        (
            "max_depth",
            AnalysisLimitRequest {
                max_depth: Some(host.max_depth().saturating_add(1)),
                ..AnalysisLimitRequest::default()
            },
        ),
        (
            "max_betweenness_work",
            AnalysisLimitRequest {
                max_betweenness_work: Some(host.max_betweenness_work().saturating_add(1)),
                ..AnalysisLimitRequest::default()
            },
        ),
    ];
    for (field, request) in rows {
        match attempted(state, project, request, AnalysisMode::DegreeCentrality) {
            Err(CodeIntelligenceError::InvalidQuerySelection { reason }) => assert!(
                reason.contains(field),
                "{field}: the refusal names the field that raised a ceiling: {reason}"
            ),
            other => panic!("{field}: a request may not raise a host ceiling: {other:?}"),
        }
    }
}

/// A request that both raises one ceiling and would fail a count refuses for
/// the comparison, because the comparison happens first.
///
/// The refusal is read for the field it names, not merely for its kind. A node
/// ceiling of zero is a request shape too, so an implementation that refused
/// this one for `max_nodes` would state the same variant and prove the opposite
/// of what the row is named for.
fn the_request_comparison_precedes_every_count(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
) {
    let host = state.index().limits().graph_analysis;
    let outcome = attempted(
        state,
        project,
        AnalysisLimitRequest {
            max_nodes: Some(0),
            max_selected_edges: Some(host.max_selected_edges().saturating_add(1)),
            ..AnalysisLimitRequest::default()
        },
        AnalysisMode::DegreeCentrality,
    );
    match outcome {
        Err(CodeIntelligenceError::InvalidQuerySelection { reason }) => assert!(
            reason.contains("max_selected_edges"),
            "a zero node ceiling would also refuse, and the raised ceiling refuses first: \
             {reason}"
        ),
        other => panic!("the request comparison precedes every count: {other:?}"),
    }
}

/// A node ceiling below the graph's own refuses at the graph-analysis owner,
/// and it refuses before the selected-edge ceiling does.
fn a_node_ceiling_refuses_before_the_selected_edge_ceiling(
    state: &CodeIntelligenceState,
    project: ProjectHandle,
) {
    let nodes = node_count(state, project);
    assert!(
        nodes > 1,
        "the library graph states nodes to bound: {nodes}"
    );
    let refusal = capacity_of(
        attempted(
            state,
            project,
            AnalysisLimitRequest {
                max_nodes: Some(nodes - 1),
                max_selected_edges: Some(0),
                ..AnalysisLimitRequest::default()
            },
            AnalysisMode::DegreeCentrality,
        ),
        "a node ceiling below the graph refuses",
    );
    assert_eq!(
        refusal,
        (
            CapacityOwner::GraphAnalysis,
            CapacityCollection::GraphNode,
            u64::from(nodes),
            u64::from(nodes - 1)
        ),
        "at the graph-analysis owner, naming the count and the ceiling, before the edge row"
    );
}

/// A walk deeper than the host's depth ceiling refuses at the traversal owner.
fn a_depth_above_the_ceiling_refuses_the_walk(state: &CodeIntelligenceState) {
    let host = state.index().limits().graph_analysis;
    let outcome = state
        .query_relations(
            &RelationQuery {
                structure: handle(state, LIBRARY_SOURCE, "build"),
                project: None,
                direction: RelationDirection::Outgoing,
                edges: everything(),
                max_depth: host.max_depth().saturating_add(1),
            },
            &whole_page(),
        )
        .map(|_| ());
    assert_eq!(
        capacity_of(outcome, "a walk past the depth ceiling refuses"),
        (
            CapacityOwner::GraphAnalysis,
            CapacityCollection::TraversalDepth,
            u64::from(host.max_depth()) + 1,
            u64::from(host.max_depth())
        ),
        "naming the depth requested and the ceiling that refused it"
    );
}

/// A path query states no depth at all, so the host's depth ceiling has nothing
/// to refuse and a route as long as the topology makes it still answers.
fn a_path_query_evaluates_no_depth(repository: &Repository) {
    let lowered = CodeIntelligenceLimits {
        graph_analysis: GraphAnalysisLimits::new(100_000, 400_000, 0, 50_000_000),
        ..CodeIntelligenceLimits::default()
    };
    let bounded_state = bounded(repository, lowered);
    let answer = bounded_state
        .find_path(&pedant_snippet::PathQuery {
            from: handle(&bounded_state, LIBRARY_SOURCE, "build"),
            to: handle(&bounded_state, LIBRARY_SOURCE, "make"),
            project: None,
            edges: everything(),
        })
        .expect("a route requests no depth, so a depth ceiling of zero refuses nothing")
        .into_result();
    assert!(
        answer.selected().is_some(),
        "and the route the topology states is still found"
    );
}

/// How many nodes one project's graph states.
fn node_count(state: &CodeIntelligenceState, project: ProjectHandle) -> u32 {
    graph_nodes(
        state
            .index()
            .project(project)
            .expect("the project is retained"),
    )
}

/// The node count one retained graph states.
///
/// Stated once, because this number becomes a ceiling one record below itself
/// and a saturating conversion would hand the rows above a ceiling the fixture
/// never measured.
fn graph_nodes(slice: &ProjectSlice) -> u32 {
    u32::try_from(slice.graph().nodes().len()).expect("the fixture graph fits in a u32")
}
