//! Every neighborhood one seed declaration states, one page at a time.
//!
//! The page is over neighborhoods, because a neighborhood is what a seed
//! instance states and every node, edge, containment row, and unresolved
//! reference belongs to exactly one of them. Paging over the members instead
//! would cut a walk in half and leave a caller holding edges whose endpoints
//! are on the next page.
//!
//! No algorithm runs here. The neighbor walk, the induced selection, and the
//! ceilings that bound them are `pedant-graph`'s, and this module states which
//! graph, which seed, and which selection — then says what each answer means in
//! terms of the declarations this index retained.

use pedant_graph::{
    CodeGraph, GraphEdge, GraphEdgeId, GraphEdgeSelection, GraphNodeId, GraphReference,
};

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeIntelligenceState, ProjectSlice,
    SliceAnalysis, StructureInstance,
};

use super::super::page::Window;
use super::super::page_request::PageRequest;
use super::super::response::NavigationResponse;
use super::entity::Projector;
use super::neighborhood::{RelationNeighbor, RelationNeighborhood};
use super::refusal::{joined, opened, refusing};
use super::relation_request::RelationQuery;
use super::seed::seeded;

/// Answer `query_relations`.
pub(crate) fn relations_selected(
    state: &CodeIntelligenceState,
    query: &RelationQuery,
    request: &PageRequest,
) -> Result<NavigationResponse<Box<[RelationNeighborhood]>>, CodeIntelligenceError> {
    let selection = query.edges.admitted()?;
    let window = Window::opened(state, query, request)?;
    let index = state.index();
    let instances = seeded(index, query.structure, query.project)?;
    let total = instances.len();
    let selected = window.page(&instances)?;

    let mut projector = Projector::new(index);
    let answered: Box<[RelationNeighborhood]> = selected
        .chunk_by(|held, next| held.project() == next.project())
        .try_fold(Vec::with_capacity(selected.len()), |answered, run| {
            walked((index, &mut projector), run, (query, selection), answered)
        })?
        .into_boxed_slice();
    Ok(NavigationResponse::paged(
        state,
        answered,
        window.next(state, query, total),
    ))
}

/// Every neighborhood one run of same-project seed instances states, appended to
/// what the runs before it stated.
///
/// One analysis per run, not one per instance. Opening one scans the whole
/// graph's admitted edge counts and, for a slice this host has to select the
/// indexes of, rebuilds that table too — which is the same reason the route
/// query opens one per slice rather than one per endpoint pair. The seeds arrive
/// in project then node order, so every instance of one slice is a contiguous
/// run.
///
/// The answers travel through the fold rather than being collected per run: the
/// page is one list in seed order, and a list per run would allocate once per
/// project only to concatenate them back.
fn walked(
    held: (&CodeIntelligenceIndex, &mut Projector<'_>),
    run: &[StructureInstance],
    stated: (&RelationQuery, GraphEdgeSelection),
    mut answered: Vec<RelationNeighborhood>,
) -> Result<Vec<RelationNeighborhood>, CodeIntelligenceError> {
    let (index, projector) = held;
    let (query, selection) = stated;
    let Some(first) = run.first() else {
        return Ok(answered);
    };
    let slice = joined(index, first.project())?;
    let analysis = opened(slice, selection, index.limits().graph_analysis)?;
    for instance in run {
        answered.push(neighborhood(
            (&analysis, slice),
            projector,
            *instance,
            query,
        )?);
    }
    Ok(answered)
}

/// One seed instance's whole neighborhood, under its own slice's analysis.
///
/// One induced selection answers the whole row. The distances and the selected
/// nodes are two readings of one breadth-first walk, so asking the analysis for
/// each separately would traverse the reachable set twice and spend two slots of
/// the bounded derived-product store on one answer.
fn neighborhood(
    held: (&SliceAnalysis<'_>, &ProjectSlice),
    projector: &mut Projector<'_>,
    instance: StructureInstance,
    query: &RelationQuery,
) -> Result<RelationNeighborhood, CodeIntelligenceError> {
    let (analysis, slice) = held;
    let authority = slice.key().authority();
    let seed = instance.node();
    let neighbors = analysis
        .neighbors(seed, query.max_depth, query.direction.admitted())
        .map_err(refusing(slice, analysis.limits()))?;
    let induced = analysis
        .subgraph(seed, query.max_depth, query.direction.admitted())
        .map_err(refusing(slice, analysis.limits()))?;
    let entities = projector.entities(slice, induced.nodes())?;
    Ok(RelationNeighborhood::stated(
        (projector.handle(slice), seed, slice.coverage()),
        (
            neighbors
                .iter()
                .map(|reached| RelationNeighbor::stated(reached.node(), reached.distance()))
                .collect(),
            entities,
        ),
        (
            edges(analysis.graph(), induced.edges(), authority)?,
            Box::from(induced.containment()),
            unresolved(analysis, induced.nodes()),
        ),
    ))
}

/// Every selected edge, exactly as the graph records it.
///
/// Stated here for both the neighborhood and the route, because both hand the
/// same graph the identities they read out of it.
///
/// A selected identity the graph holds no record for cannot happen, so it is
/// refused rather than skipped. Skipping it would hand a caller a neighborhood
/// whose edges name endpoints the same answer never lists, and a route stating
/// fewer steps than the stops between them — the one-more-node-than-edges
/// invariant the `path_record` module documents, broken silently.
pub(super) fn edges(
    graph: &CodeGraph,
    selected: &[GraphEdgeId],
    authority: &str,
) -> Result<Box<[GraphEdge]>, CodeIntelligenceError> {
    selected
        .iter()
        .map(|id| {
            graph
                .edge(*id)
                .cloned()
                .ok_or_else(|| CodeIntelligenceError::Graph {
                    authority: Box::from(authority),
                    reason: format!(
                        "edge {} is selected by a graph that records no such edge",
                        id.index()
                    )
                    .into_boxed_str(),
                })
        })
        .collect()
}

/// Every reference a selected node states that no edge answered.
///
/// Kept whole, with its gaps: a reference with no target edge is the evidence
/// that the repository states a name this tier could not resolve, and dropping
/// it would render an unresolved call as a function that calls nothing.
fn unresolved(analysis: &SliceAnalysis<'_>, selected: &[GraphNodeId]) -> Box<[GraphReference]> {
    analysis
        .graph()
        .references()
        .iter()
        .filter(|reference| reference.edges().is_empty())
        .filter(|reference| selected.binary_search(&reference.source()).is_ok())
        .cloned()
        .collect()
}
