//! The shortest route between two declarations, inside one project graph.
//!
//! Never between two. A path across two graphs would be a claim the compiler
//! never makes: a Cargo library target and a Go module are separate
//! compilations, and a route that stepped from one into the other would state a
//! relation neither language states.
//!
//! Both endpoints may appear in several graphs, so the query evaluates every
//! ordered instance pair inside every graph that holds both, then selects one:
//! fewest edges, then project key, then source node, then target node. Those
//! four are already a total order over the candidates — `ordered_pairs` yields
//! each ordered pair once per slice and the analysis states one route per pair,
//! so no two candidates share all four — and every one of them is a value the
//! graph already states, so the same repository selects the same route however
//! its authorities were walked.
//!
//! There is no depth. A route is as long as the topology makes it, so the walk
//! is bounded by the host's admitted node and selected-edge ceilings alone.

use std::sync::Arc;

use pedant_graph::{GraphNodeId, GraphPath};
use serde::{Deserialize, Serialize};

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceState, ProjectHandle, ProjectId, ProjectKey,
    ProjectSlice, SliceAnalysis, StructureHandle, StructureInstance,
};

use super::super::response::NavigationResponse;
use super::entity::Projector;
use super::path_record::{PathAnswer, RoutedPath};
use super::refusal::{joined, opened, refusing};
use super::relations::edges;
use super::seed::seeded;
use super::selection::EdgeSelection;

/// Which route one path query asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathQuery {
    /// The declaration the route starts at.
    pub from: StructureHandle,
    /// The declaration the route ends at.
    pub to: StructureHandle,
    /// The one project graph to search, or every graph holding both endpoints.
    #[serde(default)]
    pub project: Option<ProjectHandle>,
    /// Which edges the route may step over.
    pub edges: EdgeSelection,
}

/// What one candidate route is selected by.
///
/// The whole tie break, in one value, so the comparison is a single `min` over
/// a total order rather than a chain of comparisons a later reader has to
/// re-derive. The project key is borrowed whole rather than spelled out here:
/// the order is the key's own, so a key that grows a field cannot leave this
/// comparison behind.
///
/// Four keys and no fifth. The slice, the source, and the target already
/// separate every candidate — one route per ordered pair, each ordered pair
/// yielded once — so a further key over the route's own steps would be
/// positions no comparison can reach.
type RouteOrder<'index> = (usize, &'index ProjectKey, u32, u32);

/// One candidate route: what selects it, where it runs, and the stops it makes.
///
/// The route travels as the graph's own value rather than as a rendered answer,
/// because every candidate but one is discarded and a rendered answer costs one
/// describe per stop to build.
type Candidate<'index> = (RouteOrder<'index>, &'index ProjectSlice, Arc<GraphPath>);

/// Answer `find_path`.
pub(crate) fn path_selected(
    state: &CodeIntelligenceState,
    query: &PathQuery,
) -> Result<NavigationResponse<PathAnswer>, CodeIntelligenceError> {
    let selection = query.edges.admitted()?;
    let index = state.index();
    let source = seeded(index, query.from, query.project)?;
    let target = seeded(index, query.to, query.project)?;
    let endpoints = (&*source, &*target);
    let limits = index.limits().graph_analysis;

    // One analysis per slice, not one per pair: opening it rebuilds the selected
    // indexes of a whole graph, and a slice holding N sources and M targets asks
    // the same graph N times M questions. It is opened only for a slice that
    // holds both ends of some pair, so a graph over this host's ceilings that
    // holds neither endpoint still refuses nothing.
    let mut best: Option<Candidate<'_>> = None;
    for (project, from, to) in shared_runs(endpoints) {
        let slice = joined(index, project)?;
        let analysis = opened(slice, selection, limits)?;
        for pair in ordered_pairs(from, to) {
            best = shortest(best, routed(&analysis, slice, pair)?);
        }
    }

    let mut projector = Projector::new(index);
    let selected = best
        .map(|(_, slice, path)| projected(&mut projector, slice, &path))
        .transpose()?;
    Ok(NavigationResponse::whole(
        state,
        PathAnswer::stated(selected),
    ))
}

/// Every project both endpoints state an instance in, beside the instances each
/// of them states there.
///
/// A walk over the source's own runs rather than over the index. Both instance
/// lists arrive in project then node order, so one project's instances are a
/// contiguous run in each — the source is cut into its runs in one pass, and the
/// target's matching run is bounded by two binary searches. Asking every slice
/// in the index instead filtered both whole lists once per slice, `P × (S + T)`
/// for pairs that live in at most `min(S, T)` slices.
fn shared_runs<'ends>(
    endpoints: (&'ends [StructureInstance], &'ends [StructureInstance]),
) -> impl Iterator<
    Item = (
        ProjectId,
        &'ends [StructureInstance],
        &'ends [StructureInstance],
    ),
> {
    let (source, target) = endpoints;
    source
        .chunk_by(|held, next| held.project() == next.project())
        .filter_map(move |from| {
            let project = from.first()?.project();
            let to = instances_in(target, project);
            (!to.is_empty()).then_some((project, from, to))
        })
}

/// The run of instances one project states, empty where it states none.
///
/// Two binary searches rather than a scan: the list is in project then node
/// order, so one project's instances are contiguous. Both bounds are positions
/// this same list stated, and the first predicate implies the second, so the
/// range they name is always one the list holds.
fn instances_in(instances: &[StructureInstance], project: ProjectId) -> &[StructureInstance] {
    let start = instances.partition_point(|instance| instance.project() < project);
    let end = instances.partition_point(|instance| instance.project() <= project);
    &instances[start..end]
}

/// Every ordered pair one project's two endpoint runs state.
///
/// Yielded rather than collected: every pair but the selected one is compared
/// and dropped, so a list of them would be an allocation per project holding
/// both ends.
fn ordered_pairs<'ends>(
    from: &'ends [StructureInstance],
    to: &'ends [StructureInstance],
) -> impl Iterator<Item = (GraphNodeId, GraphNodeId)> {
    from.iter()
        .flat_map(move |source| to.iter().map(move |target| (source.node(), target.node())))
}

/// The route one ordered pair states, if the graph states one.
fn routed<'index>(
    analysis: &SliceAnalysis<'_>,
    slice: &'index ProjectSlice,
    pair: (GraphNodeId, GraphNodeId),
) -> Result<Option<Candidate<'index>>, CodeIntelligenceError> {
    let Some(path) = analysis
        .path(pair.0, pair.1)
        .map_err(refusing(slice, analysis.limits()))?
    else {
        return Ok(None);
    };
    let order = (
        path.edges().len(),
        slice.key(),
        pair.0.index(),
        pair.1.index(),
    );
    Ok(Some((order, slice, path)))
}

/// What the one selected route states, projected once.
///
/// The slice's own graph answers here rather than the analysis that selected the
/// route: the route is chosen before anything is rendered, and the graph outlives
/// every analysis opened over it.
fn projected(
    projector: &mut Projector<'_>,
    slice: &ProjectSlice,
    path: &GraphPath,
) -> Result<RoutedPath, CodeIntelligenceError> {
    Ok(RoutedPath::stated(
        projector.handle(slice),
        projector.entities(slice, path.nodes())?,
        edges(slice.graph(), path.edges(), slice.key().authority())?,
    ))
}

/// The better of one held candidate and one newly found route.
fn shortest<'index>(
    held: Option<Candidate<'index>>,
    found: Option<Candidate<'index>>,
) -> Option<Candidate<'index>> {
    match (held, found) {
        (None, other) | (other, None) => other,
        (Some(left), Some(right)) if right.0 < left.0 => Some(right),
        (Some(left), Some(_)) => Some(left),
    }
}
