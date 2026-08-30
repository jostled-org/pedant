//! How a graph query reaches one slice's analysis, and why one states no
//! answer, in this product's own vocabulary.
//!
//! `pedant-graph` refuses in its own terms, and every one of those refusals is
//! a ceiling this index configured. Mapping them here means an operator reading
//! a refusal sees the owner, the collection, the count, and the number to
//! raise — the same four facts every other capacity refusal in this crate
//! carries — rather than one wording for graph limits and another for
//! everything else.
//!
//! The open lives here with the mapping because every open owes one, and so
//! does every question asked of what it opened. Five call sites each spelled
//! that mapper for themselves, and three of them threaded the ceilings through
//! a whole call chain for no other purpose.

use pedant_graph::{GraphAnalysisError, GraphAnalysisLimits, GraphEdgeSelection};

use crate::index::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, CodeIntelligenceIndex, ProjectId,
    ProjectSlice, SliceAnalysis, StructureCoverage, capacity,
};

/// One slice's graph, open under `selection` and `limits`.
///
/// The one route to an analysis in this module family. A slice carries the
/// authority every refusal names and the ceilings it was admitted under, so a
/// call site that opened the analysis itself had to carry both alongside it and
/// spell the same mapper again.
///
/// # Errors
///
/// Whatever the graph crate refuses the open with, in this product's terms.
pub(super) fn opened<'slice>(
    slice: &'slice ProjectSlice,
    selection: GraphEdgeSelection,
    limits: GraphAnalysisLimits,
) -> Result<SliceAnalysis<'slice>, CodeIntelligenceError> {
    slice
        .analyzed(selection, limits)
        .map_err(refusing(slice, limits))
}

/// How one slice states a refusal from an analysis already open over it.
///
/// The ceilings travel with the analysis rather than with the caller:
/// [`SliceAnalysis::limits`] is what the graph was admitted under, so a question
/// asked of it refuses against those and not against whatever a call site
/// happened to still hold.
pub(super) fn refusing(
    slice: &ProjectSlice,
    limits: GraphAnalysisLimits,
) -> impl Fn(GraphAnalysisError) -> CodeIntelligenceError {
    move |error| refused(error, limits, slice.key().authority())
}

/// The slice one retained instance's project position names.
///
/// # Errors
///
/// That this revision holds no slice there. An internal join failure, not a
/// caller's stale handle: a query's own project is proved before any instance is
/// read, and every position reaching here was minted by the build that retained
/// the instance. Refused as the graph invariant it is, so a caller cannot read
/// it as the [`CodeIntelligenceError::UnknownProject`] a named-but-absent
/// project states.
pub(super) fn joined(
    index: &CodeIntelligenceIndex,
    project: ProjectId,
) -> Result<&ProjectSlice, CodeIntelligenceError> {
    index
        .projects()
        .get(project.position() as usize)
        .ok_or_else(|| CodeIntelligenceError::Graph {
            authority: format!("project position {}", project.position()).into_boxed_str(),
            reason: Box::from(
                "a retained structure instance names a project position this revision holds no \
                 slice at",
            ),
        })
}

/// One graph refusal, as this product states it.
fn refused(
    error: GraphAnalysisError,
    limits: GraphAnalysisLimits,
    authority: &str,
) -> CodeIntelligenceError {
    match error {
        GraphAnalysisError::NodeLimitExceeded { count, limit } => graph_capacity(
            CapacityCollection::GraphNode,
            u64::from(count),
            u64::from(limit),
        ),
        GraphAnalysisError::SelectedEdgeLimitExceeded { count, limit } => graph_capacity(
            CapacityCollection::GraphEdge,
            u64::from(count),
            u64::from(limit),
        ),
        GraphAnalysisError::DepthLimitExceeded { requested, limit } => graph_capacity(
            CapacityCollection::TraversalDepth,
            u64::from(requested),
            u64::from(limit),
        ),
        GraphAnalysisError::BetweennessWorkLimitExceeded { required, limit } => {
            graph_capacity(CapacityCollection::BetweennessWork, required, limit)
        }
        // The bound overflowed its own counter, so the work it would have cost
        // has no number: the ceiling is what the operator can act on, and the
        // observed side states the widest count the counter can hold.
        GraphAnalysisError::BetweennessWorkOverflow => graph_capacity(
            CapacityCollection::BetweennessWork,
            u64::MAX,
            limits.max_betweenness_work(),
        ),
        GraphAnalysisError::UnknownNode { node } => CodeIntelligenceError::UnavailableCoverage {
            coverage: StructureCoverage::Unavailable,
            reason: format!(
                "the graph for {authority} holds no node at position {}",
                node.index()
            )
            .into_boxed_str(),
        },
        GraphAnalysisError::ConsumedGraphInvariant { node } => CodeIntelligenceError::Graph {
            authority: Box::from(authority),
            reason: format!("node {} is owned by no container", node.index()).into_boxed_str(),
        },
    }
}

/// One graph-analysis ceiling refusal.
fn graph_capacity(
    collection: CapacityCollection,
    observed: u64,
    limit: u64,
) -> CodeIntelligenceError {
    capacity(CapacityOwner::GraphAnalysis, collection, observed, limit)
}
