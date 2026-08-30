//! The derived answers one project graph states.
//!
//! Every number here is `pedant-graph`'s. This module states which graph, which
//! selection, and which ceilings, then says what each measured node is in terms
//! of the declarations this index retained. It computes no centrality, finds no
//! component, and defines no second oracle: an answer that disagreed with the
//! graph crate's own would be a second implementation nobody asked for.

use pedant_graph::{
    BetweennessCentrality, BoundaryCrossingComponent, DegreeCentrality, GraphComponents,
    GraphNodeId, MisplacementCandidate, ModuleCohesion,
};
use serde::Serialize;

use crate::index::{CodeIntelligenceError, CodeIntelligenceState, ProjectSlice, SliceAnalysis};

use super::super::response::NavigationResponse;
use super::analysis_request::{AnalysisMode, AnalysisQuery};
use super::betweenness::BetweennessRecord;
use super::component::{ComponentRecord, CondensationAnswer, CondensationEdgeRecord};
use super::degree::DegreeRecord;
use super::divergence::{BoundaryRecord, CohesionRecord, DivergenceAnswer, MisplacementRecord};
use super::entity::{NavigationEntity, Projector};
use super::refusal::{opened, refusing};

/// What one analysis query answered.
///
/// Adjacently tagged rather than internally: three of the five answers are a
/// list of records, and an internally tagged enum cannot carry a sequence — the
/// tag would have nowhere to live. So the mode and the answer are two fields,
/// which is also the one shape all five variants can share.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "mode", content = "answer", rename_all = "snake_case")]
pub enum AnalysisAnswer {
    /// Selected edges at each end of each entity.
    DegreeCentrality(Box<[DegreeRecord]>),
    /// Shortest-path traffic through each entity.
    BetweennessCentrality(Box<[BetweennessRecord]>),
    /// The strongly connected components of the selected topology.
    Components(Box<[ComponentRecord]>),
    /// The acyclic view over those components.
    Condensation(Box<CondensationAnswer>),
    /// Where the declared module tree and the topology disagree.
    ModuleDivergence(Box<DivergenceAnswer>),
}

/// Answer `analyze_graph`.
pub(crate) fn graph_analyzed(
    state: &CodeIntelligenceState,
    query: &AnalysisQuery,
) -> Result<NavigationResponse<AnalysisAnswer>, CodeIntelligenceError> {
    let selection = query.edges.admitted()?;
    let index = state.index();
    let limits = query.limits.lowered(index.limits().graph_analysis)?;
    let slice = index.project(query.project)?;
    let analysis = opened(slice, selection, limits)?;
    let mut projector = Projector::new(index);
    let answer = answered(&analysis, (&mut projector, slice), query.mode)?;
    Ok(NavigationResponse::whole(state, answer))
}

/// The answer one mode states, projected.
///
/// One arm per mode and no projection spelled inside any of them: each mode
/// names the function that states its own answer, so the arms stay a table of
/// what the five modes are rather than a place a sixth could be answered
/// differently from the five beside it.
fn answered(
    analysis: &SliceAnalysis<'_>,
    held: (&mut Projector<'_>, &ProjectSlice),
    mode: AnalysisMode,
) -> Result<AnalysisAnswer, CodeIntelligenceError> {
    match mode {
        AnalysisMode::DegreeCentrality => {
            degrees(analysis, held).map(AnalysisAnswer::DegreeCentrality)
        }
        AnalysisMode::BetweennessCentrality => {
            betweenness(analysis, held).map(AnalysisAnswer::BetweennessCentrality)
        }
        AnalysisMode::Components => components(&analysis.strongly_connected_components(), held)
            .map(AnalysisAnswer::Components),
        AnalysisMode::Condensation => condensed(analysis, held)
            .map(Box::new)
            .map(AnalysisAnswer::Condensation),
        AnalysisMode::ModuleDivergence => diverged(analysis, held)
            .map(Box::new)
            .map(AnalysisAnswer::ModuleDivergence),
    }
}

/// One record per measured node, each stating what the node it measured is.
///
/// Every row-shaped answer here has the one shape — a measurement the graph
/// crate states, the node it measured, and what this index calls that node — so
/// the lookup, the refusal, and the collect are written once rather than once
/// per answer. A second spelling of this walk is a second place for one measured
/// node to be dropped from a list that claims to hold every one of them.
fn measured<T: Copy, R>(
    held: (&mut Projector<'_>, &ProjectSlice),
    rows: &[T],
    node: impl Fn(T) -> GraphNodeId,
    stated: impl Fn(T, NavigationEntity) -> R,
) -> Result<Box<[R]>, CodeIntelligenceError> {
    let (projector, slice) = held;
    rows.iter()
        .copied()
        .map(|row| {
            projector
                .entity(slice, node(row))
                .map(|entity| stated(row, entity))
        })
        .collect()
}

/// Selected edges at each end of each measured entity.
fn degrees(
    analysis: &SliceAnalysis<'_>,
    held: (&mut Projector<'_>, &ProjectSlice),
) -> Result<Box<[DegreeRecord]>, CodeIntelligenceError> {
    let scored = analysis.degree_centrality();
    measured(held, &scored[..], DegreeCentrality::node, |row, entity| {
        DegreeRecord::stated(entity, row.incoming(), row.outgoing())
    })
}

/// Shortest-path traffic through each measured entity.
///
/// The one mode that refuses. The work bound is proved against the ceilings the
/// analysis was admitted under rather than whatever this call site still holds,
/// so a lowered ceiling refuses in the same terms the open would have.
fn betweenness(
    analysis: &SliceAnalysis<'_>,
    held: (&mut Projector<'_>, &ProjectSlice),
) -> Result<Box<[BetweennessRecord]>, CodeIntelligenceError> {
    let (projector, slice) = held;
    let scored = analysis
        .betweenness_centrality()
        .map_err(refusing(slice, analysis.limits()))?;
    measured(
        (projector, slice),
        &scored[..],
        BetweennessCentrality::node,
        |row, entity| BetweennessRecord::stated(entity, row.raw(), row.normalized()),
    )
}

/// Every component, with its members projected.
fn components(
    held: &GraphComponents,
    stated: (&mut Projector<'_>, &ProjectSlice),
) -> Result<Box<[ComponentRecord]>, CodeIntelligenceError> {
    let (projector, slice) = stated;
    held.components()
        .iter()
        .map(|component| {
            projector
                .entities(slice, component.members())
                .map(|members| {
                    ComponentRecord::stated(component.id(), members, component.is_cyclic())
                })
        })
        .collect()
}

/// The condensation, with every component projected.
fn condensed(
    analysis: &SliceAnalysis<'_>,
    stated: (&mut Projector<'_>, &ProjectSlice),
) -> Result<CondensationAnswer, CodeIntelligenceError> {
    let condensation = analysis.condensation();
    let (projector, slice) = stated;
    Ok(CondensationAnswer::stated(
        components(condensation.components(), (projector, slice))?,
        condensation
            .edges()
            .iter()
            .map(|edge| {
                CondensationEdgeRecord::stated(
                    edge.source(),
                    edge.target(),
                    Box::from(edge.edges()),
                )
            })
            .collect(),
        Box::from(condensation.topological_order()),
    ))
}

/// The divergence evidence, with every measured node projected.
///
/// The three lists are projected from one `GraphDivergence`, so the answer
/// states three readings of one measurement rather than three that could have
/// been taken over different partitions.
fn diverged(
    analysis: &SliceAnalysis<'_>,
    stated: (&mut Projector<'_>, &ProjectSlice),
) -> Result<DivergenceAnswer, CodeIntelligenceError> {
    let evidence = analysis.divergence();
    let (projector, slice) = stated;
    let modules = cohesion((&mut *projector, slice), evidence.cohesion())?;
    let misplaced = candidates((&mut *projector, slice), evidence.candidates())?;
    let crossings = boundaries((projector, slice), evidence.boundary_components())?;
    Ok(DivergenceAnswer::stated(
        modules,
        evidence.modularity(),
        misplaced,
        crossings,
    ))
}

/// Every declared module and how much of its traffic stays inside it.
fn cohesion(
    stated: (&mut Projector<'_>, &ProjectSlice),
    held: &[ModuleCohesion],
) -> Result<Box<[CohesionRecord]>, CodeIntelligenceError> {
    measured(stated, held, ModuleCohesion::root, |row, root| {
        CohesionRecord::stated(
            root,
            (row.internal_edges(), row.boundary_edges()),
            row.score(),
        )
    })
}

/// Every symbol whose selected edges prefer another partition.
///
/// The one row that names three nodes, so it states its own walk rather than the
/// one-node projection every other measured list goes through.
fn candidates(
    stated: (&mut Projector<'_>, &ProjectSlice),
    held: &[MisplacementCandidate],
) -> Result<Box<[MisplacementRecord]>, CodeIntelligenceError> {
    let (projector, slice) = stated;
    held.iter()
        .map(|candidate| {
            let symbol = projector.entity(slice, candidate.symbol())?;
            let declared = projector.entity(slice, candidate.declared_partition())?;
            let proposed = projector.entity(slice, candidate.candidate_partition())?;
            Ok(MisplacementRecord::stated(
                (symbol, declared, proposed),
                (candidate.foreign_edges(), candidate.total_outgoing_edges()),
                candidate.affinity(),
            ))
        })
        .collect()
}

/// Every cycle that crosses a declared boundary, with the partitions it crosses
/// projected.
fn boundaries(
    stated: (&mut Projector<'_>, &ProjectSlice),
    held: &[BoundaryCrossingComponent],
) -> Result<Box<[BoundaryRecord]>, CodeIntelligenceError> {
    let (projector, slice) = stated;
    held.iter()
        .map(|crossing| {
            projector
                .entities(slice, crossing.partitions())
                .map(|partitions| BoundaryRecord::stated(crossing.component(), partitions))
        })
        .collect()
}
