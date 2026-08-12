//! Every join a Rust projection consumes, checked before a graph exists.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, every refusal a Rust projection can take
//! is built here, and every one is taken before `CodeGraph` construction. Two
//! functions record what they prove — a unit binding and a qualified source —
//! because in both the record and the refusal are one decision.

use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustResolutionUnit, RustSnapshotEdge, RustSnapshotUnitId,
    RustTargetResolution, RustUnitBinding,
};
use pedant_types::{ResolutionRecord, ResolutionReport, ResolutionUnit, SymbolReference};

use crate::containment::ContainmentEdge;
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, index_of, position};
use crate::node::NodeDraft;

use super::index::ProjectionState;

/// Where one node stands in the containment ancestor walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    /// Not yet reached.
    Pending,
    /// On the chain currently being walked.
    Active,
    /// Proved acyclic by an earlier walk.
    Done,
}

/// Both values must have been requested for the same Cargo target.
pub(crate) fn check_root_target(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
) -> Result<(), GraphBuildError> {
    match snapshot.root_target() == resolution.root_target() {
        true => Ok(()),
        false => Err(GraphBuildError::RootTargetMismatch),
    }
}

/// The supplied snapshot must be the one the resolution was validated against.
///
/// Equal root targets do not prove equal sources: an edit that leaves every
/// manifest and target identity alone still produces another snapshot.
pub(crate) fn check_snapshot_identity(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
) -> Result<(), GraphBuildError> {
    match snapshot.fingerprint() == resolution.snapshot_fingerprint() {
        true => Ok(()),
        false => Err(GraphBuildError::SnapshotFingerprintMismatch),
    }
}

/// The build unit this resolution binds one report unit to.
///
/// The resolution binds every report unit by its stable key, so a unit with no
/// binding at all is a restated resolution rather than a validated one.
pub(crate) fn stated_binding(
    resolution: &RustTargetResolution,
    unit: &ResolutionUnit,
) -> Result<RustSnapshotUnitId, GraphBuildError> {
    resolution
        .unit(unit.id())
        .map(RustUnitBinding::snapshot_unit)
        .ok_or(GraphBuildError::MissingUnitBinding {
            unit: unit.id().index(),
        })
}

/// The snapshot unit one report unit is bound to.
pub(crate) fn bound_snapshot_unit(
    state: &ProjectionState,
    unit: u32,
) -> Result<RustSnapshotUnitId, GraphBuildError> {
    state
        .snapshot_unit(unit)
        .ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// The build unit one report unit's binding names.
///
/// A binding the snapshot holds no unit for is dangling rather than missing:
/// the resolution states a build unit, and the supplied snapshot does not have
/// it. Both passes that need the instance read it through here, so the two
/// refusals cannot drift apart.
pub(crate) fn snapshot_instance(
    snapshot: &RustResolutionSnapshot,
    unit: (RustSnapshotUnitId, u32),
) -> Result<&RustResolutionUnit, GraphBuildError> {
    let (snapshot_unit, reported) = unit;
    snapshot
        .unit(snapshot_unit)
        .ok_or(GraphBuildError::DanglingUnitBinding { unit: reported })
}

/// Bind one report unit to its container and its build unit.
///
/// One build unit is bound by one report unit. A second report unit naming it
/// would give every source that unit instantiates two owners, so the collision
/// is refused where it is made rather than left to the containment check, which
/// would name a doubled node instead of the doubled binding.
pub(crate) fn bind_unit(
    state: &mut ProjectionState,
    container: GraphNodeId,
    unit: (RustSnapshotUnitId, u32),
) -> Result<(), GraphBuildError> {
    let (snapshot_unit, reported) = unit;
    match state.bind_unit(container, (snapshot_unit, reported)) {
        None => Ok(()),
        Some(held) => Err(GraphBuildError::SharedUnitBinding {
            held,
            unit: reported,
        }),
    }
}

/// The container node one report unit owns.
pub(crate) fn unit_container(
    state: &ProjectionState,
    unit: u32,
) -> Result<GraphNodeId, GraphBuildError> {
    state
        .container(unit)
        .ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// The container node one endpoint of one snapshot dependency edge owns.
///
/// The refusal names the edge rather than the unit, because a snapshot unit
/// identity is opaque outside the snapshot that issued it and the report's own
/// unit order is a different order.
pub(crate) fn snapshot_container(
    state: &ProjectionState,
    unit: RustSnapshotUnitId,
    stated: (u32, &RustSnapshotEdge),
) -> Result<GraphNodeId, GraphBuildError> {
    let (edge, declaration) = stated;
    state
        .snapshot_container(unit)
        .ok_or_else(|| GraphBuildError::MissingDependencyUnit {
            edge,
            alias: Box::from(declaration.name()),
        })
}

/// The unit-qualified file node one instantiated source takes, minted the first
/// time the unit-and-path pair is seen.
///
/// The one validator that mints, because the node and the refusal are one
/// decision: a pair whose scope nothing bound must not be answered with a node
/// that no unit reads.
pub(crate) fn qualified_source(
    state: &mut ProjectionState,
    unit: (RustSnapshotUnitId, u32),
    path: &Arc<str>,
    draft: NodeDraft,
) -> Result<GraphNodeId, GraphBuildError> {
    let (snapshot_unit, reported) = unit;
    state
        .qualify_source(snapshot_unit, path, draft)?
        .ok_or(GraphBuildError::MissingUnitBinding { unit: reported })
}

/// Every report reference beside the record that answered it.
///
/// The report validator states one record per reference. A disagreement here
/// would silently drop the tail of the longer slice, so the pairing is proved
/// once and both passes read the proved slice.
pub(crate) fn resolved_references(
    report: &ResolutionReport,
) -> Result<Box<[(&SymbolReference, &ResolutionRecord)]>, GraphBuildError> {
    let references = report.references();
    let records = report.resolutions();
    match references.len() == records.len() {
        true => Ok(references.iter().zip(records).collect()),
        false => Err(GraphBuildError::ReferenceRecordMismatch {
            references: position(references.len()),
            records: position(records.len()),
        }),
    }
}

/// The unit-qualified file node one stated site sits in.
pub(crate) fn source_node(
    state: &ProjectionState,
    unit: (RustSnapshotUnitId, u32),
    path: &str,
) -> Result<GraphNodeId, GraphBuildError> {
    let (snapshot_unit, reported) = unit;
    state
        .file_node(snapshot_unit, path)
        .ok_or_else(|| GraphBuildError::MissingSourceNode {
            unit: reported,
            path: Box::from(path),
        })
}

/// The node one report definition produced.
pub(crate) fn definition_node(
    state: &ProjectionState,
    definition: u32,
) -> Result<GraphNodeId, GraphBuildError> {
    state
        .definition_node(definition)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// Containment must be one forest whose roots are exactly the unit containers.
///
/// Four rules over the stated edges: every edge names nodes this graph holds,
/// no node is contained twice, every node below the unit containers is
/// contained once, and no chain returns to itself. The unit containers are the
/// first `units` nodes the projection minted, so a node is a root exactly when
/// its position is below that count.
pub(crate) fn check_containment_forest(
    state: &ProjectionState,
    units: usize,
) -> Result<(), GraphBuildError> {
    let parents = stated_parents(state)?;
    check_every_node_is_parented(&parents, units)?;
    check_no_unit_root_is_contained(&parents, units)?;
    check_acyclic(&parents)
}

/// One parent slot per node, refusing the second edge that claims a child.
fn stated_parents(state: &ProjectionState) -> Result<Box<[Option<GraphNodeId>]>, GraphBuildError> {
    let mut parents: Vec<Option<GraphNodeId>> = vec![None; state.node_count()];
    for edge in state.containment() {
        let slot = parent_slot(&mut parents, edge)?;
        match slot {
            Some(existing) => {
                return Err(GraphBuildError::MultiplyContained {
                    parent: existing.index(),
                    child: edge.child().index(),
                });
            }
            None => *slot = Some(edge.parent()),
        }
    }
    Ok(parents.into_boxed_slice())
}

/// The slot one containment edge's child owns.
fn parent_slot<'a>(
    parents: &'a mut [Option<GraphNodeId>],
    edge: &ContainmentEdge,
) -> Result<&'a mut Option<GraphNodeId>, GraphBuildError> {
    let child = edge.child();
    parents
        .get_mut(index_of(child.index()))
        .ok_or(GraphBuildError::UnknownContainmentNode {
            node: child.index(),
        })
}

/// Every node below the unit containers states a parent.
fn check_every_node_is_parented(
    parents: &[Option<GraphNodeId>],
    units: usize,
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .enumerate()
        .skip(units)
        .find(|(_, parent)| parent.is_none())
        .map_or(Ok(()), |(index, _)| {
            Err(GraphBuildError::UnparentedNode {
                node: position(index),
            })
        })
}

/// No unit container is contained by anything.
fn check_no_unit_root_is_contained(
    parents: &[Option<GraphNodeId>],
    units: usize,
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .enumerate()
        .take(units)
        .find_map(|(index, parent)| parent.map(|held| (index, held)))
        .map_or(Ok(()), |(index, parent)| {
            Err(GraphBuildError::RootHasParent {
                root: position(index),
                parent: parent.index(),
            })
        })
}

/// No containment chain returns to a node it already visited.
fn check_acyclic(parents: &[Option<GraphNodeId>]) -> Result<(), GraphBuildError> {
    let mut visits = vec![Visit::Pending; parents.len()];
    let mut chain: Vec<usize> = Vec::new();
    for start in 0..parents.len() {
        walk_ancestors(parents, &mut visits, &mut chain, start)?;
    }
    Ok(())
}

fn walk_ancestors(
    parents: &[Option<GraphNodeId>],
    visits: &mut [Visit],
    chain: &mut Vec<usize>,
    start: usize,
) -> Result<(), GraphBuildError> {
    match visit_of(visits, start)? {
        Visit::Pending => (),
        Visit::Active | Visit::Done => return Ok(()),
    }
    chain.clear();
    let mut current = Some(start);
    let mut cycle = None;
    while let Some(index) = current {
        let visit = visit_of(visits, index)?;
        cycle = (visit == Visit::Active).then_some(index);
        match visit {
            Visit::Pending => (),
            Visit::Active | Visit::Done => break,
        }
        mark(visits, index, Visit::Active)?;
        chain.push(index);
        current = parents
            .get(index)
            .and_then(|parent| *parent)
            .map(|parent| index_of(parent.index()));
    }
    for index in chain.drain(..) {
        mark(visits, index, Visit::Done)?;
    }
    match cycle {
        Some(index) => Err(GraphBuildError::ContainmentCycle {
            node: position(index),
        }),
        None => Ok(()),
    }
}

/// Where the walk left one node.
///
/// A position outside the node set is a stated parent this graph holds no node
/// for, which is the one join a walk that answered `Done` would accept in
/// silence.
fn visit_of(visits: &[Visit], index: usize) -> Result<Visit, GraphBuildError> {
    visits
        .get(index)
        .copied()
        .ok_or(GraphBuildError::UnknownContainmentNode {
            node: position(index),
        })
}

/// Record where the walk left one node.
fn mark(visits: &mut [Visit], index: usize, visit: Visit) -> Result<(), GraphBuildError> {
    match visits.get_mut(index) {
        Some(slot) => {
            *slot = visit;
            Ok(())
        }
        None => Err(GraphBuildError::UnknownContainmentNode {
            node: position(index),
        }),
    }
}
