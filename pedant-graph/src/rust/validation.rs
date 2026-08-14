//! Every join a Rust projection consumes, checked before a graph exists.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, every refusal a Rust projection can take
//! is built here, and every one is taken before a record is sealed. The planner
//! proves each join against the current report; the assembler proves the same
//! join again against the identities it has actually minted.

use std::sync::Arc;

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustResolutionUnit, RustSnapshotEdge, RustSnapshotUnitId,
    RustTargetResolution, RustUnitBinding,
};
use pedant_types::{ResolutionRecord, ResolutionReport, ResolutionUnit, SymbolReference};

use crate::containment::ContainmentEdge;
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, index_of, position};

use super::fragment::{
    DefinitionProjection, FragmentSlot, ProjectionPlan, ReferenceProjection, SourceSet, UnitPlan,
};
use super::identity::{DefinitionIdentity, DefinitionTable, SourceIdentity};
use super::index::{ProjectionState, SourceScope};

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

/// The build unit one report unit's binding names.
///
/// A binding the snapshot holds no unit for is dangling rather than missing:
/// the resolution states a build unit, and the supplied snapshot does not have
/// it.
pub(crate) fn snapshot_instance(
    snapshot: &RustResolutionSnapshot,
    unit: (RustSnapshotUnitId, u32),
) -> Result<&RustResolutionUnit, GraphBuildError> {
    let (snapshot_unit, reported) = unit;
    snapshot
        .unit(snapshot_unit)
        .ok_or(GraphBuildError::DanglingUnitBinding { unit: reported })
}

/// One build unit is bound by one report unit.
///
/// A second report unit naming it would give every source that unit
/// instantiates two owners, so the collision is refused where it is made rather
/// than left to the containment check, which would name a doubled node instead
/// of the doubled binding.
pub(crate) fn distinct_binding(held: Option<u32>, unit: u32) -> Result<(), GraphBuildError> {
    match held {
        None => Ok(()),
        Some(held) => Err(GraphBuildError::SharedUnitBinding { held, unit }),
    }
}

/// One unit instantiates one normalized path once.
///
/// A repeat would mint a second file node while the placement kept only the
/// last of them, leaving the first childless and moving every dense identity
/// after it. It is refused where the unit's sources are read, rather than left
/// to produce a graph nothing tells apart from a correct one.
pub(crate) fn distinct_source(
    held: Option<u32>,
    unit: u32,
    path: &str,
) -> Result<(), GraphBuildError> {
    match held {
        None => Ok(()),
        Some(_) => Err(GraphBuildError::RepeatedUnitSource {
            unit,
            path: Box::from(path),
        }),
    }
}

/// The plan one report-local unit position names.
pub(crate) fn planned_unit(units: &[UnitPlan], unit: u32) -> Result<&UnitPlan, GraphBuildError> {
    units
        .get(index_of(unit))
        .ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// The digest of the bytes one unit's source was snapshotted from.
///
/// A source a fragment answers for is a source the snapshot read, so a path it
/// holds nothing for is a plan that reached beyond the snapshot it was made
/// from rather than a repository missing a file.
pub(crate) fn source_digest(
    snapshot: &RustResolutionSnapshot,
    unit: u32,
    path: &str,
) -> Result<[u8; 32], GraphBuildError> {
    snapshot
        .source(path)
        .map(|source| *source.digest())
        .ok_or_else(|| GraphBuildError::MissingSourceNode {
            unit,
            path: Box::from(path),
        })
}

/// The fragment one unit reads one stated path through, beside the
/// unit-qualified identity that fragment answers for.
///
/// A site naming a source only another unit instantiates is refused here, so
/// the fragment a record is placed in and the refusal that record would take
/// are one decision. The identity is the one the placement already stated, so a
/// caller joins through it rather than building a second one of its own.
pub(crate) fn instantiated_source<'a>(
    sources: &'a SourceSet,
    unit: u32,
    path: &str,
) -> Result<(u32, &'a SourceIdentity), GraphBuildError> {
    sources
        .locate(unit, path)
        .ok_or_else(|| GraphBuildError::MissingSourceNode {
            unit,
            path: Box::from(path),
        })
}

/// The identity one report definition takes in the current report.
///
/// The shared handle is answered rather than the identity itself, so every join
/// this report states holds the one identity the table minted.
pub(crate) fn definition_identity(
    table: &DefinitionTable,
    definition: u32,
) -> Result<&Arc<DefinitionIdentity>, GraphBuildError> {
    table
        .identity(definition)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// The fragment one report definition was placed in.
pub(crate) fn definition_fragment(
    table: &DefinitionTable,
    definition: u32,
) -> Result<u32, GraphBuildError> {
    table
        .fragment(definition)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// The slot one placed record took in the fragment its site names.
pub(crate) fn placed_slot(
    slot: Option<FragmentSlot>,
    unit: u32,
    path: &str,
) -> Result<FragmentSlot, GraphBuildError> {
    slot.ok_or_else(|| GraphBuildError::MissingSourceNode {
        unit,
        path: Box::from(path),
    })
}

/// The unit position one snapshot dependency endpoint resolves to.
///
/// The refusal names the edge rather than the unit, because a snapshot unit
/// identity is opaque outside the snapshot that issued it and the report's own
/// unit order is a different order.
pub(crate) fn dependency_unit(
    bound: Option<u32>,
    stated: (u32, &RustSnapshotEdge),
) -> Result<u32, GraphBuildError> {
    let (edge, declaration) = stated;
    bound.ok_or_else(|| GraphBuildError::MissingDependencyUnit {
        edge,
        alias: Box::from(declaration.name()),
    })
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

/// The definition one report-order slot of a plan states.
///
/// The refusal names the report position whose stated projection is missing.
/// The planner placed every definition it identified, so this answers only for
/// a plan that lost one between the two owners.
pub(crate) fn planned_definition(
    plan: &ProjectionPlan,
    at: FragmentSlot,
    definition: u32,
) -> Result<&DefinitionProjection, GraphBuildError> {
    plan.definition(at)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// The reference one report-order slot of a plan states.
pub(crate) fn planned_reference(
    plan: &ProjectionPlan,
    at: FragmentSlot,
    reference: u32,
) -> Result<&ReferenceProjection, GraphBuildError> {
    plan.reference(at)
        .ok_or(GraphBuildError::MissingReferenceRecord { reference })
}

/// The source one fragment of a plan answers for.
pub(crate) fn fragment_source(
    plan: &ProjectionPlan,
    fragment: u32,
    definition: u32,
) -> Result<&SourceIdentity, GraphBuildError> {
    plan.source(fragment)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// The unit one fragment of a plan was placed under.
///
/// The refusal names the fragment as the unit it answers for, because a plan
/// that lost a fragment lost the unit-and-source scope every record in it was
/// placed under.
pub(crate) fn fragment_unit(plan: &ProjectionPlan, fragment: u32) -> Result<u32, GraphBuildError> {
    plan.placed(fragment)
        .map(|placed| placed.unit)
        .ok_or(GraphBuildError::MissingUnitBinding { unit: fragment })
}

/// The file-node scope one planned unit's sources are bound in.
///
/// The scope table is indexed by the unit's own position, so a position outside
/// it is a unit this assembly bound no container for. Dropping the binding
/// instead would lose the file node in silence and surface later as a missing
/// source node naming a source this assembly did in fact mint.
pub(crate) fn unit_scope(
    held: Option<&mut SourceScope>,
    unit: u32,
) -> Result<&mut SourceScope, GraphBuildError> {
    held.ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// The container node one planned unit owns.
pub(crate) fn unit_container(
    state: &ProjectionState,
    unit: u32,
) -> Result<GraphNodeId, GraphBuildError> {
    state
        .container(unit)
        .ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// The unit-qualified file node one stated site sits in.
pub(crate) fn source_node(
    state: &ProjectionState,
    unit: u32,
    path: &str,
) -> Result<GraphNodeId, GraphBuildError> {
    state
        .file(unit, path)
        .ok_or_else(|| GraphBuildError::MissingSourceNode {
            unit,
            path: Box::from(path),
        })
}

/// The node one stable definition identity was minted as.
///
/// The refusal names the report position of the record whose stated join this
/// graph holds no node for. Every identity reaching here came from the current
/// report's own definition table, and the assembler mints a node for each of
/// those before any join is resolved.
pub(crate) fn definition_node(
    state: &ProjectionState,
    identity: &DefinitionIdentity,
    stated: u32,
) -> Result<GraphNodeId, GraphBuildError> {
    state
        .definition(identity)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition: stated })
}

/// Containment must be one forest whose roots are exactly the unit containers.
///
/// Four rules over the stated edges: every edge names nodes this graph holds,
/// no node is contained twice, every node below the unit containers is
/// contained once, and no chain returns to itself. The unit containers are the
/// first `units` nodes the assembly minted, so a node is a root exactly when
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
