//! Every neutral join a projection consumes, checked before a graph exists.
//!
//! An adapter's own validator makes most of these unreachable in ordinary use.
//! They are still checked here, because a graph that silently dropped a join
//! would be indistinguishable from a repository that has none. Each function
//! owns exactly one refusal, every refusal the neutral projection can take is
//! built here, and every one is taken before a record is sealed. An adapter's
//! planner proves each join against its current report; the assembler proves the
//! same join again against the identities it has actually minted.
//!
//! What an adapter's own vocabulary earns is refused by the adapter beside it.
//! Nothing in this module reads a language.

use std::sync::Arc;

use pedant_types::{ResolutionRecord, ResolutionReport, SymbolDefinition, SymbolReference};

use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, index_of, position};
use crate::node::GraphNodeKind;
use crate::reference::GraphReferenceKind;

use super::draft::{
    DefinitionProjection, FragmentSlot, ProjectionPlan, ReferenceProjection, UnitPlan,
};
use super::placement::{DefinitionIdentity, DefinitionTable, SourceIdentity, SourceSet};
use super::state::{ProjectionState, SourceScope};

/// The snapshot instance one report unit's binding names.
///
/// A binding the snapshot holds no instance for is dangling rather than
/// missing: the resolution states a build unit, and the supplied snapshot does
/// not have it. Neutral because the refusal is — an adapter states which of its
/// own identities was looked up, and what a graph cannot do with the answer is
/// the same in every language.
pub(crate) fn bound_instance<Instance>(
    held: Option<Instance>,
    unit: u32,
) -> Result<Instance, GraphBuildError> {
    held.ok_or(GraphBuildError::DanglingUnitBinding { unit })
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

/// The identity of the definition one stated join names, when it names one.
///
/// A join an adapter did not state is not a join it may invent, and a join it
/// did state names a definition the current report's own table must answer for.
pub(crate) fn optional_identity(
    table: &DefinitionTable,
    stated: Option<u32>,
) -> Result<Option<Arc<DefinitionIdentity>>, GraphBuildError> {
    match stated {
        None => Ok(None),
        Some(at) => Ok(Some(Arc::clone(definition_identity(table, at)?))),
    }
}

/// The node kind one report definition takes, under the vocabulary its own
/// adapter named for it.
///
/// The shared report vocabulary carries every language's kinds, and each
/// adapter names the subset it has a node for. What is neutral is the refusal: a
/// kind no adapter named must stop the build rather than reach the graph under
/// a fallback category, and one owner states that for all of them.
pub(crate) fn stated_definition_kind(
    named: Option<GraphNodeKind>,
    definition: &SymbolDefinition,
) -> Result<GraphNodeKind, GraphBuildError> {
    named.ok_or(GraphBuildError::UnnamedDefinitionKind {
        definition: definition.id().index(),
    })
}

/// What one report reference denotes, under the vocabulary its own adapter
/// named for it.
pub(crate) fn stated_reference_kind(
    named: Option<GraphReferenceKind>,
    reference: &SymbolReference,
) -> Result<GraphReferenceKind, GraphBuildError> {
    named.ok_or(GraphBuildError::UnnamedReferenceKind {
        reference: reference.id().index(),
    })
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

/// The report-order slot one stated definition position names.
///
/// A unit named by one of its own declarations states that declaration by its
/// report position. A position the plan holds no slot for names no definition
/// at all, so the unit would be rooted at nothing.
pub(crate) fn stated_definition(
    plan: &ProjectionPlan,
    definition: u32,
) -> Result<FragmentSlot, GraphBuildError> {
    plan.definitions
        .get(index_of(definition))
        .copied()
        .ok_or(GraphBuildError::MissingDefinitionNode { definition })
}

/// The container slot one planned unit's position owns.
///
/// The table is sized from the plan's own unit count, so a position outside it
/// is a container bound for a unit this plan never stated.
pub(crate) fn unit_slot(
    held: Option<&mut Option<GraphNodeId>>,
    unit: u32,
) -> Result<&mut Option<GraphNodeId>, GraphBuildError> {
    held.ok_or(GraphBuildError::MissingUnitBinding { unit })
}

/// One planned unit takes one container node.
pub(crate) fn unbound_container(
    held: Option<GraphNodeId>,
    unit: u32,
) -> Result<(), GraphBuildError> {
    match held {
        None => Ok(()),
        Some(held) => Err(GraphBuildError::RepeatedUnitContainer {
            unit,
            container: held.index(),
        }),
    }
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
