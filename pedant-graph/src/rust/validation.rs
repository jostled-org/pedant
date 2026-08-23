//! Every Rust-specific join a projection consumes, checked before a graph
//! exists.
//!
//! What the neutral family beside it proves is the shape of a plan: that a
//! stated slot names a record, that a join names a node, that a source was
//! placed. What is proved here is the pairing this adapter was handed — the
//! snapshot, the resolution, the bindings between them, and the two report
//! vocabularies a Rust projection has a node and a record for.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, and every one is taken before a record is
//! sealed.

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustResolutionUnit, RustSnapshotEdge, RustSnapshotUnitId,
    RustTargetResolution, RustUnitBinding,
};
use pedant_types::{ResolutionUnit, SymbolDefinition, SymbolReference};

use crate::error::GraphBuildError;
use crate::node::GraphNodeKind;
use crate::reference::GraphReferenceKind;

use super::mapping::{self, Vocabulary};

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

/// The node kind one report definition takes in a Rust projection.
///
/// The refusal names the report-local definition whose kind this projection has
/// no node for. `RustTargetResolution` proves the Rust subset before it
/// publishes a report, so this answers only for a report that reached the
/// projection without that proof.
pub(crate) fn definition_kind(
    vocabulary: &Vocabulary,
    definition: &SymbolDefinition,
) -> Result<GraphNodeKind, GraphBuildError> {
    vocabulary
        .definition(definition.kind())
        .ok_or(GraphBuildError::UnnamedDefinitionKind {
            definition: definition.id().index(),
        })
}

/// What one report reference denotes in a Rust projection.
pub(crate) fn reference_kind(
    reference: &SymbolReference,
) -> Result<GraphReferenceKind, GraphBuildError> {
    mapping::reference_kind(reference.kind()).ok_or(GraphBuildError::UnnamedReferenceKind {
        reference: reference.id().index(),
    })
}
