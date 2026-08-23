//! Every Rust-specific join a projection consumes, checked before a graph
//! exists.
//!
//! What the neutral family beside it proves is the shape of a plan: that a
//! stated slot names a record, that a join names a node, that a source was
//! placed. What is proved here is the pairing this adapter was handed — the
//! snapshot, the resolution, the bindings between them, and the snapshot bytes
//! a retained projection is keyed against.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, and every one is taken before a record is
//! sealed.

use pedant_core::resolution::rust::{
    RustResolutionSnapshot, RustSnapshotUnitId, RustTargetResolution, RustUnitBinding,
};
use pedant_types::ResolutionUnit;

use crate::error::GraphBuildError;
use crate::projection::validation as neutral;

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
/// manifest and target identity alone still produces another snapshot. Which
/// two fingerprints answer for a Rust pairing is stated here; the comparison
/// and the refusal it earns belong to the neutral owner every adapter shares.
pub(crate) fn check_snapshot_identity(
    snapshot: &RustResolutionSnapshot,
    resolution: &RustTargetResolution,
) -> Result<(), GraphBuildError> {
    neutral::matching_fingerprint(snapshot.fingerprint(), resolution.snapshot_fingerprint())
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
