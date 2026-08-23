//! Every Go-specific join a projection consumes, checked before a graph exists.
//!
//! What the neutral family beside it proves is the shape of a plan: that a
//! stated slot names a record, that a join names a node, that a source was
//! placed. What is proved here is the pairing this adapter was handed — the
//! snapshot, the resolution, the bindings between them, the package clause each
//! unit is rooted at, and the holder one method reads its callable level from.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, and every one is taken before a record is
//! sealed.

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionSnapshot, GoUnitBinding};
use pedant_types::{ResolutionReport, ResolutionUnit, SymbolDefinition, SymbolKind};

use crate::error::GraphBuildError;
use crate::id::index_of;
use crate::projection::validation as neutral;

/// The supplied snapshot must be the one the resolution was validated against.
///
/// The main module is the snapshot's first either way, so it proves nothing on
/// its own: an edit that leaves every manifest and package clause alone still
/// produces another snapshot, and only the fingerprint sees it. Which two
/// fingerprints answer for a Go pairing is stated here; the comparison and the
/// refusal it earns belong to the neutral owner every adapter shares.
pub(crate) fn check_snapshot_identity(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
) -> Result<(), GraphBuildError> {
    neutral::matching_fingerprint(snapshot.fingerprint(), resolution.snapshot_fingerprint())
}

/// The package context this resolution binds one report unit to.
///
/// The resolution binds every report unit by its stable key, so a unit with no
/// binding at all is a restated resolution rather than a validated one.
pub(crate) fn stated_binding<'a>(
    resolution: &'a GoProjectResolution,
    unit: &ResolutionUnit,
) -> Result<&'a GoUnitBinding, GraphBuildError> {
    resolution
        .unit(unit.id())
        .ok_or(GraphBuildError::MissingUnitBinding {
            unit: unit.id().index(),
        })
}

/// The report definition whose package clause roots one unit.
pub(crate) fn package_declaration(
    declared: Option<u32>,
    unit: u32,
) -> Result<u32, GraphBuildError> {
    declared.ok_or(GraphBuildError::MissingUnitDeclaration { unit })
}

/// One report unit declares one package.
///
/// A second package definition for one context would give that unit two root
/// containers, so the collision is refused where the declarations are read
/// rather than left to the containment check, which would name a doubled node
/// instead of the doubled declaration.
pub(crate) fn distinct_declaration(held: Option<u32>, unit: u32) -> Result<(), GraphBuildError> {
    match held {
        None => Ok(()),
        Some(_) => Err(GraphBuildError::RepeatedUnitDeclaration { unit }),
    }
}

/// The kind of the definition one stated holder names.
///
/// Read rather than assumed: a method takes a different callable token
/// depending on whether an interface or a receiver's type holds it, and a
/// holder this report does not state would otherwise silently take the
/// receiver's token.
pub(crate) fn holder_kind(
    report: &ResolutionReport,
    holder: u32,
) -> Result<SymbolKind, GraphBuildError> {
    report
        .definitions()
        .get(index_of(holder))
        .map(SymbolDefinition::kind)
        .ok_or(GraphBuildError::MissingDefinitionNode { definition: holder })
}
