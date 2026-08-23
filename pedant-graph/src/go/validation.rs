//! Every Go-specific join a projection consumes, checked before a graph exists.
//!
//! What the neutral family beside it proves is the shape of a plan: that a
//! stated slot names a record, that a join names a node, that a source was
//! placed. What is proved here is the pairing this adapter was handed — the
//! snapshot, the resolution, the bindings between them, the package clause each
//! unit is rooted at, and the two report vocabularies a Go projection has a node
//! and a record for.
//!
//! The producer's own validator makes most of these unreachable in ordinary
//! use. They are still checked here, because a graph that silently dropped a
//! join would be indistinguishable from a repository that has none. Each
//! function owns exactly one refusal, and every one is taken before a record is
//! sealed.

use std::collections::BTreeMap;

use pedant_core::resolution::go::{
    GoProjectResolution, GoResolutionSnapshot, GoSnapshotEdge, GoSnapshotModuleId, GoUnitBinding,
};
use pedant_types::{ResolutionReport, ResolutionUnit, SymbolDefinition, SymbolKind};

use crate::error::GraphBuildError;
use crate::id::index_of;
use crate::node::GraphNodeKind;
use crate::projection::validation as neutral;

use super::mapping::Vocabulary;

/// The supplied snapshot must be the one the resolution was validated against.
///
/// The main module is the snapshot's first either way, so it proves nothing on
/// its own: an edit that leaves every manifest and package clause alone still
/// produces another snapshot, and only the fingerprint sees it.
pub(crate) fn check_snapshot_identity(
    snapshot: &GoResolutionSnapshot,
    resolution: &GoProjectResolution,
) -> Result<(), GraphBuildError> {
    match snapshot.fingerprint() == resolution.snapshot_fingerprint() {
        true => Ok(()),
        false => Err(GraphBuildError::SnapshotFingerprintMismatch),
    }
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

/// The plan position of the module whose tree declares one bound package.
///
/// The module table is filled from the snapshot's own modules, so a module
/// identity outside it names nothing this graph holds a container for. That is
/// the same dangling binding a missing package context is, so it is refused
/// through the same neutral owner rather than built a second time here.
pub(crate) fn module_unit(
    modules: &BTreeMap<GoSnapshotModuleId, u32>,
    module: GoSnapshotModuleId,
    reported: u32,
) -> Result<u32, GraphBuildError> {
    neutral::bound_instance(modules.get(&module).copied(), reported)
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

/// The plan position one snapshot dependency endpoint resolves to.
///
/// The refusal names the edge rather than the module, because a snapshot module
/// identity is opaque outside the snapshot that issued it and the plan's own
/// unit order is a different order.
pub(crate) fn dependency_unit(
    bound: Option<u32>,
    stated: (u32, &GoSnapshotEdge),
) -> Result<u32, GraphBuildError> {
    let (edge, declaration) = stated;
    bound.ok_or_else(|| GraphBuildError::MissingDependencyUnit {
        edge,
        alias: Box::from(declaration.module_path()),
    })
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

/// The node kind one report definition takes in a Go projection.
///
/// The refusal names the report-local definition whose kind this projection has
/// no node for. `GoProjectResolution` proves the Go subset before it publishes a
/// report, so this answers only for a report that reached the projection without
/// that proof.
pub(crate) fn definition_kind(
    vocabulary: &Vocabulary,
    definition: &SymbolDefinition,
    holder: Option<SymbolKind>,
) -> Result<GraphNodeKind, GraphBuildError> {
    neutral::stated_definition_kind(vocabulary.definition(definition.kind(), holder), definition)
}
