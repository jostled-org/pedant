//! The resolution-unit view and the Cargo edges that selected it.

use std::fmt;
use std::sync::Arc;

use crate::resolution::rust::dependency::{CargoDependencyKind, DependencyActivation};
use crate::resolution::rust::identity::{PackageId, TargetId};
use crate::resolution::rust::target::CargoTargetKind;

use super::module::RustModuleInstance;

/// Opaque identity of one resolution unit inside a single snapshot.
///
/// Unit identities are snapshot-local: they index the snapshot that issued
/// them and mean nothing outside it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RustSnapshotUnitId {
    index: u32,
}

impl RustSnapshotUnitId {
    /// Issue an identity for the unit at `index`.
    pub(super) fn new(index: u32) -> Self {
        Self { index }
    }

    /// The snapshot-local index this identity selects.
    pub(in crate::resolution::rust) fn index(&self) -> u32 {
        self.index
    }
}

impl fmt::Debug for RustSnapshotUnitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RustSnapshotUnitId({})", self.index)
    }
}

/// One Cargo target instance a resolution snapshot resolves names inside.
#[derive(Debug)]
pub struct RustResolutionUnit {
    pub(super) id: RustSnapshotUnitId,
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) name: Arc<str>,
    pub(super) manifest: Arc<str>,
    pub(super) kind: CargoTargetKind,
    pub(super) activation: DependencyActivation,
    pub(super) crate_root: Arc<str>,
    pub(super) modules: Box<[RustModuleInstance]>,
    pub(super) sources: Box<[Arc<str>]>,
}

impl RustResolutionUnit {
    /// This unit's snapshot-local identity.
    pub fn id(&self) -> RustSnapshotUnitId {
        self.id
    }

    /// The package that declares this unit's Cargo target.
    pub fn package(&self) -> PackageId {
        self.package
    }

    /// The Cargo target this unit compiles.
    pub fn target(&self) -> TargetId {
        self.target
    }

    /// The Cargo target name this unit compiles under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The repository-relative manifest that declares this unit's target.
    pub fn manifest_path(&self) -> &str {
        &self.manifest
    }

    /// Which kind of Cargo target this unit compiles.
    pub fn kind(&self) -> CargoTargetKind {
        self.kind
    }

    /// When this unit is active. `Always` when any root-to-unit path is
    /// unconditional; otherwise the combined, unevaluated predicate.
    pub fn activation(&self) -> &DependencyActivation {
        &self.activation
    }

    /// The repository-relative entry point this unit's module tree starts at.
    pub fn crate_root(&self) -> &str {
        &self.crate_root
    }

    /// Every module instance inside this unit, root first.
    pub fn modules(&self) -> &[RustModuleInstance] {
        &self.modules
    }

    /// The sorted repository-relative sources this unit's modules occupy.
    pub fn sources(&self) -> &[Arc<str>] {
        &self.sources
    }
}

/// One Cargo namespace edge between two units of a resolution snapshot.
///
/// Manifest dependencies retain their declared kind and alias. Cargo's
/// implicit same-package library edge is unconditional `Normal` and uses the
/// library crate name.
#[derive(Debug)]
pub struct RustSnapshotEdge {
    pub(super) source: RustSnapshotUnitId,
    pub(super) target: RustSnapshotUnitId,
    pub(super) name: Arc<str>,
    pub(super) kind: CargoDependencyKind,
    pub(super) activation: DependencyActivation,
}

impl RustSnapshotEdge {
    /// The unit that declares this edge.
    pub fn source(&self) -> RustSnapshotUnitId {
        self.source
    }

    /// The unit this edge selects.
    pub fn target(&self) -> RustSnapshotUnitId {
        self.target
    }

    /// The namespace-local dependency or library crate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which dependency table declared this edge.
    pub fn kind(&self) -> CargoDependencyKind {
        self.kind
    }

    /// When this edge is exposed to the source unit.
    pub fn activation(&self) -> &DependencyActivation {
        &self.activation
    }
}
