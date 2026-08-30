//! Root-only snapshots for every primary target one package publishes.
//!
//! Library, binary, and build-script closures keep separate target views while
//! sharing one source store. A normalized source reached by several targets is
//! therefore read, hashed, and parsed once without erasing which targets
//! reached it.

use std::sync::Arc;

use crate::resolution::line_index;
use crate::resolution::rust::fault::RustSourceFault;
use crate::resolution::rust::identity::{PackageId, TargetId};
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::target::{CargoTargetKind, RustTarget};
use crate::resolution::supply::SourceSupply;

use super::authority;
use super::closure::{self, ClosureEntry, UnitClosure};
use super::error::RustSnapshotError;
use super::source::RustSource;
use super::store::{SourceStore, refuse};

/// One primary target's closure inside a package snapshot.
#[derive(Debug)]
pub struct RustPrimaryTargetSnapshot {
    target: TargetId,
    kind: CargoTargetKind,
    crate_root: Arc<str>,
    sources: Box<[Arc<str>]>,
}

impl RustPrimaryTargetSnapshot {
    /// The target whose closure this view describes.
    pub fn target(&self) -> TargetId {
        self.target
    }

    /// Whether this is a library, binary, or build-script target.
    pub fn kind(&self) -> CargoTargetKind {
        self.kind
    }

    /// The repository-relative entry point this closure started at.
    pub fn crate_root(&self) -> &str {
        &self.crate_root
    }

    /// Every repository-relative source path this target reaches.
    pub fn sources(&self) -> impl ExactSizeIterator<Item = &str> {
        self.sources.iter().map(AsRef::as_ref)
    }
}

/// Every primary target of one package and their shared source store.
#[derive(Debug)]
pub struct RustPackageSnapshot {
    package: PackageId,
    targets: Box<[RustPrimaryTargetSnapshot]>,
    sources: Box<[RustSource]>,
}

impl RustPackageSnapshot {
    /// The package whose primary targets were snapshotted.
    pub fn package(&self) -> PackageId {
        self.package
    }

    /// The package's library, binary, and build-script target views.
    pub fn targets(&self) -> &[RustPrimaryTargetSnapshot] {
        &self.targets
    }

    /// Every distinct source reached by any primary target, sorted by path.
    pub fn sources(&self) -> &[RustSource] {
        &self.sources
    }

    /// The one stored source at a repository-relative path.
    pub fn source(&self, path: &str) -> Option<&RustSource> {
        line_index::find(&self.sources, path)
    }
}

/// A package snapshot failed while validating the package or walking one
/// primary target.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct RustPackageSnapshotError {
    target: Option<TargetId>,
    #[source]
    source: RustSnapshotError,
}

impl RustPackageSnapshotError {
    /// The primary target whose closure failed, when source traversal began.
    pub fn target(&self) -> Option<TargetId> {
        self.target
    }

    /// Consume the package context and return the underlying typed failure.
    pub fn into_source(self) -> RustSnapshotError {
        self.source
    }

    fn package(source: RustSnapshotError) -> Self {
        Self {
            target: None,
            source,
        }
    }

    fn for_target(target: TargetId, source: RustSnapshotError) -> Self {
        Self {
            target: Some(target),
            source,
        }
    }
}

/// Validate one package, then walk all of its primary targets into one store.
pub(in crate::resolution::rust) fn build<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    project: &RustProject,
    provider: &mut P,
    id: PackageId,
) -> Result<RustPackageSnapshot, RustPackageSnapshotError> {
    let package =
        authority::validated_package(project, id).map_err(RustPackageSnapshotError::package)?;
    let primary_targets = project
        .package_targets(package.id())
        .filter(|target| is_primary(target.kind()));
    let mut store = SourceStore::new(project.root(), project.limits());
    let mut targets = Vec::new();
    for target in primary_targets {
        targets.push(build_target(&mut store, provider, target)?);
    }
    Ok(RustPackageSnapshot {
        package: id,
        targets: targets.into_boxed_slice(),
        sources: store.finish(),
    })
}

fn build_target<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    target: &RustTarget,
) -> Result<RustPrimaryTargetSnapshot, RustPackageSnapshotError> {
    let entry = ClosureEntry::of_target(target);
    let mut failures = Vec::new();
    let closure = closure::walk_unit(store, provider, &entry, &mut failures).completed();
    match (closure, failures.is_empty()) {
        (Some(closure), true) => Ok(target_snapshot(target, closure)),
        (None, _) | (Some(_), false) => Err(RustPackageSnapshotError::for_target(
            target.id(),
            refuse(store, failures),
        )),
    }
}

fn target_snapshot(target: &RustTarget, closure: UnitClosure) -> RustPrimaryTargetSnapshot {
    RustPrimaryTargetSnapshot {
        target: target.id(),
        kind: target.kind(),
        crate_root: Arc::clone(target.shared_entry_path()),
        sources: closure.sources,
    }
}

fn is_primary(kind: CargoTargetKind) -> bool {
    matches!(
        kind,
        CargoTargetKind::Library | CargoTargetKind::Binary | CargoTargetKind::BuildScript
    )
}
