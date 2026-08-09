//! Target-authority validation, performed before any Rust source is read.
//!
//! A foreign root, another manifest revision, an index this project never
//! issued, and a manifest edited since the project loaded are each refused with
//! their own error, so two projects that both assign local index zero can never
//! select each other's targets.

use crate::hash::digest_bytes;
use crate::observe::{self, Observation};
use crate::resolution::rust::identity::{PackageId, TargetId, index_of};
use crate::resolution::rust::manifest::ManifestFingerprint;
use crate::resolution::rust::package::RustPackage;
use crate::resolution::rust::project::RustProject;
use crate::resolution::rust::target::RustTarget;

use super::error::RustSnapshotError;

/// The target `id` selects, once its authority survives every check.
pub(super) fn validated_target(
    project: &RustProject,
    id: TargetId,
) -> Result<&RustTarget, RustSnapshotError> {
    check_scope(project, id)?;
    let target = project
        .targets
        .get(index_of(id.index()))
        .ok_or(RustSnapshotError::UnknownTarget { index: id.index() })?;
    check_manifests(project)?;
    Ok(target)
}

/// The package `id` selects, once its authority survives every check.
pub(super) fn validated_package(
    project: &RustProject,
    id: PackageId,
) -> Result<&RustPackage, RustSnapshotError> {
    check_package_scope(project, id)?;
    let package = project
        .packages
        .get(index_of(id.index()))
        .ok_or(RustSnapshotError::UnknownPackage { index: id.index() })?;
    check_manifests(project)?;
    Ok(package)
}

fn check_scope(project: &RustProject, id: TargetId) -> Result<(), RustSnapshotError> {
    let issued = id.authority();
    let scope = (
        issued.same_root(&project.authority),
        issued.same_revision(&project.authority),
    );
    match scope {
        (false, _) => Err(RustSnapshotError::ForeignTarget),
        (true, false) => Err(RustSnapshotError::StaleTarget),
        (true, true) => Ok(()),
    }
}

fn check_package_scope(project: &RustProject, id: PackageId) -> Result<(), RustSnapshotError> {
    let issued = id.authority();
    let scope = (
        issued.same_root(&project.authority),
        issued.same_revision(&project.authority),
    );
    match scope {
        (false, _) => Err(RustSnapshotError::ForeignPackage),
        (true, false) => Err(RustSnapshotError::StalePackage),
        (true, true) => Ok(()),
    }
}

/// Every participating manifest must still hold the exact bytes it held when
/// the project was indexed.
fn check_manifests(project: &RustProject) -> Result<(), RustSnapshotError> {
    for manifest in project.manifests.iter() {
        observe::record(Observation::ManifestRead(&manifest.relative));
        check_manifest(project, manifest)?;
    }
    Ok(())
}

/// One manifest's current bytes against the digest the project indexed.
///
/// An unreadable manifest is its own refusal: reporting it as "changed" would
/// send the caller to reload a project that fails for another reason entirely.
fn check_manifest(
    project: &RustProject,
    manifest: &ManifestFingerprint,
) -> Result<(), RustSnapshotError> {
    let path = project.root.join(&*manifest.relative);
    let current = std::fs::read(&path).map_err(|source| RustSnapshotError::ManifestUnreadable {
        manifest: Box::from(&*manifest.relative),
        source,
    })?;
    match digest_bytes(&current) == manifest.digest {
        true => Ok(()),
        false => Err(RustSnapshotError::ProjectManifestsChanged {
            manifest: Box::from(&*manifest.relative),
        }),
    }
}
