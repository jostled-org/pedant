//! The project view: every package, target, and dependency beneath one
//! canonical repository root.

use std::path::Path;

use pedant_types::SourceProvider;

use super::dependency::RustDependency;
use super::error::RustProjectError;
use super::fault::RustSourceFault;
use super::identity::{PackageId, ProjectAuthority, TargetId, index_of};
use super::inventory::RustFileInventory;
use super::limits::ResolutionLimits;
use super::load;
use super::manifest::ManifestFingerprint;
use super::package::RustPackage;
use super::provider::RustSourceProvider;
use super::snapshot::{
    RustPackageSnapshot, RustPackageSnapshotError, RustResolutionSnapshot, RustSnapshotError,
    RustTargetSnapshot, build_package_snapshot, build_resolution_snapshot, build_target_snapshot,
};
use super::target::RustTarget;

/// A factual Cargo project index rooted at one canonical repository root.
///
/// Views are borrowed and deterministically ordered by stable structural keys,
/// so reordering filesystem enumeration cannot change what a caller reads.
#[derive(Debug)]
pub struct RustProject {
    pub(super) root: Box<Path>,
    pub(super) limits: ResolutionLimits,
    pub(super) authority: ProjectAuthority,
    pub(super) manifests: Box<[ManifestFingerprint]>,
    pub(super) packages: Box<[RustPackage]>,
    pub(super) targets: Box<[RustTarget]>,
    pub(super) dependencies: Box<[RustDependency]>,
}

impl RustProject {
    /// Read every manifest beneath `root` and index the project it declares.
    ///
    /// Reads `Cargo.toml` files and directory listings only: no Rust source is
    /// opened and Cargo is never invoked.
    pub fn load(root: &Path, limits: ResolutionLimits) -> Result<Self, RustProjectError> {
        load::load_project(root, limits)
    }

    /// The canonical repository root this project was loaded from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The limits this project was loaded under and retains for snapshots.
    pub fn limits(&self) -> ResolutionLimits {
        self.limits
    }

    /// Every package in the project, workspace members and eligible in-root
    /// path dependencies alike, ordered by manifest path.
    pub fn packages(&self) -> &[RustPackage] {
        &self.packages
    }

    /// Only the packages the workspace declares as members.
    pub fn workspace_members(&self) -> impl Iterator<Item = &RustPackage> {
        self.packages
            .iter()
            .filter(|package| package.is_workspace_member())
    }

    /// The package an identity issued by this project selects.
    pub fn package(&self, id: PackageId) -> Option<&RustPackage> {
        select(id.authority(), self.authority, id.index())
            .and_then(|index| self.packages.get(index))
    }

    /// Every target in the project, ordered by package, kind, then name.
    pub fn targets(&self) -> &[RustTarget] {
        &self.targets
    }

    /// The target an identity issued by this project selects.
    pub fn target(&self, id: TargetId) -> Option<&RustTarget> {
        select(id.authority(), self.authority, id.index()).and_then(|index| self.targets.get(index))
    }

    /// Every target one package declares.
    pub fn package_targets(&self, package: PackageId) -> impl Iterator<Item = &RustTarget> {
        self.targets
            .iter()
            .filter(move |target| target.package() == package)
    }

    /// Every dependency edge in the project, ordered by package, kind, then
    /// local dependency name.
    pub fn dependencies(&self) -> &[RustDependency] {
        &self.dependencies
    }

    /// Snapshot only this target's Rust module closure.
    ///
    /// The target's authority is validated before any source is read, and the
    /// closure is all-or-error: a caller receives every reachable source or a
    /// typed failure, never a partial set.
    pub fn snapshot_target(
        &self,
        target: TargetId,
    ) -> Result<RustTargetSnapshot, RustSnapshotError> {
        build_target_snapshot(self, &mut private_provider(self), target)
    }

    /// Snapshot every library, binary, and build-script target of one package.
    ///
    /// Target closures remain separate views, but all of them share one source
    /// store so an overlapping source is read, hashed, and parsed once. Any
    /// incomplete target refuses the entire package snapshot.
    pub fn snapshot_package_primary_targets(
        &self,
        package: PackageId,
    ) -> Result<RustPackageSnapshot, RustPackageSnapshotError> {
        build_package_snapshot(self, &mut private_provider(self), package)
    }

    /// Snapshot this target together with its same-package library, when Cargo
    /// exposes one, and the in-repository dependency libraries its namespace
    /// resolves names against.
    ///
    /// Reads through a provider of this project's own, which lives exactly as
    /// long as the call: every source this snapshot reaches is read once, and
    /// nothing it read outlives the answer.
    pub fn snapshot_resolution(
        &self,
        target: TargetId,
    ) -> Result<RustResolutionSnapshot, RustSnapshotError> {
        build_resolution_snapshot(self, &mut private_provider(self), target)
    }

    /// The same snapshot, reading through a provider the caller owns.
    ///
    /// Selection, closure walking, ceilings, ordering, errors, and the
    /// fingerprint are the ones [`Self::snapshot_resolution`] states. What
    /// changes is who read the sources: a provider that already holds a path
    /// answers from what it holds, so a file several project slices reach is
    /// read, parsed, and walked once for all of them. This snapshot still
    /// charges every source it selects against its own ceilings, because a
    /// shared read is not a free source for the corpus that selected it.
    pub fn snapshot_resolution_with_provider<P>(
        &self,
        provider: &mut P,
        target: TargetId,
    ) -> Result<RustResolutionSnapshot, RustSnapshotError>
    where
        P: SourceProvider<RustFileInventory>,
        P::Error: Into<RustSourceFault>,
    {
        build_resolution_snapshot(self, provider, target)
    }

    /// Every dependency edge one package declares.
    pub fn package_dependencies(
        &self,
        package: PackageId,
    ) -> impl Iterator<Item = &RustDependency> {
        self.dependencies
            .iter()
            .filter(move |dependency| dependency.source() == package)
    }
}

/// Reject an identity issued by another project before it selects a record.
fn select(issuing: ProjectAuthority, project: ProjectAuthority, index: u32) -> Option<usize> {
    match issuing == project {
        true => Some(index_of(index)),
        false => None,
    }
}

/// A provider that reads one project's root under its limits, for the length of
/// one convenience call.
///
/// A convenience snapshot reads exactly the sources it reaches and keeps none
/// of them, which is why its published behavior is unchanged by the seam: a
/// provider born and dropped inside one call has nothing earlier to answer
/// from.
///
/// This is the one caller that may skip the constructor's canonicalization: a
/// loaded project's root is what `canonical_root` already answered, so asking
/// the filesystem a second time could only add a failure the snapshot below
/// would report anyway on its first read.
fn private_provider(project: &RustProject) -> RustSourceProvider {
    RustSourceProvider::at_project_root(project.root.to_path_buf(), project.limits)
}
