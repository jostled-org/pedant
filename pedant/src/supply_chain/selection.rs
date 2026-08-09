//! Which Cargo targets a package attestation covers, and the exact sources
//! their complete module closures reached.
//!
//! Selection is all-or-error: a package contributes every source of every
//! primary target or none at all, so a hash can never describe a partial view
//! of a dependency.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::resolution::rust::{
    CargoTargetKind, RustPackage, RustPackageSnapshot, RustProject, RustSource,
};

use super::error::{SupplyChainError, map_package_snapshot_error};

/// Every primary-target snapshot of one package, taken before any of them is
/// read, and the package identity their sources are reported against.
pub(super) struct PackageSnapshots {
    package: Box<str>,
    directory: Box<str>,
    snapshot: RustPackageSnapshot,
}

/// One selected source: the crate-relative path an attestation names, and the
/// snapshot record already holding its bytes, digest, and one-pass IR.
pub(super) struct SelectedSource<'a> {
    pub(super) path: Arc<str>,
    pub(super) source: &'a RustSource,
    /// Whether every selected target that reached this source runs at build
    /// time, which is what tags its capabilities as a build hook.
    pub(super) build_hook: bool,
}

impl PackageSnapshots {
    /// Snapshot every primary target of `package`, failing on the first target
    /// whose closure is incomplete.
    pub(super) fn take(
        project: &RustProject,
        package: &RustPackage,
    ) -> Result<Self, SupplyChainError> {
        let snapshot = project
            .snapshot_package_primary_targets(package.id())
            .map_err(|error| map_package_snapshot_error(project, package, error))?;
        Ok(Self {
            package: Box::from(package.name()),
            directory: Box::from(package.relative_directory()),
            snapshot,
        })
    }

    /// The shared store's distinct sources, ordered by crate-relative path.
    ///
    /// Per-target views determine whether every target reaching a source is a
    /// build script; bytes, digest, and IR come from the one stored record.
    pub(super) fn selected(&self) -> Result<Box<[SelectedSource<'_>]>, SupplyChainError> {
        let mut contexts = BTreeMap::new();
        for target in self.snapshot.targets() {
            let build_hook = target.kind() == CargoTargetKind::BuildScript;
            for source in target.sources() {
                contexts
                    .entry(source)
                    .and_modify(|all_build_hooks| *all_build_hooks &= build_hook)
                    .or_insert(build_hook);
            }
        }
        let mut selected = Vec::new();
        for source in self.snapshot.sources() {
            let build_hook = contexts.get(source.path()).copied().ok_or_else(|| {
                SupplyChainError::UnownedSnapshotSource {
                    path: Box::from(source.path()),
                }
            })?;
            selected.push(SelectedSource {
                path: self.attestation_path(source.path())?,
                source,
                build_hook,
            });
        }
        Ok(selected.into_boxed_slice())
    }

    /// The `./`-prefixed crate-relative path an attestation records.
    ///
    /// A published package cannot reach a source outside its own directory, so
    /// one that does is refused rather than given an ambiguous spelling.
    fn attestation_path(&self, project_relative: &str) -> Result<Arc<str>, SupplyChainError> {
        match crate_relative(project_relative, &self.directory) {
            Some(relative) => Ok(Arc::from(format!("./{relative}"))),
            None => Err(SupplyChainError::SourceOutsidePackage {
                package: Box::from(&*self.package),
                path: Box::from(project_relative),
            }),
        }
    }
}

/// Strip the package directory from a project-relative snapshot path.
///
/// The receipt writer resolves the same correspondence between an observed
/// production path and the path an attestation names, so both read this one
/// rule.
pub(super) fn crate_relative<'a>(project_relative: &'a str, directory: &str) -> Option<&'a str> {
    match directory.is_empty() {
        true => Some(project_relative),
        false => project_relative
            .strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/')),
    }
}
