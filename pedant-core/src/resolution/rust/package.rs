//! The package view: one Cargo package declared inside the project root.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::edition::CargoEdition;
use super::identity::PackageId;
use super::version::CargoPackageVersion;

/// A Cargo package whose manifest lies beneath the project root.
///
/// Workspace members and eligible in-root path dependencies both appear here;
/// `is_workspace_member` separates them.
#[derive(Debug)]
pub struct RustPackage {
    pub(super) id: PackageId,
    pub(super) name: Arc<str>,
    pub(super) version: CargoPackageVersion,
    pub(super) rust_version: Option<Arc<str>>,
    pub(super) edition: CargoEdition,
    pub(super) manifest_path: Arc<str>,
    pub(super) relative_directory: Arc<str>,
    pub(super) directory: Box<Path>,
    pub(super) workspace_member: bool,
}

impl RustPackage {
    /// This package's project-scoped identity.
    pub fn id(&self) -> PackageId {
        self.id
    }

    /// The declared `package.name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The validated direct or workspace-inherited version.
    pub fn version(&self) -> &CargoPackageVersion {
        &self.version
    }

    /// The declared or inherited `rust-version`, when the package states one.
    pub fn rust_version(&self) -> Option<&str> {
        self.rust_version.as_deref()
    }

    /// The direct, inherited, or Cargo-defaulted Rust edition.
    pub fn edition(&self) -> CargoEdition {
        self.edition
    }

    /// The repository-relative, `/`-separated manifest path.
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    /// The repository-relative package directory; empty for the root package.
    pub fn relative_directory(&self) -> &str {
        &self.relative_directory
    }

    /// The canonical absolute package directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// This package's directory beneath a caller-supplied spelling of the root.
    ///
    /// Project loading canonicalizes its root, so a consumer that keys caches
    /// or reports paths by the root it passed in re-bases through this rather
    /// than through [`Self::directory`].
    pub fn directory_in(&self, root: &Path) -> PathBuf {
        match self.relative_directory.is_empty() {
            true => root.to_path_buf(),
            false => root.join(&*self.relative_directory),
        }
    }

    /// Whether the workspace declares this package as a member.
    pub fn is_workspace_member(&self) -> bool {
        self.workspace_member
    }
}
