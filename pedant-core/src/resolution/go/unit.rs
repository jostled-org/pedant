//! One package compilation context inside a Go resolution snapshot.

use std::fmt;
use std::sync::Arc;

use super::snapshot_module::GoSnapshotModuleId;

/// Opaque identity of one resolution unit inside a single snapshot.
///
/// Unit identities are snapshot-local: they index the snapshot that issued
/// them and mean nothing outside it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoSnapshotUnitId {
    index: u32,
}

impl GoSnapshotUnitId {
    /// Issue an identity for the unit at `index`.
    pub(super) fn new(index: u32) -> Self {
        Self { index }
    }

    /// The snapshot-local index this identity selects.
    pub(super) fn index(self) -> u32 {
        self.index
    }
}

impl fmt::Debug for GoSnapshotUnitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GoSnapshotUnitId({})", self.index)
    }
}

/// Which of a directory's three compilation contexts one unit is.
///
/// Go compiles a package directory up to three times, and the three see
/// different names. Keeping them apart is what lets a report say that a helper
/// declared in a test file is invisible to the production package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GoPackageContext {
    /// The directory's non-test sources.
    Production,
    /// The directory's same-package `_test.go` sources, together with the
    /// production sources they compile beside.
    InternalTest,
    /// The directory's `_test.go` sources declaring the external test package.
    ExternalTest,
}

impl GoPackageContext {
    /// The stable token this context takes in a digest or a rendering.
    pub fn token(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::InternalTest => "internal_test",
            Self::ExternalTest => "external_test",
        }
    }
}

/// One Go package compilation context a snapshot resolves names inside.
#[derive(Debug)]
pub struct GoResolutionUnit {
    pub(super) id: GoSnapshotUnitId,
    pub(super) module: GoSnapshotModuleId,
    pub(super) context: GoPackageContext,
    pub(super) import_path: Arc<str>,
    pub(super) package_name: Box<str>,
    pub(super) directory: Arc<str>,
    pub(super) sources: Box<[Arc<str>]>,
}

impl GoResolutionUnit {
    /// This unit's snapshot-local identity.
    pub fn id(&self) -> GoSnapshotUnitId {
        self.id
    }

    /// The module whose tree declares this unit's directory.
    pub fn module(&self) -> GoSnapshotModuleId {
        self.module
    }

    /// Which compilation context this unit is.
    pub fn context(&self) -> GoPackageContext {
        self.context
    }

    /// The import path the directory has inside its module.
    ///
    /// All three contexts of one directory share it: an import names a
    /// directory, and which context a build compiles is the build's answer.
    pub fn import_path(&self) -> &str {
        &self.import_path
    }

    /// The package clause this unit's sources declare.
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// The unit's directory, repository-relative and `/`-separated. A module
    /// root's directory is the empty string.
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// The repository-relative sources this unit instantiates, sorted by path.
    pub fn sources(&self) -> &[Arc<str>] {
        &self.sources
    }
}
