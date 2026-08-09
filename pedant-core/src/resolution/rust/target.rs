//! The target view: one compilation entry point declared by, or discovered
//! for, a package.

use std::sync::Arc;

use super::edition::CargoEdition;
use super::identity::{PackageId, TargetId};

/// The kind of Cargo target an entry point compiles into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CargoTargetKind {
    /// The package's single library target.
    Library,
    /// A binary target.
    Binary,
    /// An example target.
    Example,
    /// An integration-test target.
    Test,
    /// A benchmark target.
    Benchmark,
    /// The package's build script.
    BuildScript,
}

impl CargoTargetKind {
    /// The stable token this kind takes inside a resolution unit key.
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::Library => "lib",
            Self::Binary => "bin",
            Self::Example => "example",
            Self::Test => "test",
            Self::Benchmark => "bench",
            Self::BuildScript => "build-script",
        }
    }
}

/// One Cargo target and the source file it enters through.
#[derive(Debug)]
pub struct RustTarget {
    pub(super) id: TargetId,
    pub(super) package: PackageId,
    pub(super) name: Arc<str>,
    pub(super) kind: CargoTargetKind,
    pub(super) entry_path: Arc<str>,
    pub(super) edition: CargoEdition,
}

impl RustTarget {
    /// This target's project-scoped identity.
    pub fn id(&self) -> TargetId {
        self.id
    }

    /// The package that declares this target.
    pub fn package(&self) -> PackageId {
        self.package
    }

    /// The Cargo target name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which kind of target this is.
    pub fn kind(&self) -> CargoTargetKind {
        self.kind
    }

    /// The repository-relative, `/`-separated entry-point path.
    pub fn entry_path(&self) -> &str {
        &self.entry_path
    }

    /// The edition this target inherits from its package.
    pub fn edition(&self) -> CargoEdition {
        self.edition
    }
}
