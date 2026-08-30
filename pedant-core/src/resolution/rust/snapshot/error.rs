//! Typed failures returned while building a target or resolution snapshot.
//!
//! Authority refusals are returned before any source is read. Closure failures
//! carry the site that declared the step, the path that was attempted while it
//! remained inside the repository root, and one owning message.

use std::fmt;
use std::sync::Arc;

/// Which configured ceiling a closure crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionLimit {
    /// Resolution units one snapshot may hold.
    Units,
    /// Distinct source files one snapshot may hold.
    SourceFiles,
    /// Bytes one source file may hold.
    SourceFileBytes,
    /// Bytes all distinct source text may hold.
    TotalSourceBytes,
    /// Rust module nesting depth followed inside one unit.
    ModuleDepth,
    /// Rust module instances one unit may hold.
    ModuleInstances,
    /// Cargo dependency depth followed from the root target.
    DependencyDepth,
    /// Syntax nesting depth accepted while parsing.
    SyntaxDepth,
}

impl fmt::Display for ResolutionLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.field_name())
    }
}

impl ResolutionLimit {
    /// The `ResolutionLimits` field this ceiling belongs to.
    fn field_name(&self) -> &'static str {
        match self {
            Self::Units => "max_units",
            Self::SourceFiles => "max_source_files",
            Self::SourceFileBytes => "max_source_file_bytes",
            Self::TotalSourceBytes => "max_total_source_bytes",
            Self::ModuleDepth => "max_module_depth",
            Self::ModuleInstances => "max_module_instances",
            Self::DependencyDepth => "max_dependency_depth",
            Self::SyntaxDepth => "max_syntax_depth",
        }
    }
}

/// Which closure step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClosureFailureKind {
    /// A target's entry point could not be read.
    EntryRead,
    /// A declared module's source could not be read.
    ModuleRead,
    /// A reached source is not valid Rust.
    SourceParse,
    /// A `mod` declaration names no existing source.
    MissingModule,
    /// A `mod` declaration matches both `name.rs` and `name/mod.rs`.
    AmbiguousModule,
    /// An in-repository dependency package declares no library target.
    MissingDependencyLibraryTarget,
    /// An in-repository dependency names a library target the project that
    /// issued it no longer holds.
    UnresolvedDependencyLibraryTarget,
    /// A path the closure already interned names no source in the store.
    MissingStoredSource,
    /// One package repeats inside a single dependency chain.
    DependencyCycle,
    /// A module path or symlink resolves outside the repository root.
    OutOfRoot,
    /// A reached source is not valid UTF-8.
    InvalidUtf8,
    /// A configured ceiling was crossed.
    LimitExceeded(ResolutionLimit),
}

/// Where a closure failure was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureSite {
    /// A Cargo target's entry point.
    Target {
        /// The Cargo target name.
        name: Box<str>,
        /// The repository-relative entry path.
        entry: Box<str>,
    },
    /// A `mod` declaration inside one source.
    Module {
        /// The repository-relative source that declares the module.
        file: Box<str>,
        /// The declared module name.
        module: Box<str>,
    },
    /// A Cargo dependency edge.
    Dependency {
        /// The package that declares the edge.
        package: Box<str>,
        /// The namespace-local dependency name.
        dependency: Box<str>,
    },
}

impl ClosureSite {
    /// The read-failure kind this site owns: a target owns its entry point,
    /// and the two sites that follow a declaration read a declared module.
    ///
    /// Every variant is named. A catch-all would give a fourth site the
    /// module-read answer without anything asking whether that is the answer it
    /// owns, which is the one failure this projection can make silently.
    pub(super) fn read_kind(&self) -> SourceClosureFailureKind {
        match self {
            Self::Target { .. } => SourceClosureFailureKind::EntryRead,
            Self::Module { .. } | Self::Dependency { .. } => SourceClosureFailureKind::ModuleRead,
        }
    }
}

impl fmt::Display for ClosureSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target { name, entry } => write!(formatter, "target {name} entry {entry}"),
            Self::Module { file, module } => write!(formatter, "{file} declares mod {module}"),
            Self::Dependency {
                package,
                dependency,
            } => write!(formatter, "{package} depends on {dependency}"),
        }
    }
}

/// One typed closure failure with its declaring site and attempted path.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SourceClosureFailure {
    kind: SourceClosureFailureKind,
    site: ClosureSite,
    attempted: Option<Box<str>>,
    message: Box<str>,
}

impl SourceClosureFailure {
    /// Record one failure with the evidence its kind can carry.
    pub(super) fn new(
        kind: SourceClosureFailureKind,
        evidence: (ClosureSite, Option<Box<str>>),
        message: Box<str>,
    ) -> Self {
        let (site, attempted) = evidence;
        Self {
            kind,
            site,
            attempted,
            message,
        }
    }

    /// Which closure step failed.
    pub fn kind(&self) -> SourceClosureFailureKind {
        self.kind
    }

    /// The site that declared the failed step. Every closure step is declared
    /// by a target entry, a `mod` item, or a Cargo edge, so there is always one.
    pub fn site(&self) -> &ClosureSite {
        &self.site
    }

    /// The attempted repository-relative path, when it stayed inside the root.
    pub fn attempted(&self) -> Option<&str> {
        self.attempted.as_deref()
    }

    /// The single-owner reason this step failed.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether this failure ends the traversal rather than one branch of it.
    ///
    /// A crossed ceiling makes every later step meaningless, so reporting the
    /// same limit once per remaining source would bury the one real cause.
    pub(super) fn is_fatal(&self) -> bool {
        matches!(self.kind, SourceClosureFailureKind::LimitExceeded(_))
    }
}

/// Every failure one closure attempt collected, beside the paths it did reach.
#[derive(Debug, thiserror::Error)]
#[error("source closure failed after reaching {} path(s): {}", .reached.len(), render(.failures))]
pub struct SourceClosureError {
    reached: Box<[Arc<str>]>,
    failures: Box<[SourceClosureFailure]>,
}

impl SourceClosureError {
    /// Bind sorted reached paths to the failures that stopped the closure.
    pub(super) fn new(reached: Box<[Arc<str>]>, failures: Box<[SourceClosureFailure]>) -> Self {
        Self { reached, failures }
    }

    /// The sorted paths this attempt reached, as evidence only. They are not a
    /// partial snapshot and must never be hashed as a complete closure.
    ///
    /// Shared with the store that reached them.
    pub fn reached(&self) -> &[Arc<str>] {
        &self.reached
    }

    /// Every typed failure this attempt collected.
    pub fn failures(&self) -> &[SourceClosureFailure] {
        &self.failures
    }
}

fn render(failures: &[SourceClosureFailure]) -> String {
    failures
        .iter()
        .map(|failure| failure.message.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Failure returned by either snapshot operation.
#[derive(Debug, thiserror::Error)]
pub enum RustSnapshotError {
    /// The package identity was issued by a project rooted somewhere else.
    #[error("the package identity was issued by another repository root")]
    ForeignPackage,
    /// The package identity was issued for another revision of this repository.
    #[error("the package identity was issued for another manifest revision")]
    StalePackage,
    /// The package identity names a local index this project never issued.
    #[error("no package occupies local index {index}")]
    UnknownPackage {
        /// The absent local index.
        index: u32,
    },
    /// The identity was issued by a project rooted somewhere else.
    #[error("the target identity was issued by another repository root")]
    ForeignTarget,
    /// The identity was issued for another revision of this repository.
    #[error("the target identity was issued for another manifest revision")]
    StaleTarget,
    /// The identity names a local index this project never issued.
    #[error("no target occupies local index {index}")]
    UnknownTarget {
        /// The absent local index.
        index: u32,
    },
    /// A participating manifest changed after the project was loaded.
    #[error("manifest {manifest} changed since the project was loaded")]
    ProjectManifestsChanged {
        /// The repository-relative manifest that no longer matches.
        manifest: Box<str>,
    },
    /// A participating manifest could not be read while its revision was
    /// re-checked, so whether it still matches is unknown rather than false.
    #[error("manifest {manifest} could not be re-read: {source}")]
    ManifestUnreadable {
        /// The repository-relative manifest that could not be read.
        manifest: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The target's source closure could not be completed.
    #[error(transparent)]
    SourceClosure(#[from] SourceClosureError),
}
