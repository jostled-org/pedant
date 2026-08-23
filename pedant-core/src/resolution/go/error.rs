//! Typed failures returned while loading a Go module project.

/// Failure encountered while reading a repository's Go module manifests.
#[derive(Debug, thiserror::Error)]
pub enum GoProjectError {
    /// The supplied root is not a directory holding a readable `go.mod`.
    #[error("invalid project root {path}: {reason}")]
    InvalidRoot {
        /// The rejected root.
        path: Box<str>,
        /// Why the root cannot anchor a main module.
        reason: Box<str>,
    },
    /// A path the loader reached is not inside the repository root.
    #[error("path {path} lies outside the project root {root}")]
    OutOfRoot {
        /// The path that cannot be made repository-relative.
        path: Box<str>,
        /// The root that does not contain it.
        root: Box<str>,
    },
    /// A path beneath the repository root is not valid UTF-8.
    #[error("path {path} beneath the project root is not valid UTF-8")]
    NonUtf8Path {
        /// The offending path, rendered lossily for the message only.
        path: Box<str>,
    },
    /// A path beneath the repository root could not be resolved.
    ///
    /// Absence is not this: a path nothing holds is reported by the stage that
    /// asked for it. This is a path the filesystem refused to answer for — a
    /// denied permission, a symlink loop, an over-long name — which must not
    /// read as a declaration the repository never made.
    #[error("failed to resolve {path}: {source}")]
    PathRead {
        /// The path that could not be resolved.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A manifest could not be read.
    #[error("failed to read {path}: {source}")]
    ManifestRead {
        /// The unreadable path.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A manifest does not match the `go.mod` grammar.
    #[error("failed to parse manifest {path} at line {line}: {message}")]
    ManifestParse {
        /// The rejected manifest, repository-relative.
        path: Box<str>,
        /// The one-based line the rejection is about.
        line: u32,
        /// The single-owner reason this manifest was rejected.
        message: Box<str>,
    },
    /// A manifest states no `module` directive, so it names no module.
    #[error("manifest {path} declares no module path")]
    MissingModuleDeclaration {
        /// The manifest without a module path.
        path: Box<str>,
    },
    /// One manifest requires one module path more than once.
    #[error("manifest {path} requires {module} more than once")]
    DuplicateRequirement {
        /// The manifest holding both requirements.
        path: Box<str>,
        /// The module path required twice.
        module: Box<str>,
    },
    /// The root manifest excludes one exact module version more than once.
    #[error("manifest {path} excludes {module} {version} more than once")]
    DuplicateExclusion {
        /// The manifest holding both exclusions.
        path: Box<str>,
        /// The excluded module path.
        module: Box<str>,
        /// The excluded version.
        version: Box<str>,
    },
    /// The root manifest replaces one module key more than once.
    ///
    /// The key is the old module path together with its optional old version,
    /// which is exactly what Go's own precedence rule selects on.
    #[error("manifest {path} replaces {module} at {version} more than once")]
    DuplicateReplacement {
        /// The manifest holding both replacements.
        path: Box<str>,
        /// The replaced module path.
        module: Box<str>,
        /// The replaced version, or `any version` for a path-only entry.
        version: Box<str>,
    },
    /// A declared version is not a Go module version.
    #[error("manifest {path} declares an invalid version {version} for {module}")]
    InvalidVersion {
        /// The manifest holding the rejected version.
        path: Box<str>,
        /// The module the version belongs to.
        module: Box<str>,
        /// The exact rejected version text.
        version: Box<str>,
    },
    /// A root exclusion matches a requirement an admitted module contributed.
    ///
    /// This tier states what the manifests declare and runs no minimal-version
    /// selection, so it refuses rather than guessing a substitute version.
    #[error("requirement {module} {version} is excluded by the root manifest")]
    ExcludedRequirement {
        /// The excluded module path.
        module: Box<str>,
        /// The excluded version.
        version: Box<str>,
    },
    /// A replacement names a local directory that holds no readable manifest.
    #[error("replacement directory {directory} for {module} holds no readable go.mod")]
    MissingReplacementManifest {
        /// The replacement target, repository-relative when it is in root.
        directory: Box<str>,
        /// The module the replacement was meant to supply.
        module: Box<str>,
    },
    /// A replacement target declares a module path other than the required one.
    #[error("replacement directory {directory} declares {declared}, not {expected}")]
    ReplacementModuleMismatch {
        /// The replacement target, repository-relative.
        directory: Box<str>,
        /// The module path the target's manifest declares.
        declared: Box<str>,
        /// The module path the requirement asked for.
        expected: Box<str>,
    },
    /// Two admitted directories declare one module path, so the project has two
    /// answers for one module.
    #[error("module {module} is declared by {first} and {second}")]
    ConflictingLocalModules {
        /// The module path declared twice.
        module: Box<str>,
        /// The directory that declared it first, repository-relative.
        first: Box<str>,
        /// The directory that declared it again, repository-relative.
        second: Box<str>,
    },
    /// A module index the loader itself minted names no admitted module.
    ///
    /// Defensive: every index handed to a depth or directory lookup is one
    /// `retain_module` just returned. It refuses rather than answering, because
    /// a depth taken as zero restarts the replacement-depth count that bounds
    /// the module graph, and a directory taken as empty renders as the
    /// repository root in a conflict refusal.
    #[error("module record {index} was admitted but is not held")]
    MissingAdmittedModule {
        /// The project-local module index that names no record.
        index: u32,
    },
    /// The project holds more module manifests than the configured limit allows.
    #[error("project holds more than {limit} module manifests")]
    ManifestLimitExceeded {
        /// The configured manifest ceiling.
        limit: u32,
    },
    /// A replacement sits deeper than the configured dependency ceiling allows.
    #[error("dependency depth exceeds {limit}")]
    DependencyDepthLimitExceeded {
        /// The configured depth ceiling.
        limit: u32,
    },
}
