//! Typed failures returned while loading a Cargo project.

/// Failure encountered while reading a repository's Cargo manifests.
#[derive(Debug, thiserror::Error)]
pub enum RustProjectError {
    /// The supplied root is not a directory holding a readable `Cargo.toml`.
    #[error("invalid project root {path}: {reason}")]
    InvalidRoot {
        /// The rejected root.
        path: Box<str>,
        /// Why the root cannot anchor a project.
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
    /// A manifest or a directory scanned for members could not be read.
    #[error("failed to read {path}: {source}")]
    ManifestRead {
        /// The unreadable path.
        path: Box<str>,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A manifest is not valid TOML, or does not match Cargo's schema.
    #[error("failed to parse manifest {path}: {message}")]
    ManifestParse {
        /// The rejected manifest.
        path: Box<str>,
        /// The single-owner reason this manifest was rejected.
        message: Box<str>,
    },
    /// A package declares no version and inherits none.
    #[error("manifest {path} declares no package version")]
    MissingPackageVersion {
        /// The manifest without a resolvable version.
        path: Box<str>,
    },
    /// A package inherits its version from a workspace that declares none.
    #[error("manifest {path} inherits a package version that {workspace} does not declare")]
    MissingWorkspacePackageVersion {
        /// The inheriting manifest.
        path: Box<str>,
        /// The workspace manifest that owes the value.
        workspace: Box<str>,
    },
    /// A resolved package version is not valid SemVer.
    #[error("manifest {path} declares an invalid package version {version}: {source}")]
    InvalidPackageVersion {
        /// The manifest holding the rejected version.
        path: Box<str>,
        /// The exact rejected version text.
        version: Box<str>,
        /// The underlying SemVer failure.
        #[source]
        source: semver::Error,
    },
    /// A package declares an edition Cargo does not recognize.
    #[error("manifest {path} declares an invalid package edition {edition}")]
    InvalidPackageEdition {
        /// The manifest holding the rejected edition.
        path: Box<str>,
        /// The exact rejected edition text.
        edition: Box<str>,
    },
    /// A package inherits its edition from a workspace that declares none.
    #[error("manifest {path} inherits a package edition that {workspace} does not declare")]
    MissingWorkspacePackageEdition {
        /// The inheriting manifest.
        path: Box<str>,
        /// The workspace manifest that owes the value.
        workspace: Box<str>,
    },
    /// The project holds more manifests than the configured limit allows.
    #[error("project holds more than {limit} manifests")]
    LimitExceeded {
        /// The configured manifest ceiling.
        limit: u32,
    },
    /// Expanding the workspace member globs walked more of the tree than the
    /// configured limit allows.
    ///
    /// Separate from [`Self::LimitExceeded`] because it is crossed before any
    /// manifest is read: the subject is directories visited, not manifests
    /// held, and the operator's fix is a narrower `members` pattern rather
    /// than a higher manifest ceiling.
    #[error("expanding the workspace members visited more than {limit} directory entries")]
    MemberScanLimitExceeded {
        /// The configured member-scan ceiling.
        limit: u32,
    },
}
