use std::path::Path;

use pedant_core::resolution::rust::{
    RustPackage, RustPackageSnapshotError, RustProject, RustProjectError, RustSnapshotError,
    SourceClosureFailure,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum SupplyChainError {
    #[error("no Cargo.lock found in {0}; generate and commit a lockfile first")]
    MissingLockfile(Box<str>),
    #[error("failed to determine current directory: {0}")]
    CurrentDir(#[source] std::io::Error),
    #[error("failed to create temp directory: {0}")]
    TempDir(#[source] std::io::Error),
    #[error("failed to run cargo vendor: {0}")]
    CargoVendorSpawn(#[source] std::io::Error),
    #[error("cargo vendor failed: {0}")]
    CargoVendor(Box<str>),
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to delete path {path}: {source}")]
    DeletePath {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("the vendored Cargo project at {path} publishes no package")]
    PublishesNothing { path: Box<str> },
    #[error("failed to load a vendored Cargo project: {source}")]
    Project {
        #[from]
        source: RustProjectError,
    },
    #[error("{package}: target {target} has no complete source closure: {detail}")]
    TargetSourceClosure {
        package: Box<str>,
        target: Box<str>,
        /// Every closure failure, rendered for a reader.
        detail: Box<str>,
        /// The typed failure the substrate reported.
        #[source]
        source: RustSnapshotError,
    },
    #[error("{package} reaches {path}, which lies outside the package directory")]
    SourceOutsidePackage { package: Box<str>, path: Box<str> },
    #[error("package snapshot stored {path} without a primary-target owner")]
    UnownedSnapshotSource { path: Box<str> },
    #[error("failed to parse baseline {path}: {source}")]
    BaselineParse {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize the baseline for {path}: {source}")]
    BaselineSerialize {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize the report for {path}: {source}")]
    ReportSerialize {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize the proof receipt for {path}: {source}")]
    #[cfg(feature = "resolution-test-support")]
    ReceiptSerialize {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to compute attestation timestamp: {0}")]
    Timestamp(#[source] std::time::SystemTimeError),
    #[error("failed to persist temporary report: {0}")]
    PersistReport(#[source] std::io::Error),
    #[error("failed to write GitHub output {path}: {source}")]
    GithubOutput {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
}

/// The selected target a snapshot failure belongs to.
pub(super) struct TargetContext<'a> {
    pub(super) package: &'a str,
    pub(super) target: &'a str,
}

/// Render a path for an error payload without borrowing it.
pub(super) fn path_text(path: &Path) -> Box<str> {
    path.display().to_string().into_boxed_str()
}

/// Bind a write failure to the path it was attempted on.
pub(super) fn write_error(path: &Path) -> impl Fn(std::io::Error) -> SupplyChainError {
    let path = path_text(path);
    move |source| SupplyChainError::WriteFile {
        path: path.clone(),
        source,
    }
}

/// A selected target with no complete closure is security-fatal, so the failure
/// keeps the target it belongs to beside every declaring site, attempted path,
/// and cause the substrate reported. The typed failure travels as the source,
/// so a caller can still tell a limit breach from a broken `mod` path.
pub(super) fn map_snapshot_error(
    context: &TargetContext<'_>,
    error: RustSnapshotError,
) -> SupplyChainError {
    SupplyChainError::TargetSourceClosure {
        package: Box::from(context.package),
        target: Box::from(context.target),
        detail: snapshot_detail(&error),
        source: error,
    }
}

/// Bind a package-primary snapshot failure back to the target whose closure
/// failed. Package-level authority refusals retain a stable aggregate label.
pub(super) fn map_package_snapshot_error(
    project: &RustProject,
    package: &RustPackage,
    error: RustPackageSnapshotError,
) -> SupplyChainError {
    let target = error
        .target()
        .and_then(|id| project.target(id))
        .map_or("primary-target set", |target| target.name());
    map_snapshot_error(
        &TargetContext {
            package: package.name(),
            target,
        },
        error.into_source(),
    )
}

fn snapshot_detail(error: &RustSnapshotError) -> Box<str> {
    match error {
        RustSnapshotError::SourceClosure(closure) => closure
            .failures()
            .iter()
            .map(failure_detail)
            .collect::<Vec<_>>()
            .join("; ")
            .into_boxed_str(),
        authority => authority.to_string().into_boxed_str(),
    }
}

/// One closure failure with its declaring site, the path it attempted while
/// that path stayed inside the repository root, and its cause.
fn failure_detail(failure: &SourceClosureFailure) -> String {
    let site = failure.site();
    match failure.attempted() {
        Some(attempted) => format!("[{site}] {} (attempted {attempted})", failure.message()),
        None => format!("[{site}] {}", failure.message()),
    }
}
