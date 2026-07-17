use std::path::Path;

use pedant_core::WorkspaceMemberError;

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
    #[error("manifest {path} is missing a [package] section")]
    MissingPackageSection { path: Box<str> },
    #[error("failed to parse manifest {path}: {source}")]
    ManifestParse {
        path: Box<str>,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to parse baseline {path}: {source}")]
    BaselineParse {
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

/// Render a path for an error payload without borrowing it.
pub(super) fn path_text(path: &Path) -> Box<str> {
    path.display().to_string().into_boxed_str()
}

pub(super) fn missing_package_section(crate_dir: &Path) -> SupplyChainError {
    SupplyChainError::MissingPackageSection {
        path: path_text(&crate_dir.join("Cargo.toml")),
    }
}

pub(super) fn map_workspace_member_error(error: WorkspaceMemberError) -> SupplyChainError {
    match error {
        WorkspaceMemberError::ReadDir { path, source } => {
            SupplyChainError::ReadDir { path, source }
        }
    }
}
