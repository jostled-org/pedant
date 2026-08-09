//! Package fields, including the values a workspace may supply.

use std::sync::Arc;

use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::error::RustProjectError;
use crate::resolution::rust::toml_view;
use crate::resolution::rust::version::CargoPackageVersion;

/// The package fields the project view exposes.
pub(super) struct PackageFacts {
    pub(super) name: Arc<str>,
    pub(super) version: CargoPackageVersion,
    pub(super) rust_version: Option<Arc<str>>,
    pub(super) edition: CargoEdition,
}

/// What a package may inherit, and from which manifest.
pub(super) struct WorkspaceSource<'a> {
    pub(super) package: Option<&'a toml::Table>,
    pub(super) manifest_path: &'a str,
}

/// Read one package's name, validated version, and optional MSRV.
pub(super) fn package_facts(
    package: &toml::Table,
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<PackageFacts, RustProjectError> {
    let name =
        toml_view::string(package, "name").ok_or_else(|| RustProjectError::ManifestParse {
            path: Box::from(manifest_path),
            message: Box::from("[package] declares no name"),
        })?;
    Ok(PackageFacts {
        name: Arc::from(name),
        version: resolve_version(package, manifest_path, workspace)?,
        rust_version: resolve_rust_version(package, workspace),
        edition: resolve_edition(package, manifest_path, workspace)?,
    })
}

fn resolve_edition(
    package: &toml::Table,
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoEdition, RustProjectError> {
    match toml_view::string(package, "edition") {
        Some(text) => parse_edition(text, manifest_path),
        None => inherited_or_default_edition(package, manifest_path, workspace),
    }
}

fn inherited_or_default_edition(
    package: &toml::Table,
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoEdition, RustProjectError> {
    match toml_view::inherits(package, "edition") {
        true => workspace_edition(manifest_path, workspace),
        false => Ok(CargoEdition::default()),
    }
}

fn workspace_edition(
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoEdition, RustProjectError> {
    let declared = workspace
        .package
        .and_then(|table| toml_view::string(table, "edition"));
    match declared {
        Some(text) => parse_edition(text, manifest_path),
        None => Err(RustProjectError::MissingWorkspacePackageEdition {
            path: Box::from(manifest_path),
            workspace: Box::from(workspace.manifest_path),
        }),
    }
}

fn parse_edition(text: &str, manifest_path: &str) -> Result<CargoEdition, RustProjectError> {
    CargoEdition::parse(text).ok_or_else(|| RustProjectError::InvalidPackageEdition {
        path: Box::from(manifest_path),
        edition: Box::from(text),
    })
}

fn resolve_version(
    package: &toml::Table,
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoPackageVersion, RustProjectError> {
    match toml_view::string(package, "version") {
        Some(text) => parse_version(text, manifest_path),
        None => inherited_version(package, manifest_path, workspace),
    }
}

fn inherited_version(
    package: &toml::Table,
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoPackageVersion, RustProjectError> {
    match toml_view::inherits(package, "version") {
        true => workspace_version(manifest_path, workspace),
        false => Err(RustProjectError::MissingPackageVersion {
            path: Box::from(manifest_path),
        }),
    }
}

fn workspace_version(
    manifest_path: &str,
    workspace: &WorkspaceSource<'_>,
) -> Result<CargoPackageVersion, RustProjectError> {
    let declared = workspace
        .package
        .and_then(|table| toml_view::string(table, "version"));
    match declared {
        Some(text) => parse_version(text, manifest_path),
        None => Err(RustProjectError::MissingWorkspacePackageVersion {
            path: Box::from(manifest_path),
            workspace: Box::from(workspace.manifest_path),
        }),
    }
}

fn parse_version(text: &str, manifest_path: &str) -> Result<CargoPackageVersion, RustProjectError> {
    CargoPackageVersion::parse(text).map_err(|source| RustProjectError::InvalidPackageVersion {
        path: Box::from(manifest_path),
        version: Box::from(text),
        source,
    })
}

fn resolve_rust_version(
    package: &toml::Table,
    workspace: &WorkspaceSource<'_>,
) -> Option<Arc<str>> {
    match toml_view::string(package, "rust-version") {
        Some(text) => Some(Arc::from(text)),
        None => inherited_rust_version(package, workspace),
    }
}

fn inherited_rust_version(
    package: &toml::Table,
    workspace: &WorkspaceSource<'_>,
) -> Option<Arc<str>> {
    match toml_view::inherits(package, "rust-version") {
        true => workspace
            .package
            .and_then(|table| toml_view::string(table, "rust-version"))
            .map(Arc::from),
        false => None,
    }
}
