use std::path::{Path, PathBuf};

use pedant_core::lint::discover_build_script;
use pedant_core::resolve_workspace_members as expand_workspace_members;

use super::dir::{entry_file_type, read_dir_sorted};
use super::error::{
    SupplyChainError, map_workspace_member_error, missing_package_section, path_text,
};
use super::manifest::{CargoManifest, collect_entry_files, read_manifest};

/// A single crate inside the vendored tree, with its analysis entry points.
pub(super) struct VendoredCrate {
    pub(super) dir: PathBuf,
    pub(super) name: Box<str>,
    pub(super) version: Box<str>,
    pub(super) rust_version: Option<Box<str>>,
    pub(super) entry_files: Box<[PathBuf]>,
    pub(super) build_script: Option<PathBuf>,
}

/// Walk the vendor root, expanding each directory into the crates it holds.
pub(super) fn enumerate_vendored_crates(
    vendor_root: &Path,
) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    for entry in read_dir_sorted(vendor_root)? {
        if !entry_file_type(&entry, vendor_root)?.is_dir() {
            continue;
        }
        let dir = entry.path();
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        crates.extend(resolve_vendored_crates(
            &dir,
            &read_manifest(&manifest_path)?,
        )?);
    }
    Ok(crates)
}

/// A vendored directory may be a plain package, a workspace, or both.
fn resolve_vendored_crates(
    root: &Path,
    manifest: &CargoManifest,
) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    if manifest.package.is_some() {
        crates.push(build_vendored_crate(root, manifest)?);
    }
    if let Some(workspace) = &manifest.workspace {
        crates.extend(collect_workspace_member_crates(root, &workspace.members)?);
    }
    Ok(crates)
}

fn collect_workspace_member_crates(
    workspace_root: &Path,
    members: &[Box<str>],
) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    for member_dir in
        expand_workspace_members(workspace_root, members).map_err(map_workspace_member_error)?
    {
        let manifest_path = member_dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let member_manifest = read_manifest(&manifest_path)?;
        if member_manifest.package.is_none() {
            continue;
        }
        crates.push(build_vendored_crate(&member_dir, &member_manifest)?);
    }
    Ok(crates)
}

fn build_vendored_crate(
    crate_dir: &Path,
    manifest: &CargoManifest,
) -> Result<VendoredCrate, SupplyChainError> {
    let package = match &manifest.package {
        Some(package) => package,
        None => return Err(missing_package_section(crate_dir)),
    };
    let entry_files = collect_entry_files(crate_dir, manifest)?;
    let build_script =
        discover_build_script(crate_dir).map_err(|source| SupplyChainError::ReadFile {
            path: path_text(crate_dir),
            source: std::io::Error::other(source.to_string()),
        })?;
    Ok(VendoredCrate {
        dir: crate_dir.to_path_buf(),
        name: package.name.clone().into_boxed_str(),
        version: package.version.clone().into_boxed_str(),
        rust_version: package.rust_version.as_deref().map(Box::<str>::from),
        entry_files,
        build_script,
    })
}
