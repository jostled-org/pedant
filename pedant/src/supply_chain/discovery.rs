use std::path::{Path, PathBuf};

use pedant_core::resolution::rust::{ResolutionLimits, RustProject};

use super::dir::{entry_file_type, read_dir_sorted};
use super::error::{SupplyChainError, path_text};

/// Every directory under the vendor root that carries a `Cargo.toml`.
///
/// Only the paths are collected. The caller indexes one directory at a time and
/// drops the project before the next, so a vendor tree of several hundred
/// crates never holds more than one project index live.
pub(super) fn vendored_project_dirs(
    vendor_root: &Path,
) -> Result<Box<[PathBuf]>, SupplyChainError> {
    let mut dirs = Vec::new();
    for entry in read_dir_sorted(vendor_root)? {
        if !entry_file_type(&entry, vendor_root)?.is_dir() {
            continue;
        }
        let dir = entry.path();
        if !dir.join("Cargo.toml").is_file() {
            continue;
        }
        dirs.push(dir);
    }
    Ok(dirs.into_boxed_slice())
}

/// Index one vendored directory as a Cargo project.
///
/// A vendored directory may be a plain package, a workspace, or both. The
/// shared Cargo project authority answers which packages it publishes, resolves
/// each one's direct or workspace-inherited version, and issues the target
/// identities the attestation snapshots.
///
/// A directory that publishes no package would be attested as nothing at all,
/// so it is refused rather than skipped.
pub(super) fn load_vendored_project(root: &Path) -> Result<RustProject, SupplyChainError> {
    let project = RustProject::load(root, ResolutionLimits::default())?;
    let publishes = project.workspace_members().next().is_some();
    match publishes {
        true => Ok(project),
        false => Err(SupplyChainError::PublishesNothing {
            path: path_text(root),
        }),
    }
}
