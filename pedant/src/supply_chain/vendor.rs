use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::{TempDir, tempdir};

use super::error::{SupplyChainError, path_text};

/// Owns the temp directory holding the vendored crate tree.
///
/// Dropping this removes the tree, so it must outlive every read of
/// [`VendorContext::vendor_root`].
pub(super) struct VendorContext {
    tempdir: TempDir,
}

impl VendorContext {
    pub(super) fn vendor_root(&self) -> PathBuf {
        self.tempdir.path().join("cargo")
    }
}

/// Anchor on the current directory, requiring a committed lockfile.
pub(super) fn current_workspace_root() -> Result<PathBuf, SupplyChainError> {
    let cwd = std::env::current_dir().map_err(SupplyChainError::CurrentDir)?;
    let lockfile = cwd.join("Cargo.lock");
    match lockfile.is_file() {
        true => Ok(cwd),
        false => Err(SupplyChainError::MissingLockfile(path_text(&cwd))),
    }
}

pub(super) fn vendor_cargo_deps(workspace_root: &Path) -> Result<VendorContext, SupplyChainError> {
    let context = VendorContext {
        tempdir: tempdir().map_err(SupplyChainError::TempDir)?,
    };
    let output = Command::new("cargo")
        .arg("vendor")
        .arg(context.vendor_root())
        .arg("--locked")
        .arg("--quiet")
        .current_dir(workspace_root)
        .output()
        .map_err(SupplyChainError::CargoVendorSpawn)?;
    match output.status.success() {
        true => Ok(context),
        false => Err(SupplyChainError::CargoVendor(
            String::from_utf8_lossy(&output.stderr)
                .trim()
                .to_owned()
                .into_boxed_str(),
        )),
    }
}
