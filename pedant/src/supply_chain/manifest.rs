use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::dir::{entry_file_type, read_dir_sorted};
use super::error::{SupplyChainError, missing_package_section, path_text};

#[derive(Deserialize, Default)]
pub(super) struct CargoManifest {
    pub(super) package: Option<CargoPackage>,
    pub(super) workspace: Option<WorkspaceSection>,
    pub(super) lib: Option<TargetSection>,
    #[serde(default, rename = "bin")]
    pub(super) bins: Vec<TargetSection>,
}

#[derive(Deserialize)]
pub(super) struct CargoPackage {
    pub(super) name: String,
    pub(super) version: String,
    #[serde(default = "default_true")]
    pub(super) autobins: bool,
    #[serde(default, rename = "rust-version")]
    pub(super) rust_version: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct WorkspaceSection {
    #[serde(default)]
    pub(super) members: Box<[Box<str>]>,
}

#[derive(Deserialize, Default)]
pub(super) struct TargetSection {
    pub(super) path: Option<String>,
}

fn default_true() -> bool {
    true
}

pub(super) fn read_manifest(path: &Path) -> Result<CargoManifest, SupplyChainError> {
    let raw = fs::read_to_string(path).map_err(|source| SupplyChainError::ReadFile {
        path: path_text(path),
        source,
    })?;
    toml::from_str(&raw).map_err(|source| SupplyChainError::ManifestParse {
        path: path_text(path),
        source,
    })
}

/// Resolve every compilation entry point the manifest declares or implies.
pub(super) fn collect_entry_files(
    crate_dir: &Path,
    manifest: &CargoManifest,
) -> Result<Box<[PathBuf]>, SupplyChainError> {
    let package = match &manifest.package {
        Some(package) => package,
        None => return Err(missing_package_section(crate_dir)),
    };
    let mut entries = Vec::new();

    push_lib_entry(crate_dir, manifest, &mut entries);
    for bin in &manifest.bins {
        if let Some(path) = bin.path.as_deref() {
            push_entry_file(crate_dir, Path::new(path), &mut entries);
        }
    }
    push_bin_entries(crate_dir, package.autobins, &mut entries)?;

    entries.sort();
    entries.dedup();
    Ok(entries.into_boxed_slice())
}

fn push_lib_entry(crate_dir: &Path, manifest: &CargoManifest, entries: &mut Vec<PathBuf>) {
    let default_lib = crate_dir.join("src/lib.rs");
    match manifest.lib.as_ref().and_then(|lib| lib.path.as_deref()) {
        Some(path) => push_entry_file(crate_dir, Path::new(path), entries),
        None if default_lib.is_file() => entries.push(default_lib),
        None => {}
    }
}

fn push_bin_entries(
    crate_dir: &Path,
    autobins: bool,
    entries: &mut Vec<PathBuf>,
) -> Result<(), SupplyChainError> {
    let default_bin = crate_dir.join("src/main.rs");
    match (autobins, default_bin.is_file()) {
        (true, true) => {
            entries.push(default_bin);
            collect_autobin_entries(crate_dir, entries)
        }
        (true, false) => collect_autobin_entries(crate_dir, entries),
        (false, _) => Ok(()),
    }
}

fn push_entry_file(crate_dir: &Path, relative_path: &Path, entries: &mut Vec<PathBuf>) {
    let absolute = crate_dir.join(relative_path);
    if absolute.is_file() {
        entries.push(absolute);
    }
}

/// Pick up the implicit `src/bin/*.rs` and `src/bin/*/main.rs` targets.
fn collect_autobin_entries(
    crate_dir: &Path,
    entries: &mut Vec<PathBuf>,
) -> Result<(), SupplyChainError> {
    let bin_dir = crate_dir.join("src/bin");
    if !bin_dir.is_dir() {
        return Ok(());
    }
    for entry in read_dir_sorted(&bin_dir)? {
        let path = entry.path();
        let file_type = entry_file_type(&entry, &bin_dir)?;
        let main_rs = path.join("main.rs");
        match (file_type.is_file(), file_type.is_dir()) {
            (true, _) if path.extension() == Some(OsStr::new("rs")) => entries.push(path),
            (_, true) if main_rs.is_file() => entries.push(main_rs),
            _ => {}
        }
    }
    Ok(())
}
