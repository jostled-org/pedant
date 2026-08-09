use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_types::AttestationContent;
use semver::Version;

use super::attestation::CrateAttestation;
use super::dir::{entry_file_type, read_dir_sorted};
use super::error::{SupplyChainError, path_text, write_error};

/// The only ecosystem this baseline store covers; also the first path segment.
pub(super) const ECOSYSTEM: &str = "cargo";

/// Baselines live at `<root>/cargo/<name>/<version>.json`.
pub(super) fn baseline_file_path(baseline_root: &Path, name: &str, version: &str) -> PathBuf {
    baseline_root
        .join(ECOSYSTEM)
        .join(name)
        .join(format!("{version}.json"))
}

pub(super) fn load_baseline(path: &Path) -> Result<AttestationContent, SupplyChainError> {
    let raw = fs::read_to_string(path).map_err(|source| SupplyChainError::ReadFile {
        path: path_text(path),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| SupplyChainError::BaselineParse {
        path: path_text(path),
        source,
    })
}

pub(super) fn write_baseline_file(
    baseline_root: &Path,
    attestation: &CrateAttestation,
) -> Result<(), SupplyChainError> {
    let path = baseline_file_path(baseline_root, &attestation.name, &attestation.version);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(write_error(parent))?;
    }
    let json = serde_json::to_vec_pretty(&attestation.content).map_err(|source| {
        SupplyChainError::BaselineSerialize {
            path: path_text(&path),
            source,
        }
    })?;
    fs::write(&path, json).map_err(write_error(&path))
}

/// Drop baselines for crates that left the tree, and versions that moved on.
pub(super) fn prune_stale_baselines(
    baseline_root: &Path,
    attestations: &[CrateAttestation],
) -> Result<(), SupplyChainError> {
    let cargo_root = baseline_root.join(ECOSYSTEM);
    if !cargo_root.is_dir() {
        return Ok(());
    }

    // A crate may resolve to several versions at once (a diamond dependency on
    // incompatible semver), so each name maps to the set of its current
    // versions. Keying on name alone would drop every version but one.
    let mut current_versions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for attestation in attestations {
        current_versions
            .entry(attestation.name.as_ref())
            .or_default()
            .insert(attestation.version.as_ref());
    }

    for crate_entry in read_dir_sorted(&cargo_root)? {
        if !entry_file_type(&crate_entry, &cargo_root)?.is_dir() {
            continue;
        }
        prune_crate_dir(&crate_entry.path(), &current_versions)?;
    }

    Ok(())
}

fn prune_crate_dir(
    crate_dir: &Path,
    current_versions: &BTreeMap<&str, BTreeSet<&str>>,
) -> Result<(), SupplyChainError> {
    let crate_name = crate_dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let Some(current) = current_versions.get(crate_name) else {
        return remove_dir_all(crate_dir);
    };

    for version_entry in read_dir_sorted(crate_dir)? {
        let version_path = version_entry.path();
        match stale_baseline_version(&version_path, current) {
            true => remove_file(&version_path)?,
            false => continue,
        }
    }

    match read_dir_sorted(crate_dir)?.is_empty() {
        true => remove_dir(crate_dir),
        false => Ok(()),
    }
}

/// A `<version>.json` file is stale when it names a version we no longer use.
fn stale_baseline_version(version_path: &Path, current: &BTreeSet<&str>) -> bool {
    if version_path.extension() != Some(OsStr::new("json")) {
        return false;
    }
    let version = version_path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    !current.contains(version)
}

fn remove_dir_all(path: &Path) -> Result<(), SupplyChainError> {
    fs::remove_dir_all(path).map_err(delete_error(path))
}

fn remove_dir(path: &Path) -> Result<(), SupplyChainError> {
    fs::remove_dir(path).map_err(delete_error(path))
}

fn remove_file(path: &Path) -> Result<(), SupplyChainError> {
    fs::remove_file(path).map_err(delete_error(path))
}

fn delete_error(path: &Path) -> impl Fn(std::io::Error) -> SupplyChainError {
    let path = path_text(path);
    move |source| SupplyChainError::DeletePath {
        path: path.clone(),
        source,
    }
}

/// The newest baseline strictly older than `current_version`, if any.
///
/// Unparseable versions sort by filename and are only chosen when the current
/// version itself does not parse as semver.
pub(super) fn best_prior_baseline(
    baseline_dir: &Path,
    current_version: &str,
) -> Result<Option<PathBuf>, SupplyChainError> {
    if !baseline_dir.is_dir() {
        return Ok(None);
    }

    let current = Version::parse(current_version).ok();
    let mut candidates = baseline_candidates(baseline_dir)?;
    candidates.sort_by(|(left_version, left_path), (right_version, right_path)| {
        match (left_version, right_version) {
            (Some(left), Some(right)) => left.cmp(right),
            _ => left_path.cmp(right_path),
        }
    });

    for (version, path) in candidates.into_iter().rev() {
        match (&current, version) {
            (Some(current), Some(version)) if version < *current => return Ok(Some(path)),
            (None, _) => return Ok(Some(path)),
            _ => {}
        }
    }
    Ok(None)
}

fn baseline_candidates(
    baseline_dir: &Path,
) -> Result<Vec<(Option<Version>, PathBuf)>, SupplyChainError> {
    let mut candidates = Vec::new();
    for entry in read_dir_sorted(baseline_dir)? {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or_default();
        candidates.push((Version::parse(stem).ok(), path));
    }
    Ok(candidates)
}
