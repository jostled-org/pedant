//! The parent's half of the proof-only parse/projection receipt.
//!
//! The feature-enabled child writes what its production loaders did with each
//! selected source. This reads that document back and holds it to a model the
//! parent states independently: the exact selected paths, the SHA-256 the
//! parent computes from the fixture on disk, and exactly one parse and one
//! projection each. A projection that reparsed instead of reusing the stored
//! `FileIr` reports two parses and fails here, whichever route it reparsed
//! through: `pedant-core` records every parse at the one entry into `syn`.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The environment variable the child reads its destination from.
pub(crate) const RECEIPT_ENV: &str = "PEDANT_RESOLUTION_PROBE_RECEIPT";

/// The only receipt schema this parent accepts.
const RECEIPT_VERSION: u32 = 1;

#[derive(Deserialize)]
struct Receipt {
    receipt_version: u32,
    packages: Box<[PackageRecord]>,
}

#[derive(Deserialize)]
struct PackageRecord {
    name: Box<str>,
    version: Box<str>,
    files: Box<[FileRecord]>,
}

#[derive(Deserialize)]
struct FileRecord {
    path: Box<str>,
    digest: Box<str>,
    parses: usize,
    projections: usize,
}

/// One package the parent requires the receipt to describe exactly.
pub(crate) struct Expected<'a> {
    /// The attested package name.
    pub(crate) name: &'a str,
    /// The attested package version.
    pub(crate) version: &'a str,
    /// Every selected source: the path an attestation names, and the file on
    /// disk the parent hashes to check the child's digest.
    pub(crate) files: &'a [(&'a str, PathBuf)],
}

/// Read the receipt and hold it to `expected`, then delete it.
///
/// Deleting here keeps the receipt from outliving the run that produced it: a
/// later run reading a stale document would prove nothing about itself.
pub(crate) fn consume(receipt_path: &Path, expected: &Expected<'_>) -> Result<(), String> {
    let outcome = validate(receipt_path, expected);
    let removed = std::fs::remove_file(receipt_path).map_err(|error| {
        format!(
            "the receipt at {} is not removable: {error}",
            receipt_path.display()
        )
    });
    outcome.and(removed)
}

fn validate(receipt_path: &Path, expected: &Expected<'_>) -> Result<(), String> {
    let raw = std::fs::read_to_string(receipt_path)
        .map_err(|error| format!("no receipt at {}: {error}", receipt_path.display()))?;
    let receipt: Receipt = serde_json::from_str(&raw)
        .map_err(|error| format!("the receipt is not valid JSON: {error} in {raw}"))?;
    if receipt.receipt_version != RECEIPT_VERSION {
        return Err(format!(
            "the receipt states version {} rather than {RECEIPT_VERSION}",
            receipt.receipt_version
        ));
    }
    let package = single_package(&receipt.packages)?;
    check_identity(package, expected)?;
    check_files(&package.files, expected.files)
}

fn single_package(packages: &[PackageRecord]) -> Result<&PackageRecord, String> {
    match packages {
        [package] => Ok(package),
        other => Err(format!(
            "the receipt describes {} packages rather than one",
            other.len()
        )),
    }
}

fn check_identity(package: &PackageRecord, expected: &Expected<'_>) -> Result<(), String> {
    match (
        package.name.as_ref() == expected.name,
        package.version.as_ref() == expected.version,
    ) {
        (true, true) => Ok(()),
        _ => Err(format!(
            "the receipt names {}@{} rather than {}@{}",
            package.name, package.version, expected.name, expected.version
        )),
    }
}

fn check_files(recorded: &[FileRecord], expected: &[(&str, PathBuf)]) -> Result<(), String> {
    let names = recorded
        .iter()
        .map(|file| file.path.as_ref())
        .collect::<Vec<_>>();
    let wanted = expected.iter().map(|(path, _)| *path).collect::<Vec<_>>();
    if names != wanted {
        return Err(format!(
            "the receipt selected {names:?} rather than {wanted:?}"
        ));
    }
    for (file, (path, on_disk)) in recorded.iter().zip(expected) {
        check_file(file, path, on_disk)?;
    }
    Ok(())
}

fn check_file(file: &FileRecord, path: &str, on_disk: &Path) -> Result<(), String> {
    let expected_digest = sha256_hex(on_disk)?;
    match (
        file.digest.as_ref() == expected_digest.as_str(),
        file.parses,
        file.projections,
    ) {
        (true, 1, 1) => Ok(()),
        (digest_matches, parses, projections) => Err(format!(
            "{path}: digest_matches={digest_matches} parses={parses} projections={projections}; \
             exactly one parse and one projection per selected source are required"
        )),
    }
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("the fixture at {} is unreadable: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
