//! Proof-only receipt of what the production loaders did while attesting.
//!
//! Compiled solely by `resolution-test-support` and written solely when a test
//! names a destination, so an ordinary binary carries neither the probe nor the
//! branch that reads the environment. The receipt exists to falsify a second
//! parse: a projection that reparsed instead of reusing the stored `FileIr`
//! shows its source twice in the parse count, whichever route it reparsed
//! through, because one owner in `pedant-core` records every parse.

use std::path::{Path, PathBuf};

use pedant_core::resolution::ResolutionProbe;
use serde::Serialize;

use super::attestation::CrateAttestation;
use super::error::{SupplyChainError, write_error};
use super::selection::crate_relative;

/// The test-owned path this receipt is written to.
const RECEIPT_PATH: &str = "PEDANT_RESOLUTION_PROBE_RECEIPT";

/// Schema version of the written receipt.
const RECEIPT_VERSION: u32 = 1;

/// One selected source and what the production loaders did with it.
#[derive(Serialize)]
struct FileRecord {
    path: Box<str>,
    digest: Box<str>,
    parses: usize,
    projections: usize,
}

/// One attested package's observed counters.
#[derive(Serialize)]
struct PackageRecord {
    name: Box<str>,
    version: Box<str>,
    files: Box<[FileRecord]>,
}

/// The written document.
#[derive(Serialize)]
struct Receipt {
    receipt_version: u32,
    packages: Box<[PackageRecord]>,
}

/// Collects one receipt across every attested package.
pub(super) struct Ledger {
    destination: Option<PathBuf>,
    packages: Vec<PackageRecord>,
}

impl Ledger {
    /// Read the destination a test supplied, if it supplied one.
    pub(super) fn open() -> Self {
        Self {
            destination: std::env::var_os(RECEIPT_PATH).map(PathBuf::from),
            packages: Vec::new(),
        }
    }

    /// Record what `probe` saw while `attestation` was built.
    pub(super) fn record(
        &mut self,
        probe: &ResolutionProbe,
        directory: &str,
        attestation: &CrateAttestation,
    ) {
        if self.destination.is_none() {
            return;
        }
        let parses = probe.parses();
        let projections = probe.capability_projections();
        self.packages.push(PackageRecord {
            name: attestation.name.clone(),
            version: attestation.version.clone(),
            files: attestation
                .source_files
                .iter()
                .map(|file| FileRecord {
                    path: Box::from(file.path.as_ref()),
                    digest: file.digest.clone(),
                    parses: count(&parses, directory, &file.path),
                    projections: count(&projections, directory, &file.path),
                })
                .collect(),
        });
    }

    /// Write the receipt where a reader can never observe a partial document.
    pub(super) fn finish(self) -> Result<(), SupplyChainError> {
        let Some(destination) = self.destination else {
            return Ok(());
        };
        let receipt = Receipt {
            receipt_version: RECEIPT_VERSION,
            packages: self.packages.into_boxed_slice(),
        };
        let json = serde_json::to_vec_pretty(&receipt).map_err(|source| {
            SupplyChainError::ReceiptSerialize {
                path: super::error::path_text(&destination),
                source,
            }
        })?;
        let staging = staging_path(&destination);
        std::fs::write(&staging, json).map_err(write_error(&staging))?;
        std::fs::rename(&staging, &destination).map_err(write_error(&destination))
    }
}

/// Stage beside the destination so the rename that publishes it is atomic.
fn staging_path(destination: &Path) -> PathBuf {
    let mut staging = destination.as_os_str().to_owned();
    staging.push(".partial");
    PathBuf::from(staging)
}

/// How many observed production events named one crate-relative source.
fn count(observed: &[Box<str>], directory: &str, path: &str) -> usize {
    observed
        .iter()
        .filter(|event| names_source(event, directory, path))
        .count()
}

fn names_source(observed: &str, directory: &str, path: &str) -> bool {
    crate_relative(observed, directory)
        .is_some_and(|relative| path.strip_prefix("./") == Some(relative))
}
