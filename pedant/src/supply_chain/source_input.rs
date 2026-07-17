use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use pedant_core::check_config::CheckConfig;
use pedant_core::hash::{compute_source_hash, encode_hex_digest};
use pedant_core::lint::{analyze, analyze_build_script};
use pedant_types::{AnalysisCompleteness, CapabilityProfile, SkippedAnalysis};
use sha2::{Digest, Sha256};

use super::discovery::VendoredCrate;
use super::error::{SupplyChainError, path_text};

/// One source file's identity, as recorded in an attestation.
pub(super) struct SourceFileInput {
    pub(super) path: Arc<str>,
    pub(super) bytes: usize,
    pub(super) digest: Box<str>,
}

/// A source file plus its text, held only while an attestation is built.
struct CollectedSourceInput {
    path: Arc<str>,
    source: Box<str>,
    bytes: usize,
    digest: Box<str>,
    is_build_script: bool,
}

/// Everything derived from one crate's reachable sources in a single read pass.
pub(super) struct SourceInputs {
    pub(super) source_hash: Box<str>,
    pub(super) files: Box<[SourceFileInput]>,
    pub(super) profile: CapabilityProfile,
    pub(super) completeness: AnalysisCompleteness,
}

/// Read, hash, and analyze every reachable source file of a crate.
pub(super) fn collect_source_inputs(
    crate_info: &VendoredCrate,
    files: &[Arc<str>],
) -> Result<SourceInputs, SupplyChainError> {
    let collected = read_source_inputs(crate_info, files)?;
    let (profile, completeness) = analyze_source_inputs(&collected);
    Ok(SourceInputs {
        source_hash: compute_hashed_source(&collected),
        files: source_file_inputs(&collected),
        profile,
        completeness,
    })
}

fn read_source_inputs(
    crate_info: &VendoredCrate,
    files: &[Arc<str>],
) -> Result<Vec<CollectedSourceInput>, SupplyChainError> {
    let mut collected = Vec::with_capacity(files.len());
    for relative_path in files {
        let disk_path = crate_info.dir.join(relative_path.trim_start_matches("./"));
        let source =
            fs::read_to_string(&disk_path).map_err(|source| SupplyChainError::ReadFile {
                path: path_text(&disk_path),
                source,
            })?;
        collected.push(CollectedSourceInput {
            path: Arc::clone(relative_path),
            bytes: source.len(),
            digest: sha256_hex(source.as_bytes()),
            is_build_script: is_build_script_path(&disk_path, crate_info.build_script.as_deref()),
            source: source.into_boxed_str(),
        });
    }
    Ok(collected)
}

fn compute_hashed_source(collected_sources: &[CollectedSourceInput]) -> Box<str> {
    let sources = collected_sources
        .iter()
        .map(|source| (Arc::clone(&source.path), source.source.as_ref()))
        .collect::<BTreeMap<_, _>>();
    compute_source_hash(&sources)
}

fn source_file_inputs(collected_sources: &[CollectedSourceInput]) -> Box<[SourceFileInput]> {
    collected_sources
        .iter()
        .map(|source| SourceFileInput {
            path: Arc::clone(&source.path),
            bytes: source.bytes,
            digest: source.digest.clone(),
        })
        .collect()
}

/// Union every file's capabilities, recording files the parser could not read.
fn analyze_source_inputs(
    collected_sources: &[CollectedSourceInput],
) -> (CapabilityProfile, AnalysisCompleteness) {
    let mut findings = Vec::new();
    let mut analyzed_files = 0;
    let mut skipped_details = Vec::new();

    for source in collected_sources {
        match analyze_supply_chain_source(&source.path, &source.source, source.is_build_script) {
            Ok(capabilities) => {
                analyzed_files += 1;
                findings.extend(capabilities.findings.into_vec());
            }
            Err(error) => skipped_details.push(SkippedAnalysis {
                path: Box::from(source.path.as_ref()),
                error,
            }),
        }
    }

    let skipped_paths = skipped_details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<Vec<_>>();

    (
        CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
        AnalysisCompleteness {
            analyzed_files,
            skipped_files: skipped_paths.len(),
            skipped_paths: skipped_paths.into_boxed_slice(),
            skipped_details: skipped_details.into_boxed_slice(),
        },
    )
}

fn analyze_supply_chain_source(
    relative_path: &str,
    source: &str,
    is_build_script: bool,
) -> Result<CapabilityProfile, Box<str>> {
    let result = match is_build_script {
        true => analyze_build_script(relative_path, source, &CheckConfig::default(), None),
        false => analyze(relative_path, source, &CheckConfig::default(), None),
    };
    match result {
        Ok(result) => Ok(result.capabilities),
        Err(error) => Err(error.to_string().into_boxed_str()),
    }
}

fn is_build_script_path(path: &Path, build_script: Option<&Path>) -> bool {
    let Some(build_script) = build_script else {
        return false;
    };
    match (path.canonicalize(), build_script.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => path == build_script,
    }
}

fn sha256_hex(bytes: &[u8]) -> Box<str> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_hex_digest(&hasher.finalize())
}
