use std::path::Path;
use std::time::SystemTime;

use pedant_types::{AnalysisCompleteness, AnalysisTier, AttestationContent, CapabilityProfile};

use super::discovery::{VendoredCrate, enumerate_vendored_crates};
use super::error::SupplyChainError;
use super::module_graph::collect_reachable_sources;
use super::source_input::{SourceFileInput, SourceInputs, collect_source_inputs};

const SPEC_VERSION: &str = "0.1.0";

/// One crate's attested content, plus the file list backing `--debug-package`.
pub(super) struct CrateAttestation {
    pub(super) name: Box<str>,
    pub(super) version: Box<str>,
    pub(super) content: AttestationContent,
    pub(super) source_files: Box<[SourceFileInput]>,
}

pub(super) fn collect_attestations(
    vendor_root: &Path,
) -> Result<Vec<CrateAttestation>, SupplyChainError> {
    enumerate_vendored_crates(vendor_root)?
        .into_iter()
        .map(|crate_info| build_attestation_for_crate(&crate_info))
        .collect()
}

fn build_attestation_for_crate(
    crate_info: &VendoredCrate,
) -> Result<CrateAttestation, SupplyChainError> {
    let reachable = collect_reachable_sources(
        &crate_info.dir,
        &crate_info.entry_files,
        crate_info.build_script.as_deref(),
    )?;
    // Destructured so the profile and completeness move into the content
    // rather than being cloned out of a borrow.
    let SourceInputs {
        source_hash,
        files,
        profile,
        completeness,
    } = collect_source_inputs(crate_info, &reachable)?;
    Ok(CrateAttestation {
        name: crate_info.name.clone(),
        version: crate_info.version.clone(),
        content: attestation_content(crate_info, source_hash, profile, completeness)?,
        source_files: files,
    })
}

fn attestation_content(
    crate_info: &VendoredCrate,
    source_hash: Box<str>,
    profile: CapabilityProfile,
    completeness: AnalysisCompleteness,
) -> Result<AttestationContent, SupplyChainError> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(SupplyChainError::Timestamp)?;
    Ok(AttestationContent {
        spec_version: Box::from(SPEC_VERSION),
        source_hash,
        crate_name: crate_info.name.clone(),
        crate_version: crate_info.version.clone(),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp,
        analysis_completeness: Some(completeness),
        rust_version: crate_info.rust_version.clone(),
        profile,
    })
}
