use std::path::Path;
use std::time::SystemTime;

#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::rust::ResolutionProbe;
use pedant_core::resolution::rust::{RustPackage, RustProject};
use pedant_types::{AnalysisCompleteness, AnalysisTier, AttestationContent, CapabilityProfile};

use super::discovery::{load_vendored_project, vendored_project_dirs};
use super::error::SupplyChainError;
use super::selection::PackageSnapshots;
use super::source_input::{SourceFileInput, SourceInputs, collect_source_inputs};

const SPEC_VERSION: &str = "0.1.0";

/// One crate's attested content, plus the file list backing `--debug-package`.
pub(super) struct CrateAttestation {
    pub(super) name: Box<str>,
    pub(super) version: Box<str>,
    pub(super) content: AttestationContent,
    pub(super) source_files: Box<[SourceFileInput]>,
}

/// Attest every package the vendored tree publishes.
///
/// The whole set is built before a caller may write anything, so one crate's
/// incomplete closure aborts the command with no baseline touched.
pub(super) fn collect_attestations(
    vendor_root: &Path,
) -> Result<Box<[CrateAttestation]>, SupplyChainError> {
    let dirs = vendored_project_dirs(vendor_root)?;
    #[cfg(feature = "resolution-test-support")]
    let mut ledger = super::receipt::Ledger::open();
    let mut attestations = Vec::new();
    for dir in &dirs {
        // The project index drops at the end of this iteration, so the vendor
        // tree costs one live index rather than one per vendored crate.
        let project = load_vendored_project(dir)?;
        for package in project.workspace_members() {
            // The probe is installed per package so the observed paths stay
            // unambiguous: two vendored packages both name `src/lib.rs`, and
            // one shared probe could not say which of them a parse belonged to.
            #[cfg(feature = "resolution-test-support")]
            let probe = ResolutionProbe::install();
            let attestation = attest_package(&project, package)?;
            #[cfg(feature = "resolution-test-support")]
            ledger.record(&probe, package.relative_directory(), &attestation);
            attestations.push(attestation);
        }
    }
    #[cfg(feature = "resolution-test-support")]
    ledger.finish()?;
    Ok(attestations.into_boxed_slice())
}

fn attest_package(
    project: &RustProject,
    package: &RustPackage,
) -> Result<CrateAttestation, SupplyChainError> {
    let snapshots = PackageSnapshots::take(project, package)?;
    let selected = snapshots.selected()?;
    // Destructured so the profile and completeness move into the content
    // rather than being cloned out of a borrow.
    let SourceInputs {
        source_hash,
        files,
        profile,
        completeness,
    } = collect_source_inputs(&selected);
    Ok(CrateAttestation {
        name: Box::from(package.name()),
        version: Box::from(package.version().as_str()),
        content: attestation_content(package, source_hash, profile, completeness)?,
        source_files: files,
    })
}

fn attestation_content(
    package: &RustPackage,
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
        crate_name: Box::from(package.name()),
        crate_version: Box::from(package.version().as_str()),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp,
        analysis_completeness: Some(completeness),
        rust_version: package.rust_version().map(Box::<str>::from),
        profile,
    })
}
