use std::ffi::OsStr;
use std::path::Path;

use pedant_types::{AttestationContent, CapabilityDiff};

use super::attestation::CrateAttestation;
use super::baseline::{ECOSYSTEM, baseline_file_path, best_prior_baseline, load_baseline};
use super::capability_text::{capability_list, capability_names};
use super::completeness::{
    attestation_completeness_summary, attestation_is_complete, completeness_summary,
};
use super::error::SupplyChainError;
use super::report::{FindingLevel, ReportFinding};

/// Compare one crate against its baseline.
///
/// An exact version match is a pure content check; anything else is a new or
/// upgraded dependency, which is judged on capabilities instead.
pub(super) fn compare_attestation(
    baseline_root: &Path,
    current: &CrateAttestation,
) -> Result<Vec<ReportFinding>, SupplyChainError> {
    let exact_baseline = baseline_file_path(baseline_root, &current.name, &current.version);
    if !exact_baseline.is_file() {
        return compare_new_or_upgraded_dependency(baseline_root, current);
    }

    let baseline = load_baseline(&exact_baseline)?;
    match baseline.source_hash == current.content.source_hash {
        true => Ok(Vec::new()),
        false => Ok(vec![finding(
            FindingLevel::HashMismatch,
            current,
            format!(
                "content changed (baseline: {}... current: {}...)",
                prefix16(&baseline.source_hash),
                prefix16(&current.content.source_hash),
            ),
        )]),
    }
}

fn compare_new_or_upgraded_dependency(
    baseline_root: &Path,
    current: &CrateAttestation,
) -> Result<Vec<ReportFinding>, SupplyChainError> {
    let baseline_dir = baseline_root.join(ECOSYSTEM).join(current.name.as_ref());
    let Some(prior_path) = best_prior_baseline(&baseline_dir, &current.version)? else {
        return Ok(new_dependency_findings(current));
    };

    let prior = load_baseline(&prior_path)?;
    let prior_version = version_from_path(&prior_path);
    if let Some(finding) = incomplete_analysis_finding(&prior, current, prior_version) {
        return Ok(vec![finding]);
    }
    Ok(new_capability_findings(&prior, current, prior_version))
}

/// A crate with no prior baseline: report it, and flag a partial read.
fn new_dependency_findings(current: &CrateAttestation) -> Vec<ReportFinding> {
    let mut findings = vec![finding(
        FindingLevel::NewDependency,
        current,
        format!(
            "capabilities: {}",
            capability_list(&current.content.profile)
        ),
    )];
    if !attestation_is_complete(&current.content) {
        findings.push(finding(
            FindingLevel::AnalysisIncomplete,
            current,
            format!(
                "new dependency analyzed partially ({})",
                attestation_completeness_summary(&current.content)
            ),
        ));
    }
    findings
}

fn new_capability_findings(
    prior: &AttestationContent,
    current: &CrateAttestation,
    prior_version: &str,
) -> Vec<ReportFinding> {
    let diff = CapabilityDiff::compute(&prior.profile, &current.content.profile);
    match diff.new_capabilities.is_empty() {
        true => Vec::new(),
        false => vec![finding(
            FindingLevel::NewCapability,
            current,
            format!(
                "upgraded from {prior_version} — new capabilities: {}",
                capability_names(&diff.new_capabilities)
            ),
        )],
    }
}

/// A capability diff across an incomplete analysis would be noise, so say so.
fn incomplete_analysis_finding(
    prior: &AttestationContent,
    current: &CrateAttestation,
    prior_version: &str,
) -> Option<ReportFinding> {
    match attestation_is_complete(prior) && attestation_is_complete(&current.content) {
        true => None,
        false => Some(finding(
            FindingLevel::AnalysisIncomplete,
            current,
            format!(
                "upgraded from {prior_version} — capability comparison skipped ({})",
                completeness_summary(prior, &current.content)
            ),
        )),
    }
}

fn finding(level: FindingLevel, current: &CrateAttestation, detail: String) -> ReportFinding {
    ReportFinding {
        level,
        ecosystem: ECOSYSTEM,
        name: current.name.clone(),
        version: current.version.clone(),
        detail: detail.into_boxed_str(),
    }
}

fn version_from_path(path: &Path) -> &str {
    path.file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown")
}

fn prefix16(hash: &str) -> &str {
    &hash[..hash.len().min(16)]
}
