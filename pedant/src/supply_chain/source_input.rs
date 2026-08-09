use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::capabilities::detect_capabilities;
use pedant_core::hash::{compute_source_hash, encode_hex_digest};
use pedant_types::{AnalysisCompleteness, CapabilityFinding, CapabilityProfile, ExecutionContext};

use super::selection::SelectedSource;

/// One source file's identity, as recorded in an attestation.
pub(super) struct SourceFileInput {
    pub(super) path: Arc<str>,
    pub(super) bytes: usize,
    pub(super) digest: Box<str>,
}

/// Everything one crate's selected sources contribute to its attestation.
pub(super) struct SourceInputs {
    pub(super) source_hash: Box<str>,
    pub(super) files: Box<[SourceFileInput]>,
    pub(super) profile: CapabilityProfile,
    pub(super) completeness: AnalysisCompleteness,
}

/// Hash and project every selected source of one crate.
///
/// The snapshot already read the exact bytes and parsed them once, so nothing
/// here opens a file or reparses; projection over a stored `FileIr` cannot
/// fail, which is why the reported analysis is always complete.
pub(super) fn collect_source_inputs(selected: &[SelectedSource<'_>]) -> SourceInputs {
    SourceInputs {
        source_hash: hashed_source(selected),
        files: source_file_inputs(selected),
        profile: projected_profile(selected),
        completeness: complete_analysis(selected),
    }
}

fn hashed_source(selected: &[SelectedSource<'_>]) -> Box<str> {
    let sources = selected
        .iter()
        .map(|selected| (Arc::clone(&selected.path), selected.source.text()))
        .collect::<BTreeMap<_, _>>();
    compute_source_hash(&sources)
}

fn source_file_inputs(selected: &[SelectedSource<'_>]) -> Box<[SourceFileInput]> {
    selected
        .iter()
        .map(|selected| SourceFileInput {
            path: Arc::clone(&selected.path),
            bytes: selected.source.text().len(),
            digest: encode_hex_digest(selected.source.digest()),
        })
        .collect()
}

/// Union every selected source's capabilities from its stored IR.
fn projected_profile(selected: &[SelectedSource<'_>]) -> CapabilityProfile {
    let mut findings = Vec::new();
    for selected in selected {
        let profile = detect_capabilities(selected.source.ir(), execution_context(selected));
        findings.extend(rebased(profile, &selected.path));
    }
    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

/// A source only the build script reaches runs before the consumer's own code.
fn execution_context(selected: &SelectedSource<'_>) -> Option<ExecutionContext> {
    selected.build_hook.then_some(ExecutionContext::BuildHook)
}

/// Findings name the crate-relative path the attestation records, not the
/// project-relative path the snapshot indexed the source under.
fn rebased(profile: CapabilityProfile, path: &Arc<str>) -> Vec<CapabilityFinding> {
    let mut findings = profile.findings.into_vec();
    for finding in &mut findings {
        finding.location.file = Arc::clone(path);
    }
    findings
}

fn complete_analysis(selected: &[SelectedSource<'_>]) -> AnalysisCompleteness {
    AnalysisCompleteness {
        analyzed_files: selected.len(),
        skipped_files: 0,
        skipped_paths: Box::new([]),
        skipped_details: Box::new([]),
    }
}
