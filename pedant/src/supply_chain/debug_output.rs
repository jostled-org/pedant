use std::collections::BTreeSet;
use std::io::Write;

use pedant_types::AnalysisCompleteness;

use super::attestation::CrateAttestation;
use super::source_input::SourceFileInput;

/// Dump one crate's attestation inputs for `--debug-package`.
pub(super) fn emit_debug_package(stderr: &mut impl Write, attestation: &CrateAttestation) {
    let content = &attestation.content;
    std::mem::drop(writeln!(
        stderr,
        "debug-package: {}@{}",
        attestation.name, attestation.version
    ));
    std::mem::drop(writeln!(stderr, "source_hash: {}", content.source_hash));
    if let Some(version) = content.rust_version.as_deref() {
        std::mem::drop(writeln!(stderr, "rust-version: {version}"));
    }
    if let Some(completeness) = content.analysis_completeness.as_ref() {
        emit_completeness(stderr, completeness);
    }
    emit_source_files(stderr, &attestation.source_files);
}

fn emit_completeness(stderr: &mut impl Write, completeness: &AnalysisCompleteness) {
    std::mem::drop(writeln!(
        stderr,
        "analysis: analyzed_files={} skipped_files={}",
        completeness.analyzed_files, completeness.skipped_files
    ));
    for skipped in &completeness.skipped_details {
        std::mem::drop(writeln!(
            stderr,
            "skipped: {} error: {}",
            skipped.path, skipped.error
        ));
    }
    emit_undetailed_skips(stderr, completeness);
}

/// Skipped paths without a matching detail entry still deserve a line.
fn emit_undetailed_skips(stderr: &mut impl Write, completeness: &AnalysisCompleteness) {
    let detailed: BTreeSet<&str> = completeness
        .skipped_details
        .iter()
        .map(|detail| detail.path.as_ref())
        .collect();
    for skipped_path in completeness
        .skipped_paths
        .iter()
        .filter(|path| !detailed.contains(path.as_ref()))
    {
        std::mem::drop(writeln!(stderr, "skipped: {skipped_path}"));
    }
}

fn emit_source_files(stderr: &mut impl Write, source_files: &[SourceFileInput]) {
    for source_file in source_files {
        std::mem::drop(writeln!(
            stderr,
            "file: {} bytes={} sha256={}",
            source_file.path, source_file.bytes, source_file.digest
        ));
    }
}
