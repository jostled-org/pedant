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

/// The attestation being dumped was just computed, and the snapshot it reads
/// already parsed every selected source, so nothing is ever skipped: the count
/// line is the whole completeness report.
fn emit_completeness(stderr: &mut impl Write, completeness: &AnalysisCompleteness) {
    std::mem::drop(writeln!(
        stderr,
        "analysis: analyzed_files={} skipped_files={}",
        completeness.analyzed_files, completeness.skipped_files
    ));
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
