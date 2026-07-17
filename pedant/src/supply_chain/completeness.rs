use std::fmt::Write;

use pedant_types::{AnalysisCompleteness, AttestationContent};

/// An attestation is complete only when every source file parsed.
pub(super) fn attestation_is_complete(attestation: &AttestationContent) -> bool {
    attestation
        .analysis_completeness
        .as_ref()
        .is_some_and(AnalysisCompleteness::is_complete)
}

pub(super) fn completeness_summary(
    prior: &AttestationContent,
    current: &AttestationContent,
) -> String {
    format!(
        "prior {} ; current {}",
        attestation_completeness_summary(prior),
        attestation_completeness_summary(current)
    )
}

pub(super) fn attestation_completeness_summary(attestation: &AttestationContent) -> String {
    let prefix = match attestation.rust_version.as_deref() {
        Some(version) => format!("rust-version={version} "),
        None => String::new(),
    };
    match attestation.analysis_completeness.as_ref() {
        Some(completeness) => format!(
            "{prefix}analyzed={} skipped={}{}",
            completeness.analyzed_files,
            completeness.skipped_files,
            skipped_path_suffix(completeness)
        ),
        None => format!("{prefix}analysis completeness unavailable"),
    }
}

fn skipped_path_suffix(completeness: &AnalysisCompleteness) -> String {
    let mut suffix = String::new();
    if !completeness.skipped_paths.is_empty() {
        // Writing to a String cannot fail.
        write!(
            suffix,
            " skipped_paths={}",
            completeness.skipped_paths.join(", ")
        )
        .ok();
    }
    if completeness.skipped_details.is_empty() {
        return suffix;
    }
    let details = completeness
        .skipped_details
        .iter()
        .map(|detail| format!("{}:{}", detail.path, detail.error))
        .collect::<Vec<_>>()
        .join(", ");
    write!(suffix, " skipped_errors={details}").ok();
    suffix
}
