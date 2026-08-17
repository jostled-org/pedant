//! The one path every language case takes into `analyze_file`.
//!
//! A case states a source and a language and asks what comes back. Stating that
//! once keeps every case reading the same three projections: sorted,
//! deduplicated capabilities, which do not depend on the finding order a scanner
//! tier produces; the findings themselves for a case that judges origin,
//! location, or evidence; and the flat row sequence a case compares against a
//! written-down table.

use std::path::Path;

use pedant_lang::{analyze_file, detect_language};
use pedant_types::{Capability, CapabilityAnalysis, CapabilityFinding, FindingOrigin, Language};

/// The whole analysis `analyze_file` reports for one source.
///
/// The symbol cases and the availability cases read the status and the symbol
/// projection from here; the older cases take the flat projection below, so
/// both read the same one entry point.
pub fn analysis_for(source: &str, path: &str, lang: Language) -> CapabilityAnalysis {
    analyze_file(Path::new(path), source, lang)
}

/// Every finding `analyze_file` reports for one source.
pub fn findings_for(source: &str, path: &str, lang: Language) -> Box<[CapabilityFinding]> {
    analysis_for(source, path, lang).into_profile().findings
}

/// The same, for a source whose language the detector names from its path.
pub fn analyze_detected(path: &str, source: &str) -> Box<[CapabilityFinding]> {
    let language = detect_language(Path::new(path), source)
        .unwrap_or_else(|| panic!("{path} must resolve to a supported language"));
    findings_for(source, path, language)
}

/// Whether any finding reports `capability`.
pub fn has_capability(findings: &[CapabilityFinding], capability: Capability) -> bool {
    findings
        .iter()
        .any(|finding| finding.capability == capability)
}

/// The sorted, deduplicated capabilities a set of findings reports.
///
/// Sorting and deduplicating is what makes a capability list comparable: the
/// order a scanner tier emits findings in is not part of any capability claim.
pub fn capabilities(findings: &[CapabilityFinding]) -> Box<[Capability]> {
    let mut caps: Vec<Capability> = findings.iter().map(|finding| finding.capability).collect();
    caps.sort();
    caps.dedup();
    caps.into_boxed_slice()
}

/// The deduplicated capabilities `analyze_file` reports for one source.
pub fn caps_for(source: &str, path: &str, lang: Language) -> Box<[Capability]> {
    capabilities(&findings_for(source, path, lang))
}

/// The flat projection of one finding, as every written-down table reads it.
///
/// The origin and the language ride along exactly as the analysis states them,
/// so a finding that names neither, or names the wrong language, disagrees with
/// a table that states both.
pub type FlatRow<'a> = (
    Capability,
    &'a str,
    usize,
    usize,
    Option<FindingOrigin>,
    Option<Language>,
);

/// Every finding an analysis reports, in the projection above.
fn flat_rows(analysis: &CapabilityAnalysis) -> Box<[FlatRow<'_>]> {
    analysis
        .profile
        .findings
        .iter()
        .map(|finding| {
            (
                finding.capability,
                &*finding.evidence,
                finding.location.line,
                finding.location.column,
                finding.origin,
                finding.language,
            )
        })
        .collect()
}

/// Assert one analysis produces exactly the written-down flat sequence.
///
/// One home for the comparison, because the symbol cases and the availability
/// cases make the same claim about the same projection: two copies were two
/// chances for one of them to drop a field and stop noticing.
pub fn assert_flat_sequence<'a>(
    analysis: &'a CapabilityAnalysis,
    path: &str,
    expected: &[FlatRow<'a>],
) {
    let actual = flat_rows(analysis);
    assert_eq!(
        &*actual, expected,
        "{path} must produce exactly the written-down flat sequence"
    );
    assert!(
        !actual.is_empty(),
        "{path} must produce at least one finding"
    );
}

pub fn py_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.py", Language::Python)
}

pub fn js_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.js", Language::JavaScript)
}

pub fn go_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.go", Language::Go)
}

pub fn bash_caps(source: &str) -> Box<[Capability]> {
    caps_for(source, "test.sh", Language::Bash)
}

pub fn has_py_cap(source: &str, expected: Capability) -> bool {
    py_caps(source).contains(&expected)
}
