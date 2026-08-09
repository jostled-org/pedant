//! The one path every language case takes into `analyze_file`.
//!
//! A case states a source and a language and asks what comes back. Stating that
//! once keeps every case reading the same two projections: sorted, deduplicated
//! capabilities, which do not depend on the finding order a scanner tier
//! produces, and the findings themselves for a case that judges origin,
//! location, or evidence.

use std::path::Path;

use pedant_lang::{analyze_file, detect_language};
use pedant_types::{Capability, CapabilityFinding, Language};

/// Every finding `analyze_file` reports for one source.
pub fn findings_for(source: &str, path: &str, lang: Language) -> Box<[CapabilityFinding]> {
    analyze_file(Path::new(path), source, lang).findings
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

/// The deduplicated capabilities `analyze_file` reports for one source.
pub fn caps_for(source: &str, path: &str, lang: Language) -> Box<[Capability]> {
    let mut caps: Vec<Capability> = findings_for(source, path, lang)
        .iter()
        .map(|finding| finding.capability)
        .collect();
    caps.sort();
    caps.dedup();
    caps.into_boxed_slice()
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
