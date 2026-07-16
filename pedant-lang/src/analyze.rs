use std::path::Path;

use pedant_types::{CapabilityProfile, Language};

use crate::{bash, go, javascript, manifest, python};

/// Analyze a package manifest or hook-entrypoint file for capabilities.
///
/// Recognized files: `package.json`, `setup.py`, `pyproject.toml`,
/// `Makefile`, `justfile`, and `.go` files (for `//go:generate` directives).
/// Returns an empty profile for unrecognized files.
pub fn analyze_manifest(path: &Path, source: &str) -> CapabilityProfile {
    manifest::analyze(path, source)
}

/// Analyze a non-Rust source file for capabilities.
///
/// The caller provides the detected `language` so that detection and analysis
/// remain decoupled. Returns a profile with findings tagged with the language.
pub fn analyze_file(path: &Path, source: &str, language: Language) -> CapabilityProfile {
    let file: std::sync::Arc<str> = path.to_string_lossy().into();
    let findings = match language {
        Language::Python => python::analyze(&file, source),
        Language::JavaScript | Language::TypeScript => javascript::analyze(&file, source, language),
        Language::Go => go::analyze(&file, source),
        Language::Bash => bash::analyze(&file, source),
    };
    CapabilityProfile { findings }
}
