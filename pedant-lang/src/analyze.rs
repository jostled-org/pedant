use std::path::Path;

use pedant_syntax::{SyntaxLanguage, syntax_language};
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
///
/// JavaScript and TypeScript also need the grammar the path names, which is a
/// finer question than `language` answers: `.tsx` carries capability language
/// [`Language::TypeScript`] but reads as a type assertion under the plain
/// TypeScript grammar. `pedant_syntax::syntax_language` owns that rule, so this
/// is where it is asked rather than a second extension test inside the scanner.
pub fn analyze_file(path: &Path, source: &str, language: Language) -> CapabilityProfile {
    let file: std::sync::Arc<str> = path.to_string_lossy().into();
    let findings = match language {
        // Rust capability extraction belongs to `pedant-core`, which owns the
        // `syn` IR this crate never builds. Answering with another language's
        // scanner would report findings from the wrong grammar, so the honest
        // answer at this boundary is an empty profile.
        Language::Rust => Box::default(),
        Language::Python => python::analyze(&file, source),
        Language::JavaScript | Language::TypeScript => {
            // A path `syntax_language` does not recognize keeps the plain
            // mapping the capability language implies.
            let syntax = syntax_language(path, source).unwrap_or(SyntaxLanguage::from(language));
            javascript::analyze(&file, source, language, syntax)
        }
        Language::Go => go::analyze(&file, source),
        Language::Bash => bash::analyze(&file, source),
    };
    CapabilityProfile { findings }
}
