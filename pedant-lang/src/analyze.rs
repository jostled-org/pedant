use std::path::Path;

use pedant_syntax::{SyntaxLanguage, syntax_language};
use pedant_types::{CapabilityAnalysis, Language};

use crate::{attribution, bash, go, javascript, manifest, python};

/// Analyze a package manifest or hook-entrypoint file for capabilities.
///
/// Recognized files: `package.json`, `setup.py`, `pyproject.toml`,
/// `Makefile`, `justfile`, and `.go` files (for `//go:generate` directives).
/// Returns an empty profile for unrecognized files.
///
/// Symbol attribution is always
/// [`NotApplicable`](pedant_types::SymbolAttributionStatus::NotApplicable): a
/// manifest states hooks, not callables, so there is no callable inventory to
/// be complete or incomplete about.
pub fn analyze_manifest(path: &Path, source: &str) -> CapabilityAnalysis {
    attribution::envelope::not_applicable(manifest::analyze(path, source))
}

/// Analyze a non-Rust source file for capabilities.
///
/// The caller provides the detected `language` so that detection and analysis
/// remain decoupled. Returns an analysis whose flat findings are tagged with
/// the language, beside the callables that contain them.
///
/// JavaScript and TypeScript also need the grammar the path names, which is a
/// finer question than `language` answers: `.tsx` carries capability language
/// [`Language::TypeScript`] but reads as a type assertion under the plain
/// TypeScript grammar. `pedant_syntax::syntax_language` owns that rule, so this
/// is where it is asked rather than a second extension test inside the scanner.
pub fn analyze_file(path: &Path, source: &str, language: Language) -> CapabilityAnalysis {
    let file: std::sync::Arc<str> = path.to_string_lossy().into();
    match language {
        // Rust capability extraction belongs to `pedant-core`, which owns the
        // `syn` IR this crate never builds. Answering with another language's
        // scanner would report findings from the wrong grammar, so the honest
        // answer at this boundary is an empty profile — and no callable claim,
        // because the callables are `pedant-core`'s to state.
        Language::Rust => attribution::envelope::not_applicable(Box::new([])),
        Language::Python => python::analyze(&file, source),
        Language::JavaScript | Language::TypeScript => {
            // A path `syntax_language` does not recognize keeps the plain
            // mapping the capability language implies.
            let syntax = syntax_language(path, source).unwrap_or(SyntaxLanguage::from(language));
            javascript::analyze(&file, source, language, syntax)
        }
        Language::Go => go::analyze(&file, source),
        Language::Bash => bash::analyze(&file, source),
    }
}
