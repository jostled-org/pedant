//! Multi-language capability detection for pedant.
//!
//! Analyzes Python, JavaScript/TypeScript, Go, and Bash source files
//! for capability findings. Produces the same `CapabilityProfile` shape as
//! Rust analysis in `pedant-core`, with explicit language metadata.

mod bash;
mod go;
mod javascript;
mod manifest;
mod python;
mod string_analysis;
#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
mod tree_sitter_ext;

use std::path::Path;

use pedant_types::{CapabilityProfile, Language};

/// How a file should be processed by the analysis pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileClassification {
    /// Rust source — handled by pedant-core.
    Rust,
    /// Unrecognized file type.
    Unsupported,
    /// Non-Rust source in a supported language.
    Source(Language),
    /// Package manifest (package.json, Makefile, etc.).
    Manifest,
    /// Both source and manifest (e.g., `.go` files with `//go:generate`).
    SourceAndManifest(Language),
}

impl FileClassification {
    /// The source language, if this classification represents analyzable source.
    pub fn language(self) -> Option<Language> {
        match self {
            Self::Source(language) | Self::SourceAndManifest(language) => Some(language),
            Self::Rust | Self::Unsupported | Self::Manifest => None,
        }
    }

    /// Whether this classification includes manifest analysis.
    pub fn analyzes_manifest(self) -> bool {
        matches!(self, Self::Manifest | Self::SourceAndManifest(_))
    }
}

/// Classify a path for non-Rust source and manifest analysis.
pub fn classify_path(path: &Path) -> FileClassification {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    match filename {
        "package.json" | "setup.py" | "pyproject.toml" | "Makefile" | "makefile"
        | "GNUmakefile" | "justfile" | "Justfile" => return FileClassification::Manifest,
        _ => {}
    }

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => FileClassification::Rust,
        Some("py") => FileClassification::Source(Language::Python),
        Some("js" | "mjs" | "cjs") => FileClassification::Source(Language::JavaScript),
        Some("ts" | "tsx" | "mts") => FileClassification::Source(Language::TypeScript),
        Some("go") => FileClassification::SourceAndManifest(Language::Go),
        Some("sh" | "bash" | "zsh") => FileClassification::Source(Language::Bash),
        _ => FileClassification::Unsupported,
    }
}

/// Detect the programming language of a source file from its extension.
///
/// Falls back to shebang detection when no extension matches.
pub fn detect_language(path: &Path, source: &str) -> Option<Language> {
    classify_path(path)
        .language()
        .or_else(|| detect_from_shebang(source))
}

fn detect_from_shebang(source: &str) -> Option<Language> {
    let first_line = source.lines().next()?;
    if !first_line.starts_with("#!") {
        return None;
    }
    let shebang = first_line.trim_start_matches("#!");
    // Handle both `/bin/bash` and `/usr/bin/env bash` forms.
    let command = shebang.rsplit('/').next()?.split_whitespace().next()?;
    // For `#!/usr/bin/env X`, resolve the interpreter name after `env`.
    let interpreter = match command {
        "env" => shebang.split_whitespace().nth(1)?,
        other => other,
    };
    language_from_interpreter(interpreter)
}

fn language_from_interpreter(name: &str) -> Option<Language> {
    match name {
        "bash" | "sh" | "zsh" => Some(Language::Bash),
        "python" | "python3" => Some(Language::Python),
        "node" => Some(Language::JavaScript),
        _ => None,
    }
}

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
