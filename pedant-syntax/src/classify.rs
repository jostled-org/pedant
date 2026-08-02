//! Path, extension, and shebang classification.
//!
//! Capability routing and syntax dispatch ask the same question about a file,
//! so they read the same answer here rather than keeping two rule sets that can
//! disagree about what a path is.

use std::path::Path;

use pedant_types::Language;

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
}

/// Classify a path for non-Rust source and manifest analysis.
pub fn classify_path(path: &Path) -> FileClassification {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    match filename {
        "package.json" | "setup.py" | "pyproject.toml" | "Makefile" | "makefile"
        | "GNUmakefile" | "justfile" | "Justfile" => FileClassification::Manifest,
        _ => classify_extension(path),
    }
}

/// Classify a path a manifest name does not claim, by extension alone.
///
/// Visible to the crate so syntax dispatch can ask the extension question about
/// a path a manifest name already claimed, which is how `setup.py` resolves as
/// Python source without a second extension table.
pub(crate) fn classify_extension(path: &Path) -> FileClassification {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => FileClassification::Rust,
        Some("py") => FileClassification::Source(Language::Python),
        Some("js" | "jsx" | "mjs" | "cjs") => FileClassification::Source(Language::JavaScript),
        Some("ts" | "tsx" | "mts" | "cts") => FileClassification::Source(Language::TypeScript),
        Some("go") => FileClassification::SourceAndManifest(Language::Go),
        Some("sh" | "bash" | "zsh") => FileClassification::Source(Language::Bash),
        _ => FileClassification::Unsupported,
    }
}

/// Detect the programming language of a source file from its extension.
///
/// Falls back to shebang detection when no extension matches.
pub fn detect_language(path: &Path, source: &str) -> Option<Language> {
    language_or_shebang(classify_path(path), source)
}

/// The language `classification` names, or the one a leading shebang names.
///
/// The one tail both [`detect_language`] and [`crate::syntax_language`] read,
/// so capability routing and syntax dispatch cannot disagree about when a
/// shebang speaks.
pub(crate) fn language_or_shebang(
    classification: FileClassification,
    source: &str,
) -> Option<Language> {
    classification
        .language()
        .or_else(|| detect_from_shebang(source))
}

/// The language a leading shebang names, for a path no extension claimed.
fn detect_from_shebang(source: &str) -> Option<Language> {
    let shebang = source.lines().next()?.strip_prefix("#!")?;
    let mut words = shebang.split_whitespace();
    // Handle both `/bin/bash` and `/usr/bin/env bash` forms.
    let command = words.next()?.rsplit('/').next()?;
    match command {
        // `env` takes its own options before the program it runs, so
        // `#!/usr/bin/env -S python3` names `python3` rather than `-S`.
        "env" => words
            .find(|word| !word.starts_with('-'))
            .and_then(language_from_interpreter),
        other => language_from_interpreter(other),
    }
}

fn language_from_interpreter(name: &str) -> Option<Language> {
    match name {
        "bash" | "sh" | "zsh" => Some(Language::Bash),
        "python" | "python3" => Some(Language::Python),
        "node" => Some(Language::JavaScript),
        _ => None,
    }
}
