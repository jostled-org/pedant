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
