//! Syntax-language dispatch: which parser backend owns a source file.

use std::path::Path;

use pedant_types::Language;
use serde::{Deserialize, Serialize};

use crate::classify::{FileClassification, classify_extension, classify_path, language_or_shebang};

/// A language whose syntax `pedant-syntax` can parse.
///
/// Wider than the capability [`Language`] set: it adds Rust, which capability
/// analysis leaves to `pedant-core`, and TSX, which shares TypeScript's
/// classification but needs its own grammar.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxLanguage {
    /// Rust (`.rs`), parsed with `syn`.
    Rust,
    /// Python (`.py`).
    Python,
    /// JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`).
    ///
    /// `.jsx` belongs here: the JavaScript grammar already parses JSX, so the
    /// React extension needs no separate variant the way `.tsx` does.
    JavaScript,
    /// TypeScript without JSX (`.ts`, `.mts`, `.cts`).
    TypeScript,
    /// TypeScript with JSX (`.tsx`).
    Tsx,
    /// Go (`.go`).
    Go,
    /// Bash/shell (`.sh`, `.bash`, `.zsh`).
    Bash,
}

impl From<Language> for SyntaxLanguage {
    /// Capability `TypeScript` keeps the plain TypeScript grammar; only
    /// [`syntax_language`] distinguishes TSX.
    fn from(language: Language) -> Self {
        match language {
            Language::Python => Self::Python,
            Language::JavaScript => Self::JavaScript,
            Language::TypeScript => Self::TypeScript,
            Language::Go => Self::Go,
            Language::Bash => Self::Bash,
        }
    }
}

/// Detect the syntax language of a source file.
///
/// `.tsx` resolves to [`SyntaxLanguage::Tsx`] before classification and Rust
/// source resolves to [`SyntaxLanguage::Rust`]. A manifest name resolves by
/// extension alone. Every other path follows the existing
/// [`crate::detect_language`] rules, including the shebang fallback.
/// Unrecognized files, and manifests that hold no source, return `None`.
///
/// The path is classified once and every arm reads that one answer, so the Rust
/// rule and the language rule cannot disagree about what a path is. Every
/// [`FileClassification`] variant is named rather than bound by a catch-all, so
/// a sixth variant fails to compile here rather than falling into the shebang
/// rule unexamined.
pub fn syntax_language(path: &Path, source: &str) -> Option<SyntaxLanguage> {
    if path.extension().is_some_and(|extension| extension == "tsx") {
        return Some(SyntaxLanguage::Tsx);
    }
    match classify_path(path) {
        FileClassification::Rust => Some(SyntaxLanguage::Rust),
        FileClassification::Manifest => manifest_syntax(path),
        classification @ (FileClassification::Source(_)
        | FileClassification::SourceAndManifest(_)
        | FileClassification::Unsupported) => {
            language_or_shebang(classification, source).map(SyntaxLanguage::from)
        }
    }
}

/// The syntax language of a path a manifest name claimed, by extension alone.
///
/// A manifest filename is matched before any extension is, so `setup.py`
/// classifies as a manifest and names no language. Falling through to the
/// shebang rule would then make the same Python file extractable for one author
/// and not for the next; the extension is the deterministic answer. It resolves
/// `setup.py` as Python and leaves `package.json`, `pyproject.toml`,
/// `Makefile`, and `justfile` — which hold no source — at `None`.
///
/// No manifest name carries a `.rs` extension, so no Rust arm is reachable
/// here; a manifest that later did would classify as unsupported and answer
/// `None` rather than answer wrongly.
fn manifest_syntax(path: &Path) -> Option<SyntaxLanguage> {
    classify_extension(path)
        .language()
        .map(SyntaxLanguage::from)
}
