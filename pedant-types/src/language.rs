use serde::{Deserialize, Serialize};

/// Programming language of a source file that produced a capability finding.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Rust (`.rs`).
    ///
    /// Rust capability analysis and symbol resolution belong to `pedant-core`,
    /// not to the `pedant-lang` backends: this variant names the language a
    /// shared result carries, not a scanner that handles it. `.rs` therefore
    /// keeps its dedicated `FileClassification::Rust` path and stays outside
    /// extension-and-shebang language detection.
    Rust,
    /// Python (`.py`).
    Python,
    /// JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`).
    JavaScript,
    /// TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`).
    TypeScript,
    /// Go (`.go`).
    Go,
    /// Bash/shell (`.sh`, `.bash`, `.zsh`).
    Bash,
}
