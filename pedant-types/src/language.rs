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

impl Language {
    /// Every language, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 6] = [
        Self::Rust,
        Self::Python,
        Self::JavaScript,
        Self::TypeScript,
        Self::Go,
        Self::Bash,
    ];

    /// The stable token this language is claimed under.
    ///
    /// Exhaustive, so a seventh language fails to compile here rather than
    /// publishing a schema one token short of what it accepts. Every spelling is
    /// the one the `snake_case` rename above produces, which is why the two
    /// compound names carry a separator the language's own name does not.
    pub fn token(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Python => "python",
            Self::JavaScript => "java_script",
            Self::TypeScript => "type_script",
            Self::Go => "go",
            Self::Bash => "bash",
        }
    }
}
