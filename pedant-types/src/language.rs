use serde::{Deserialize, Serialize};

/// Programming language of a source file that produced a capability finding.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Python (`.py`).
    Python,
    /// JavaScript (`.js`, `.mjs`, `.cjs`).
    JavaScript,
    /// TypeScript (`.ts`, `.tsx`, `.mts`).
    TypeScript,
    /// Go (`.go`).
    Go,
    /// Bash/shell (`.sh`, `.bash`, `.zsh`).
    Bash,
}
