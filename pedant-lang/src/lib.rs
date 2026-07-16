//! Multi-language capability detection for pedant.
//!
//! Analyzes Python, JavaScript/TypeScript, Go, and Bash source files
//! for capability findings. Produces the same `CapabilityProfile` shape as
//! Rust analysis in `pedant-core`, with explicit language metadata.

mod analyze;
mod bash;
mod classify;
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

pub use analyze::{analyze_file, analyze_manifest};
pub use classify::{FileClassification, classify_path, detect_language};
