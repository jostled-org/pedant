//! Multi-language capability detection for pedant.
//!
//! Analyzes Python, JavaScript/TypeScript, Go, and Bash source files
//! for capability findings. Produces the same `CapabilityAnalysis` envelope as
//! Rust analysis in `pedant-core`, with explicit language metadata: the flat
//! `CapabilityProfile` every persisted and policy consumer reads, the callables
//! that contain those findings, and an honest statement of whether a complete
//! structural parse stood behind them.

mod analyze;
mod attribution;
mod bash;
mod go;
mod javascript;
mod manifest;
mod python;
mod string_analysis;

pub use analyze::{analyze_file, analyze_manifest};
// Classification moved to `pedant-syntax`, which needs the same path and
// shebang rules for syntax dispatch. Re-exported rather than relocated in every
// caller, so `pedant`, `pedant-mcp`, and downstream consumers import no new
// crate to keep reading a file's language from here.
pub use pedant_syntax::{FileClassification, classify_path, detect_language};
