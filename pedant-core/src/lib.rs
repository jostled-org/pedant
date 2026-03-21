//! Analysis engine for pedant: IR extraction, style checks, and capability detection.
//!
//! `pedant-core` provides the core analysis pipeline without CLI dependencies.
//! Parse Rust source, extract an intermediate representation, run style checks,
//! and detect capability usage — all without pulling in `clap` or output formatting.
//!
//! # Quick start
//!
//! ```
//! use pedant_core::{lint_str, Config};
//!
//! let config = Config::default();
//! let result = lint_str("fn f() { if true { if false {} } }", &config).unwrap();
//! assert!(!result.violations.is_empty());
//! ```

/// Combined analysis result type.
pub mod analysis_result;
/// IR-based capability detection consuming extracted facts.
pub mod capabilities;
/// Check configuration, TOML config file types, and config file loading.
pub mod check_config;
/// Check metadata catalog used by `--list-checks` and `--explain`.
pub mod checks;
/// Graph algorithms for type-relationship analysis.
pub(crate) mod graph;
/// Source content hashing for attestation.
pub mod hash;
/// Intermediate representation: facts extracted from the AST in a single pass.
pub mod ir;
/// JSON serialization types for violation output.
pub mod json_format;
/// Linting entry points and error types.
pub mod lint;
/// Glob-style pattern matching for AST node text.
pub mod pattern;
/// IR-based style checks consuming extracted facts.
pub mod style;
/// Violation types, rationale, and the `Violation` struct.
pub mod violation;

pub use analysis_result::AnalysisResult;
pub use check_config::{
    CheckConfig as Config, ConfigFile, NamingCheck, PatternCheck, PatternOverride,
};
pub use checks::{ALL_CHECKS, CheckInfo};
pub use lint::{
    LintError, analyze, analyze_build_script, analyze_with_build_script, discover_build_script,
    lint_file, lint_str,
};
pub use violation::{CheckRationale, Violation, ViolationType, lookup_rationale};

/// Re-export syn::Error as ParseError for consumers that call [`analyze`] directly.
pub use syn::Error as ParseError;
