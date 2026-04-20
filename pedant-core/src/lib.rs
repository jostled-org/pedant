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

/// Violations + capabilities produced by a single analysis run.
pub mod analysis_result;
/// Path-based capability detection over extracted IR facts.
pub mod capabilities;
/// `.pedant.toml` schema, loading, and per-path override resolution.
pub mod check_config;
/// Check catalog: metadata, rationale, and the `ViolationType` enum.
pub mod checks;
/// Security gate rules that fire on suspicious capability combinations.
pub mod gate;
/// BFS and pairwise-edge helpers for type-relationship graphs.
pub(crate) mod graph;
/// SHA-256 hashing of source contents for attestation.
pub mod hash;
/// Intermediate representation extracted from the AST in one pass.
pub mod ir;
/// JSON serialization for machine-readable violation output.
pub mod json_format;
/// High-level analysis entry points and error types.
pub mod lint;
/// Glob and wildcard matching for AST node text and file paths.
pub mod pattern;
/// Style checks that consume IR facts and produce violations.
pub mod style;
/// The `Violation` type, display formatting, and check rationale.
pub mod violation;

pub use analysis_result::AnalysisResult;
pub use check_config::{
    CheckConfig as Config, ConfigFile, GateConfig, GateRuleOverride, NamingCheck, PatternCheck,
    PatternOverride,
};
pub use checks::{ALL_CHECKS, CheckInfo};
pub use gate::{
    GateInputSummary, GateRuleInfo, GateSeverity, GateVerdict, all_gate_rules, evaluate_gate_rules,
};
pub use lint::{
    LintError, analyze, analyze_build_script, analyze_with_build_script, determine_analysis_tier,
    discover_build_script, discover_workspace_root, lint_file, lint_str,
};
pub use violation::{CheckRationale, Violation, ViolationType, lookup_rationale};

/// Alias for `syn::Error`, used by consumers that call [`analyze`] directly.
pub use syn::Error as ParseError;

#[cfg(feature = "semantic")]
pub use ir::semantic::FunctionAnalysisSummary;
pub use ir::semantic::{SemanticContext, SemanticFileAnalysis};
