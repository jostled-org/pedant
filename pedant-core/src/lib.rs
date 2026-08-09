//! Analysis engine for pedant: IR extraction, capability detection, and style checks.
//!
//! `pedant-core` provides the core analysis pipeline without CLI dependencies.
//! It presents two surfaces over one module tree, selected by feature.
//!
//! The **substrate** is present in every configuration. It answers factual
//! questions about source text: [`ir`] extracts facts, [`capabilities`] resolves
//! them to capabilities, [`resolution`] models the Cargo project those files
//! belong to, and [`hash`] and [`pattern`] support them. No substrate entry
//! point accepts policy input.
//!
//! The **judgment** surface sits behind the `checks` feature, which is on by
//! default. It answers acceptability questions and owns every type whose shape
//! is determined by an opinion: the check catalog, the gate rules engine, check
//! configuration, violations, and the orchestrating `lint` entry points. A
//! consumer that wants facts without opinions takes `default-features = false`.
//!
//! `semantic` is a third, orthogonal axis. It combines with either surface, and
//! enabling `checks` does not enable it.
//!
//! # Quick start
//!
//! ```
//! use pedant_core::capabilities::detect_capabilities;
//! use pedant_core::ir::extract;
//! use pedant_types::Capability;
//!
//! let syntax = syn::parse_file("use std::fs;").expect("source parses");
//! let ir = extract("example.rs", &syntax, None);
//! let profile = detect_capabilities(&ir, None);
//!
//! assert_eq!(profile.findings[0].capability, Capability::FileRead);
//! ```

/// Violations + capabilities produced by a single analysis run.
#[cfg(feature = "checks")]
pub mod analysis_result;
/// Path-based capability detection over extracted IR facts.
pub mod capabilities;
/// `.pedant.toml` schema, loading, and per-path override resolution.
#[cfg(feature = "checks")]
pub mod check_config;
/// Check catalog: metadata, rationale, and the `ViolationType` enum.
#[cfg(feature = "checks")]
pub mod checks;
/// Security gate rules that fire on suspicious capability combinations.
#[cfg(feature = "checks")]
pub mod gate;
/// BFS and pairwise-edge helpers for type-relationship graphs.
pub(crate) mod graph;
/// SHA-256 hashing of source contents for attestation.
pub mod hash;
/// Intermediate representation extracted from the AST in one pass.
pub mod ir;
/// JSON serialization for machine-readable violation output.
#[cfg(feature = "checks")]
pub mod json_format;
/// High-level analysis entry points and error types.
///
/// ```
/// use pedant_core::{lint_str, Config};
///
/// let config = Config::default();
/// let result = lint_str("fn f() { if true { if false {} } }", &config).unwrap();
/// assert!(!result.violations.is_empty());
/// ```
#[cfg(feature = "checks")]
pub mod lint;
/// Observation hooks the proof feature reads; inert in ordinary builds.
pub(crate) mod observe;
/// Glob and wildcard matching for AST node text and file paths.
pub mod pattern;
/// Whole-workspace structural checks over the file tree and Cargo metadata.
#[cfg(feature = "checks")]
pub mod project;
/// Language-scoped project and symbol-resolution models.
pub mod resolution;
/// Style checks that consume IR facts and produce violations.
#[cfg(feature = "checks")]
pub mod style;
/// The `Violation` type, display formatting, and check rationale.
#[cfg(feature = "checks")]
pub mod violation;

#[cfg(feature = "checks")]
pub use analysis_result::AnalysisResult;
#[cfg(feature = "checks")]
pub use check_config::{
    CheckConfig as Config, ConfigFile, GateConfig, GateRuleOverride, NamingCheck, PatternCheck,
    PatternOverride,
};
#[cfg(feature = "checks")]
pub use checks::{ALL_CHECKS, CheckInfo};
#[cfg(feature = "checks")]
pub use gate::{
    GateInputSummary, GateRuleInfo, GateSeverity, GateVerdict, all_gate_rules, evaluate_gate_rules,
};
#[cfg(feature = "checks")]
pub use lint::{
    LintError, analyze, analyze_build_script, analyze_build_script_with_shape,
    analyze_with_build_script, analyze_with_shape, determine_analysis_tier, discover_build_script,
    discover_crate_root, discover_workspace_root, lint_file, lint_str,
};
#[cfg(feature = "checks")]
pub use violation::{CheckRationale, Violation, ViolationType, lookup_rationale};

/// Alias for `syn::Error`, used by consumers that parse source themselves.
pub use syn::Error as ParseError;

#[cfg(feature = "semantic")]
pub use ir::semantic::FunctionAnalysisSummary;
pub use ir::semantic::{SemanticContext, SemanticFileAnalysis};
