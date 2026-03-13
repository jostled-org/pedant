//! An opinionated Rust linter with special focus on AI-generated code.
//!
//! pedant catches patterns that compile but violate best practices: deep nesting,
//! panic-prone calls, silenced warnings, dynamic dispatch, and mixed concerns.
//!
//! # Quick start
//!
//! ```
//! use pedant::{lint_str, Config};
//!
//! let config = Config::default();
//! let result = lint_str("fn f() { if true { if false {} } }", &config).unwrap();
//! assert!(!result.violations.is_empty());
//! ```

/// Combined analysis result type.
pub mod analysis_result;
/// Capability detection via use-path and call-site analysis.
pub(crate) mod capability_visitor;
/// Check metadata catalog used by `--list-checks` and `--explain`.
pub mod checks;
/// CLI argument parsing and TOML config file loading.
pub mod config;
/// Source content hashing for attestation.
pub mod hash;
/// JSON serialization types for violation output.
pub(crate) mod json_format;
/// Linting entry points and error types.
pub mod lint;
/// Glob-style pattern matching for AST node text.
pub mod pattern;
/// Violation output formatting (text and JSON).
pub mod reporter;
/// Violation types, rationale, and the `Violation` struct.
pub mod violation;
/// AST visitor that performs all checks in a single pass.
pub mod visitor;

pub use analysis_result::AnalysisResult;
pub use checks::{ALL_CHECKS, CheckInfo};
pub use config::{Cli, ConfigFile, NamingCheck, PatternCheck, PatternOverride};
pub use lint::{Config, LintError, lint_file, lint_str};
pub use reporter::{OutputFormat, Reporter};
pub use violation::{CheckRationale, Violation, ViolationType, lookup_rationale};
pub use visitor::{CheckConfig, analyze};
