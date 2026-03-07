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

/// Capability detection via use-path and call-site analysis.
pub(crate) mod capability_visitor;
/// Check metadata catalog used by `--list-checks` and `--explain`.
pub mod checks;
/// CLI argument parsing and TOML config file loading.
pub mod config;
/// JSON serialization types for violation output.
pub(crate) mod json_format;
/// Glob-style pattern matching for AST node text.
pub mod pattern;
/// Violation output formatting (text and JSON).
pub mod reporter;
/// Violation types, rationale, and the `Violation` struct.
pub mod violation;
/// AST visitor that performs all checks in a single pass.
pub mod visitor;

use std::fs;
use std::path::Path;

pub use analysis_result::AnalysisResult;
pub use checks::{ALL_CHECKS, CheckInfo};
pub use config::{Cli, ConfigFile, NamingCheck, PatternCheck, PatternOverride};
pub use reporter::{OutputFormat, Reporter};
pub use violation::{CheckRationale, Violation, ViolationType, lookup_rationale};
pub use visitor::{CheckConfig, analyze};

/// Combined analysis result type.
pub mod analysis_result;

/// Type alias for the configuration used by the linter.
pub type Config = CheckConfig;

/// Error type for linting operations.
#[derive(Debug)]
pub enum LintError {
    /// Failed to read the source file.
    IoError(std::io::Error),
    /// Failed to parse the Rust source code.
    ParseError(syn::Error),
}

impl std::fmt::Display for LintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {e}"),
            Self::ParseError(e) => write!(f, "parse error: {e}"),
        }
    }
}

impl std::error::Error for LintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            Self::ParseError(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for LintError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<syn::Error> for LintError {
    fn from(e: syn::Error) -> Self {
        Self::ParseError(e)
    }
}

/// Lint a string of Rust source code.
///
/// # Arguments
/// * `source` - The Rust source code to lint
/// * `config` - The linting configuration
///
/// # Returns
/// An [`AnalysisResult`] containing violations and capability findings, or an error if parsing fails.
pub fn lint_str(source: &str, config: &Config) -> Result<AnalysisResult, LintError> {
    analyze("<string>", source, config).map_err(LintError::from)
}

/// Lint a file of Rust source code.
///
/// # Arguments
/// * `path` - The path to the Rust source file
/// * `config` - The linting configuration
///
/// # Returns
/// An [`AnalysisResult`] containing violations and capability findings, or an error if reading or parsing fails.
pub fn lint_file(path: &Path, config: &Config) -> Result<AnalysisResult, LintError> {
    let source = fs::read_to_string(path)?;
    let file_path = path.to_string_lossy();
    analyze(&file_path, &source, config).map_err(LintError::from)
}
