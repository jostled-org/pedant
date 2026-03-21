use std::fs;
use std::path::Path;

use crate::analysis_result::AnalysisResult;
use crate::capabilities::detect_capabilities;
use crate::check_config::CheckConfig;
use crate::ir;
use crate::style::check_style;

/// Error type for linting operations.
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    /// Failed to read the source file.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Failed to parse the Rust source code.
    #[error("parse error: {0}")]
    ParseError(#[from] syn::Error),
}

/// Parse and analyze a Rust source string, returning violations and capability findings.
///
/// Parses the AST once with `syn::parse_file`, extracts IR facts, then runs
/// style checks and capability detection over the IR.
pub fn analyze(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
) -> Result<AnalysisResult, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let ir = ir::extract(file_path, &syntax);

    Ok(AnalysisResult {
        violations: check_style(&ir, config).into_boxed_slice(),
        capabilities: detect_capabilities(&ir),
    })
}

/// Lint a string of Rust source code.
///
/// # Arguments
/// * `source` - The Rust source code to lint
/// * `config` - The linting configuration
///
/// # Returns
/// An [`AnalysisResult`] containing violations and capability findings, or an error if parsing fails.
pub fn lint_str(source: &str, config: &CheckConfig) -> Result<AnalysisResult, LintError> {
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
pub fn lint_file(path: &Path, config: &CheckConfig) -> Result<AnalysisResult, LintError> {
    let source = fs::read_to_string(path)?;
    let file_path = path.to_string_lossy();
    analyze(&file_path, &source, config).map_err(LintError::from)
}
