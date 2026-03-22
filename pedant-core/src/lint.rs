use std::fs;
use std::path::{Path, PathBuf};

use crate::analysis_result::AnalysisResult;
use crate::capabilities::detect_capabilities;
use crate::check_config::CheckConfig;
use crate::ir;
use crate::ir::semantic::SemanticContext;
use crate::style::check_style;

/// Error type for linting operations.
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    /// Failed to read a source or configuration file.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Failed to parse the Rust source code.
    #[error("parse error: {0}")]
    ParseError(#[from] syn::Error),
    /// Failed to parse a TOML configuration file.
    #[error("TOML parse error: {0}")]
    TomlParseError(#[from] toml::de::Error),
}

/// Parse and analyze a Rust source string, returning violations and capability findings.
///
/// Parses the AST once with `syn::parse_file`, extracts IR facts, then runs
/// style checks and capability detection over the IR. When `semantic` is
/// `Some`, IR facts are enriched with resolved type information.
pub fn analyze(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, syn::Error> {
    analyze_inner(file_path, source, config, semantic, false)
}

/// Parse and analyze a build script source, tagging all capability findings with `build_script: true`.
pub fn analyze_build_script(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, syn::Error> {
    analyze_inner(file_path, source, config, semantic, true)
}

fn analyze_inner(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
    build_script: bool,
) -> Result<AnalysisResult, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let ir = ir::extract(file_path, &syntax, semantic);

    Ok(AnalysisResult {
        violations: check_style(&ir, config).into_boxed_slice(),
        capabilities: detect_capabilities(&ir, build_script),
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
    analyze("<string>", source, config, None).map_err(LintError::from)
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
    analyze(&file_path, &source, config, None).map_err(LintError::from)
}

/// Discover the build script path for a crate root directory.
///
/// Reads `Cargo.toml` at `crate_root` and checks `[package].build`.
/// If specified, returns the resolved path. Otherwise falls back to `build.rs`.
/// Returns `Ok(None)` if no `Cargo.toml` or build script exists.
/// Returns `Err` if `Cargo.toml` exists but cannot be read or parsed.
pub fn discover_build_script(crate_root: &Path) -> Result<Option<PathBuf>, LintError> {
    let cargo_toml_path = crate_root.join("Cargo.toml");
    let cargo_toml_contents = match fs::read_to_string(&cargo_toml_path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LintError::IoError(e)),
    };
    let table: toml::Table = cargo_toml_contents.parse()?;

    let custom_path = table
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|pkg| pkg.get("build"))
        .and_then(toml::Value::as_str);

    let candidate = match custom_path {
        Some(build_path) => crate_root.join(build_path),
        None => crate_root.join("build.rs"),
    };

    Ok(candidate.is_file().then_some(candidate))
}

/// Analyze a source file together with an optional build script.
///
/// Runs `analyze()` on the main source, then (if provided) on the build script
/// with `build_script=true`. Merges capability findings from both into a single result.
pub fn analyze_with_build_script(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
    build_source: Option<(&str, &str)>,
) -> Result<AnalysisResult, syn::Error> {
    let mut result = analyze(file_path, source, config, semantic)?;

    let Some((build_path, build_src)) = build_source else {
        return Ok(result);
    };

    let build_syntax = syn::parse_file(build_src)?;
    let build_ir = ir::extract(build_path, &build_syntax, semantic);
    let build_caps = detect_capabilities(&build_ir, true);

    let mut merged: Vec<pedant_types::CapabilityFinding> = result.capabilities.findings.into_vec();
    merged.extend(build_caps.findings.into_vec());
    result.capabilities.findings = merged.into_boxed_slice();

    Ok(result)
}
