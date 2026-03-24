use std::fs;
use std::path::{Path, PathBuf};

use pedant_types::AnalysisTier;

use crate::analysis_result::AnalysisResult;
use crate::capabilities::detect_capabilities;
use crate::check_config::CheckConfig;
use crate::ir;
use crate::ir::DataFlowFact;
use crate::ir::semantic::SemanticContext;
use crate::style::check_style;

/// Failure modes for the lint pipeline (I/O, parse, config).
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    /// Disk I/O failure reading source or config.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// `syn` could not parse the Rust source.
    #[error("parse error: {0}")]
    ParseError(#[from] syn::Error),
    /// TOML syntax or schema error in a config file.
    #[error("TOML parse error: {0}")]
    TomlParseError(#[from] toml::de::Error),
}

/// Full analysis pipeline: parse, extract IR, run style checks, detect capabilities.
///
/// When `semantic` is `Some`, IR facts are enriched with resolved type information
/// before checks run.
pub fn analyze(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, syn::Error> {
    analyze_inner(file_path, source, config, semantic, false)
}

/// Like [`analyze`], but tags all capability findings with `build_script: true`.
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
    let violations = check_style(&ir, config).into_boxed_slice();
    let capabilities = detect_capabilities(&ir, build_script);

    #[cfg(feature = "semantic")]
    let capabilities = {
        let mut caps = capabilities;
        if let Some(ctx) = semantic {
            enrich_reachability(&mut caps.findings, ctx);
        }
        caps
    };

    Ok(AnalysisResult {
        violations,
        capabilities,
        data_flows: ir.data_flows,
    })
}

/// Convenience wrapper: analyze a Rust source string with no file path or semantic context.
pub fn lint_str(source: &str, config: &CheckConfig) -> Result<AnalysisResult, LintError> {
    analyze("<string>", source, config, None).map_err(LintError::from)
}

/// Convenience wrapper: read and analyze a Rust source file with no semantic context.
pub fn lint_file(path: &Path, config: &CheckConfig) -> Result<AnalysisResult, LintError> {
    let source = fs::read_to_string(path)?;
    let file_path = path.to_string_lossy();
    analyze(&file_path, &source, config, None).map_err(LintError::from)
}

/// Walk ancestors of `start` looking for a Cargo workspace or package root.
///
/// Prefers a directory containing a `Cargo.toml` with `[workspace]`. Falls back
/// to the nearest `Cargo.toml` with `[package]` if no workspace is found.
pub fn discover_workspace_root(start: &Path) -> Option<PathBuf> {
    let start_dir = match start.is_dir() {
        true => start,
        false => start.parent()?,
    };

    let mut nearest_package: Option<PathBuf> = None;
    for dir in start_dir.ancestors() {
        let cargo_toml = dir.join("Cargo.toml");
        let (has_workspace, has_package) = fs::read_to_string(&cargo_toml)
            .map(|c| (c.contains("[workspace]"), c.contains("[package]")))
            .unwrap_or((false, false));
        match (has_workspace, has_package, nearest_package.is_some()) {
            (true, _, _) => return Some(dir.to_path_buf()),
            (false, true, false) => nearest_package = Some(dir.to_path_buf()),
            _ => {}
        }
    }
    nearest_package
}

/// Find the build script for a crate by reading `[package].build` from `Cargo.toml`.
///
/// Falls back to `build.rs` when `build` is not specified.
/// Returns `Ok(None)` when no `Cargo.toml` or build script exists on disk.
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

/// Analyze a source file and optionally merge build-script capability findings.
///
/// When `build_source` is `Some`, its findings are tagged `build_script: true`
/// and appended to the main result's capability profile.
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

/// Determine the analysis tier based on whether semantic analysis ran and
/// whether data flow facts were detected.
///
/// - `DataFlow` when semantic context was active and flows were found.
/// - `Semantic` when semantic context was active but no flows detected.
/// - `Syntactic` otherwise.
pub fn determine_analysis_tier(
    semantic: Option<&SemanticContext>,
    data_flows: &[DataFlowFact],
) -> AnalysisTier {
    match (semantic.is_some(), !data_flows.is_empty()) {
        (_, true) => AnalysisTier::DataFlow,
        (true, false) => AnalysisTier::Semantic,
        (false, false) => AnalysisTier::Syntactic,
    }
}

/// Annotate capability findings with entry-point reachability.
///
/// Sets `reachable` to `Some(true)` or `Some(false)` for each finding
/// based on whether the containing function is reachable from a public
/// entry point via the call graph.
#[cfg(feature = "semantic")]
fn enrich_reachability(findings: &mut [pedant_types::CapabilityFinding], ctx: &SemanticContext) {
    use std::collections::BTreeMap;

    // Group finding indices by file so the call graph is built once per file.
    // Collect owned keys to avoid borrowing `findings` across the mutation below.
    let mut by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, finding) in findings.iter().enumerate() {
        by_file
            .entry(finding.location.file.to_string())
            .or_default()
            .push(idx);
    }

    for (file, indices) in &by_file {
        let lines: Vec<usize> = indices.iter().map(|&i| findings[i].location.line).collect();
        let results = ctx.check_reachability_batch(file, &lines);
        for (pos, &idx) in indices.iter().enumerate() {
            findings[idx].reachable = Some(results[pos]);
        }
    }
}
