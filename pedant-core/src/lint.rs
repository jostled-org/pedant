use std::fs;
use std::path::{Path, PathBuf};

use pedant_types::{AnalysisTier, ExecutionContext};

use crate::analysis_result::AnalysisResult;
use crate::capabilities::detect_capabilities;
use crate::check_config::CheckConfig;
use crate::ir;
use crate::ir::DataFlowFact;
use crate::ir::extract::compute_fingerprints;
use crate::ir::semantic::SemanticContext;
use crate::style::check_style;

type ManifestPresence = (bool, bool);

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
    analyze_inner(file_path, source, config, semantic, None)
}

/// Like [`analyze`], but tags all capability findings with `ExecutionContext::BuildHook`.
pub fn analyze_build_script(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, syn::Error> {
    analyze_inner(
        file_path,
        source,
        config,
        semantic,
        Some(ExecutionContext::BuildHook),
    )
}

fn analyze_inner(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
    execution_context: Option<ExecutionContext>,
) -> Result<AnalysisResult, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let ir = ir::extract(file_path, &syntax, semantic);
    let violations = check_style(&ir, config).into_boxed_slice();
    let capabilities = detect_capabilities(&ir, execution_context);

    #[cfg(feature = "semantic")]
    let capabilities = {
        let mut caps = capabilities;
        if let Some(ctx) = semantic {
            enrich_reachability(&mut caps.findings, ctx);
        }
        caps
    };

    let fn_fingerprints = compute_fingerprints(&ir);

    Ok(AnalysisResult {
        violations,
        capabilities,
        data_flows: ir.data_flows,
        fn_fingerprints,
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
/// Returns an error when a manifest exists but cannot be read.
pub fn discover_workspace_root(start: &Path) -> Result<Option<PathBuf>, LintError> {
    let start_dir = match (start.is_dir(), start.parent()) {
        (true, _) => start,
        (false, Some(parent)) => parent,
        (false, None) => return Ok(None),
    };

    let mut nearest_package: Option<PathBuf> = None;
    for dir in start_dir.ancestors() {
        let cargo_toml = dir.join("Cargo.toml");
        let (has_workspace, has_package) = read_manifest_presence(&cargo_toml)?;
        match (has_workspace, has_package, nearest_package.is_some()) {
            (true, _, _) => return Ok(Some(dir.to_path_buf())),
            (false, true, false) => nearest_package = Some(dir.to_path_buf()),
            _ => {}
        }
    }
    Ok(nearest_package)
}

fn read_manifest_presence(cargo_toml: &Path) -> Result<ManifestPresence, LintError> {
    let contents = match fs::read_to_string(cargo_toml) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((false, false)),
        Err(error) => return Err(LintError::IoError(error)),
    };
    let table: toml::Table = contents.parse()?;
    Ok((
        contains_manifest_table(&table, "workspace"),
        contains_manifest_table(&table, "package"),
    ))
}

fn contains_manifest_table(table: &toml::Table, section_name: &str) -> bool {
    table
        .get(section_name)
        .and_then(toml::Value::as_table)
        .is_some()
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
/// When `build_source` is `Some`, its findings are tagged with
/// `ExecutionContext::BuildHook` and appended to the main result's capability profile.
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

    let build_caps = analyze_build_script(build_path, build_src, config, semantic)?.capabilities;

    let mut merged = result.capabilities.findings.into_vec();
    merged.extend(build_caps.findings);
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
        (true, true) => AnalysisTier::DataFlow,
        (true, false) => AnalysisTier::Semantic,
        (false, _) => AnalysisTier::Syntactic,
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
    use std::sync::Arc;

    // Group finding indices by file so the call graph is built once per file.
    let mut by_file: BTreeMap<Arc<str>, Vec<usize>> = BTreeMap::new();
    for (idx, finding) in findings.iter().enumerate() {
        by_file
            .entry(Arc::clone(&finding.location.file))
            .or_default()
            .push(idx);
    }

    for (file, indices) in &by_file {
        let Some(analysis) = ctx.analyze_file(file) else {
            continue;
        };
        let lines: Vec<usize> = indices.iter().map(|&i| findings[i].location.line).collect();
        let results = analysis.check_reachability_batch(&lines);
        for (pos, &idx) in indices.iter().enumerate() {
            findings[idx].reachable = Some(results[pos]);
        }
    }
}
