use std::fs;
use std::path::{Component, Path, PathBuf};

use pedant_types::{AnalysisTier, ExecutionContext};

use crate::analysis_result::AnalysisResult;
use crate::capabilities::{draft_capabilities, project_analysis};
use crate::check_config::CheckConfig;
use crate::ir;
use crate::ir::DataFlowFact;
use crate::ir::extract::{compute_fingerprints, parse_source};
use crate::ir::semantic::SemanticContext;
use crate::project::{FileShape, project_shape};
use crate::style::check_style;

struct ManifestPresence {
    workspace: bool,
    package: bool,
    workspace_pointer: Option<Box<str>>,
}

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
    /// A package's explicit workspace manifest could not be read.
    #[error("failed to read pointed workspace manifest {path}: {source}")]
    PointedWorkspaceRead {
        /// The `Cargo.toml` selected by `package.workspace`.
        path: PathBuf,
        /// The filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A package's explicit workspace manifest is not valid TOML.
    #[error("failed to parse pointed workspace manifest {path}: {source}")]
    PointedWorkspaceParse {
        /// The `Cargo.toml` selected by `package.workspace`.
        path: PathBuf,
        /// The TOML parser failure.
        #[source]
        source: toml::de::Error,
    },
    /// A package's explicit workspace manifest lacks its required table.
    #[error("pointed workspace manifest {path} does not declare [workspace]")]
    PointedWorkspaceDeclarationMissing {
        /// The `Cargo.toml` selected by `package.workspace`.
        path: PathBuf,
    },
    /// A package's explicit workspace pointer is not a TOML string.
    #[error("package.workspace in {path} must be a string")]
    WorkspacePointerNotString {
        /// The package manifest holding the invalid pointer.
        path: PathBuf,
    },
    /// One manifest cannot be both the local workspace and point elsewhere.
    #[error("manifest {path} declares both [workspace] and package.workspace")]
    WorkspacePointerWithLocalWorkspace {
        /// The contradictory package manifest.
        path: PathBuf,
    },
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
    Ok(analyze_inner(file_path, source, config, semantic, None)?.0)
}

/// Like [`analyze`], but tags all capability findings with `ExecutionContext::BuildHook`.
pub fn analyze_build_script(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, syn::Error> {
    Ok(analyze_inner(
        file_path,
        source,
        config,
        semantic,
        Some(ExecutionContext::BuildHook),
    )?
    .0)
}

/// [`analyze`], plus the [`FileShape`] that whole-crate checks consume.
///
/// [`analyze`] discards the shape. Callers that also run
/// [`check_project`](crate::project::check_project) take it from here, since
/// projecting it later would mean parsing the file a second time.
pub fn analyze_with_shape(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<(AnalysisResult, FileShape), syn::Error> {
    analyze_inner(file_path, source, config, semantic, None)
}

/// [`analyze_build_script`], plus the [`FileShape`] whole-crate checks consume.
pub fn analyze_build_script_with_shape(
    file_path: &str,
    source: &str,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
) -> Result<(AnalysisResult, FileShape), syn::Error> {
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
) -> Result<(AnalysisResult, FileShape), syn::Error> {
    let syntax = parse_source(file_path, source)?;
    let mut ir = ir::extract(file_path, &syntax, semantic);
    ir.source_line_count = source.lines().count();
    let violations = check_style(&ir, config).into_boxed_slice();
    let shape = project_shape(&ir, config);
    let draft = draft_capabilities(&ir, execution_context);

    #[cfg(feature = "semantic")]
    let draft = {
        let mut draft = draft;
        if let Some(ctx) = semantic {
            enrich_reachability(draft.entries_mut(), ctx);
        }
        draft
    };

    let capabilities = project_analysis(&ir, draft);

    let fn_fingerprints = compute_fingerprints(&ir);

    Ok((
        AnalysisResult {
            violations,
            capabilities,
            data_flows: ir.data_flows,
            fn_fingerprints,
        },
        shape,
    ))
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
/// An explicit `package.workspace` selects that workspace before an ancestor
/// can be considered. Otherwise, a directory containing a `Cargo.toml` with
/// `[workspace]` is preferred, with the nearest package as the fallback.
/// Returns an error when a manifest exists but cannot be read or when an
/// explicit workspace pointer cannot identify a workspace manifest.
pub fn discover_workspace_root(start: &Path) -> Result<Option<PathBuf>, LintError> {
    let start_dir = match (start.is_dir(), start.parent()) {
        (true, _) => start,
        (false, Some(parent)) => parent,
        (false, None) => return Ok(None),
    };

    let mut nearest_package: Option<PathBuf> = None;
    for dir in start_dir.ancestors() {
        let cargo_toml = dir.join("Cargo.toml");
        let presence = read_manifest_presence(&cargo_toml)?;
        match (
            presence.workspace,
            presence.package,
            nearest_package.is_some(),
            presence.workspace_pointer,
        ) {
            (true, _, _, _) => return Ok(Some(dir.to_path_buf())),
            (false, true, false, Some(pointer)) => {
                return pointed_workspace_root(dir, &pointer).map(Some);
            }
            (false, true, false, None) => nearest_package = Some(dir.to_path_buf()),
            _ => {}
        }
    }
    Ok(nearest_package)
}

/// Walk ancestors of `file` to the nearest directory holding a `Cargo.toml`.
///
/// That directory is the file's crate root: Cargo resolves a source file's
/// package by exactly this rule. Returns `None` for a file with no manifest
/// above it, which has no crate to belong to.
pub fn discover_crate_root(file: &Path) -> Option<&Path> {
    let mut dir = file.parent()?;
    loop {
        match dir.join("Cargo.toml").is_file() {
            true => return Some(dir),
            false => dir = dir.parent()?,
        }
    }
}

fn read_manifest_presence(cargo_toml: &Path) -> Result<ManifestPresence, LintError> {
    let contents = match fs::read_to_string(cargo_toml) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManifestPresence {
                workspace: false,
                package: false,
                workspace_pointer: None,
            });
        }
        Err(error) => return Err(LintError::IoError(error)),
    };
    let table: toml::Table = contents.parse()?;
    let package = table.get("package").and_then(toml::Value::as_table);
    let workspace_pointer = match package.and_then(|package| package.get("workspace")) {
        Some(toml::Value::String(pointer)) => Some(Box::from(pointer.as_str())),
        Some(_) => {
            return Err(LintError::WorkspacePointerNotString {
                path: cargo_toml.to_path_buf(),
            });
        }
        None => None,
    };
    let workspace = contains_manifest_table(&table, "workspace");
    if let (true, true) = (workspace, workspace_pointer.is_some()) {
        return Err(LintError::WorkspacePointerWithLocalWorkspace {
            path: cargo_toml.to_path_buf(),
        });
    }
    Ok(ManifestPresence {
        workspace,
        package: package.is_some(),
        workspace_pointer,
    })
}

fn pointed_workspace_root(package_root: &Path, pointer: &str) -> Result<PathBuf, LintError> {
    let workspace_root = lexical_path(package_root.join(pointer));
    let manifest = workspace_root.join("Cargo.toml");
    let contents =
        fs::read_to_string(&manifest).map_err(|source| LintError::PointedWorkspaceRead {
            path: manifest.clone(),
            source,
        })?;
    let table =
        contents
            .parse::<toml::Table>()
            .map_err(|source| LintError::PointedWorkspaceParse {
                path: manifest.clone(),
                source,
            })?;
    match contains_manifest_table(&table, "workspace") {
        true => Ok(workspace_root),
        false => Err(LintError::PointedWorkspaceDeclarationMissing { path: manifest }),
    }
}

fn lexical_path(path: PathBuf) -> PathBuf {
    let rooted = path.has_root();
    path.components().fold(PathBuf::new(), |mut result, part| {
        match part {
            Component::ParentDir => resolve_parent(&mut result, rooted),
            Component::CurDir => {}
            _ => result.push(part.as_os_str()),
        }
        result
    })
}

fn resolve_parent(path: &mut PathBuf, rooted: bool) {
    match path.components().next_back() {
        Some(Component::Normal(_)) => {
            path.pop();
        }
        Some(Component::ParentDir) | None if !rooted => path.push(".."),
        _ => {}
    }
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

/// Analyze a source file and optionally merge build-script capability analysis.
///
/// When `build_source` is `Some`, its findings are tagged with
/// `ExecutionContext::BuildHook` and merged after the main source's, keeping
/// main-source findings first. Both inputs are parsed Rust, so the merged
/// attribution stays `Complete`.
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
    result.capabilities = result.capabilities.merge(build_caps);

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
fn enrich_reachability(entries: &mut [crate::capabilities::DraftedFinding], ctx: &SemanticContext) {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // Group finding indices by file so the call graph is built once per file.
    let mut by_file: BTreeMap<Arc<str>, Vec<usize>> = BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        by_file
            .entry(Arc::clone(&entry.finding.location.file))
            .or_default()
            .push(idx);
    }

    for (file, indices) in &by_file {
        let Some(analysis) = ctx.analyze_file(file) else {
            continue;
        };
        let lines: Vec<usize> = indices
            .iter()
            .map(|&i| entries[i].finding.location.line)
            .collect();
        let results = analysis.check_reachability_batch(&lines);
        for (pos, &idx) in indices.iter().enumerate() {
            entries[idx].finding.reachable = Some(results[pos]);
        }
    }
}
