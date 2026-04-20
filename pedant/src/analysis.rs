use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use pedant_core::AnalysisResult;
use pedant_core::SemanticContext;
use pedant_core::check_config::CheckConfig;
use pedant_core::hash::compute_source_hash;
use pedant_core::lint::{analyze, analyze_build_script, discover_build_script};
use pedant_lang::FileClassification;
use pedant_types::Language;

use crate::ProcessError;
use crate::config::Cli;

type AnalyzeFn = fn(
    &str,
    &str,
    &CheckConfig,
    Option<&SemanticContext>,
) -> Result<AnalysisResult, pedant_core::ParseError>;

type FileAnalysis<'a> = (AnalyzeFn, Option<&'a SemanticContext>);

pub(crate) struct AnalysisContext<'a> {
    pub(crate) base_config: &'a CheckConfig,
    pub(crate) file_config: Option<&'a pedant_core::check_config::ConfigFile>,
    pub(crate) semantic: Option<&'a SemanticContext>,
}

pub(crate) struct AnalysisAccumulator {
    pub(crate) violations: Vec<pedant_core::Violation>,
    pub(crate) findings: Vec<pedant_types::CapabilityFinding>,
    pub(crate) data_flows: Vec<pedant_core::ir::DataFlowFact>,
    pub(crate) had_error: bool,
}

impl AnalysisAccumulator {
    pub(crate) fn with_capacity(file_count: usize) -> Self {
        Self {
            violations: Vec::with_capacity(file_count),
            findings: Vec::with_capacity(file_count),
            data_flows: Vec::new(),
            had_error: false,
        }
    }

    pub(crate) fn handle(
        &mut self,
        result: Result<AnalysisResult, ProcessError>,
        context: &str,
        stderr: &mut impl Write,
    ) {
        match result {
            Ok(r) => {
                self.violations.append(&mut r.violations.into_vec());
                self.findings
                    .append(&mut r.capabilities.findings.into_vec());
                self.data_flows.extend_from_slice(&r.data_flows);
            }
            Err(e) => {
                crate::report_error(stderr, format_args!("{context}: {e}"));
                self.had_error = true;
            }
        }
    }
}

/// Select the input source (stdin vs files) and run analysis, returning a source
/// hash when attestation mode requires one.
pub(crate) fn run_analysis(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    match (cli.attestation, cli.stdin) {
        (true, true) => attest_stdin(ctx.base_config, acc, stderr),
        (true, false) => Some(attest_files(cli, ctx, acc, stderr)),
        (false, true) => {
            acc.handle(process_stdin(ctx.base_config), "error", stderr);
            None
        }
        (false, false) => {
            analyze_file_list(cli, ctx, None, acc, stderr);
            None
        }
    }
}

/// Load `SemanticContext` when `--semantic` is requested.
///
/// Returns `None` (with a stderr warning) if loading fails or the flag is absent.
#[cfg(feature = "semantic")]
pub(crate) fn load_semantic_if_requested(
    cli: &Cli,
    stderr: &mut impl Write,
) -> Option<SemanticContext> {
    use std::time::Instant;

    if !cli.semantic {
        return None;
    }

    let root = match discover_semantic_workspace_root(&cli.files) {
        Ok(Some(root)) => root,
        Ok(None) => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: no Cargo.toml found, falling back to syntactic analysis"
                ),
            );
            return None;
        }
        Err(error) => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: failed to discover workspace root: {error}; falling back to syntactic analysis"
                ),
            );
            return None;
        }
    };

    let start = Instant::now();
    let ctx = SemanticContext::load(&root);
    let elapsed = start.elapsed();

    match ctx {
        Some(c) => {
            crate::report_error(
                stderr,
                format_args!(
                    "semantic: loaded workspace in {:.1}s",
                    elapsed.as_secs_f64()
                ),
            );
            Some(c)
        }
        None => {
            crate::report_error(
                stderr,
                format_args!(
                    "warning: --semantic: failed to load workspace at {}, falling back to syntactic analysis",
                    root.display()
                ),
            );
            None
        }
    }
}

#[cfg(feature = "semantic")]
fn discover_semantic_workspace_root(
    files: &[String],
) -> Result<Option<Box<Path>>, pedant_core::lint::LintError> {
    use pedant_core::lint::discover_workspace_root;

    let mut last_error = None;

    for file in files {
        match discover_workspace_root(Path::new(file.as_str())) {
            Ok(Some(root)) => return Ok(Some(root.into_boxed_path())),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// Stub when the `semantic` feature is disabled — always returns `None`.
#[cfg(not(feature = "semantic"))]
pub(crate) fn load_semantic_if_requested(
    _cli: &Cli,
    _stderr: &mut impl Write,
) -> Option<SemanticContext> {
    None
}

fn attest_stdin(
    config: &CheckConfig,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    let source = match read_stdin_source() {
        Ok(s) => s,
        Err(e) => {
            crate::report_error(stderr, format_args!("error: {e}"));
            acc.had_error = true;
            return None;
        }
    };
    acc.handle(
        analyze("<stdin>", &source, config, None).map_err(ProcessError::from),
        "error",
        stderr,
    );
    let mut sources = BTreeMap::new();
    sources.insert(Box::<str>::from("<stdin>"), source);
    Some(compute_source_hash(&sources))
}

fn attest_files(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Box<str> {
    let mut sources = BTreeMap::new();
    analyze_file_list(cli, ctx, Some(&mut sources), acc, stderr);
    compute_source_hash(&sources)
}

fn analyze_file_list(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    mut sources: Option<&mut BTreeMap<Box<str>, String>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let mut seen_build_roots: BTreeSet<Box<Path>> = BTreeSet::new();
    for file_path in &cli.files {
        let path = Path::new(file_path.as_str());
        match pedant_lang::classify_path(path) {
            FileClassification::SourceAndManifest(lang) => {
                analyze_non_rust_file(file_path, path, lang, acc, stderr);
                analyze_manifest_file(file_path, path, acc, stderr);
            }
            FileClassification::Source(lang) => {
                analyze_non_rust_file(file_path, path, lang, acc, stderr);
            }
            FileClassification::Manifest => {
                analyze_manifest_file(file_path, path, acc, stderr);
            }
            FileClassification::Unsupported => {}
            FileClassification::Rust => {
                analyze_rust_file(
                    file_path,
                    cli,
                    ctx,
                    sources.as_deref_mut(),
                    &mut seen_build_roots,
                    acc,
                    stderr,
                );
            }
        }
    }
}

fn analyze_rust_file(
    file_path: &str,
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    mut sources: Option<&mut BTreeMap<Box<str>, String>>,
    seen_build_roots: &mut BTreeSet<Box<Path>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(cfg) = ctx.base_config.resolve_for_path(file_path, ctx.file_config) else {
        return;
    };
    let (analyze_fn, semantic) = match classify_rust_analysis(file_path, ctx.semantic) {
        Ok(classification) => classification,
        Err(error) => {
            crate::report_error(stderr, format_args!("build script discovery: {error}"));
            acc.had_error = true;
            return;
        }
    };
    analyze_single_file(
        file_path,
        analyze_fn,
        &cfg,
        semantic,
        reborrow_sources(&mut sources),
        acc,
        stderr,
    );
    if let Err(error) = discover_and_analyze_build_script(
        file_path,
        &cli.files,
        &cfg,
        sources,
        seen_build_roots,
        acc,
        stderr,
    ) {
        crate::report_error(stderr, format_args!("build script discovery: {error}"));
        acc.had_error = true;
    }
}

fn analyze_non_rust_file(
    file_path: &str,
    path: &Path,
    language: Language,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(source) = read_source(file_path, acc, stderr) else {
        return;
    };
    let profile = pedant_lang::analyze_file(path, &source, language);
    acc.findings.extend(profile.findings.into_vec());
}

fn analyze_manifest_file(
    file_path: &str,
    path: &Path,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(source) = read_source(file_path, acc, stderr) else {
        return;
    };
    let profile = pedant_lang::analyze_manifest(path, &source);
    acc.findings.extend(profile.findings.into_vec());
}

/// Read a source file, reporting errors to stderr and marking the accumulator.
fn read_source(
    file_path: &str,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<String> {
    match fs::read_to_string(file_path) {
        Ok(s) => Some(s),
        Err(e) => {
            crate::report_error(stderr, format_args!("{file_path}: {e}"));
            acc.had_error = true;
            None
        }
    }
}

fn classify_rust_analysis<'a>(
    file_path: &str,
    semantic: Option<&'a SemanticContext>,
) -> Result<FileAnalysis<'a>, ProcessError> {
    match is_explicit_build_script(file_path)? {
        true => Ok((analyze_build_script, None)),
        false => Ok((analyze, semantic)),
    }
}

/// Find the crate root by walking up from a file path to locate `Cargo.toml`.
fn find_crate_root(file_path: &str) -> Option<&Path> {
    let mut dir = Path::new(file_path).parent()?;
    loop {
        match dir.join("Cargo.toml").is_file() {
            true => return Some(dir),
            false => dir = dir.parent()?,
        }
    }
}

fn is_explicit_build_script(file_path: &str) -> Result<bool, ProcessError> {
    let Some(crate_root) = find_crate_root(file_path) else {
        return Ok(false);
    };
    let Some(build_path) =
        discover_build_script(crate_root).map_err(|source| ProcessError::BuildScriptDiscovery {
            crate_root: crate_root.display().to_string().into_boxed_str(),
            source,
        })?
    else {
        return Ok(false);
    };

    Ok(paths_match(Path::new(file_path), &build_path))
}

fn paths_match(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(canonical_left), Ok(canonical_right)) => canonical_left == canonical_right,
        _ => left == right,
    }
}

fn discover_and_analyze_build_script(
    file_path: &str,
    cli_files: &[String],
    config: &CheckConfig,
    sources: Option<&mut BTreeMap<Box<str>, String>>,
    seen_roots: &mut BTreeSet<Box<Path>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Result<(), ProcessError> {
    let Some(crate_root) = find_crate_root(file_path) else {
        return Ok(());
    };
    if seen_roots.contains(crate_root) {
        return Ok(());
    }
    seen_roots.insert(Box::from(crate_root));
    let build_path = match discover_build_script(crate_root) {
        Ok(Some(path)) => path,
        Ok(None) => return Ok(()),
        Err(source) => {
            return Err(ProcessError::BuildScriptDiscovery {
                crate_root: crate_root.display().to_string().into_boxed_str(),
                source,
            });
        }
    };
    let build_path_label = build_path.to_string_lossy().into_owned();
    // Skip if the build script is already in the CLI file list.
    if cli_files
        .iter()
        .any(|file| paths_match(Path::new(file), &build_path))
    {
        return Ok(());
    }
    analyze_single_file(
        &build_path_label,
        analyze_build_script,
        config,
        None,
        sources,
        acc,
        stderr,
    );
    Ok(())
}

fn analyze_single_file(
    file_path: &str,
    analyze_fn: AnalyzeFn,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
    sources: Option<&mut BTreeMap<Box<str>, String>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(source) = read_source(file_path, acc, stderr) else {
        return;
    };
    acc.handle(
        analyze_fn(file_path, &source, config, semantic).map_err(ProcessError::from),
        file_path,
        stderr,
    );
    if let Some(sources) = sources {
        sources.insert(Box::from(file_path), source);
    }
}

fn read_stdin_source() -> Result<String, ProcessError> {
    use std::io::Read;
    let mut source = String::new();
    std::io::stdin()
        .read_to_string(&mut source)
        .map_err(ProcessError::StdinRead)?;
    Ok(source)
}

fn process_stdin(config: &CheckConfig) -> Result<AnalysisResult, ProcessError> {
    let source = read_stdin_source()?;
    Ok(analyze("<stdin>", &source, config, None)?)
}

/// Reborrow an `Option<&mut T>` so the original option remains usable.
fn reborrow_sources<'a>(
    opt: &'a mut Option<&mut BTreeMap<Box<str>, String>>,
) -> Option<&'a mut BTreeMap<Box<str>, String>> {
    opt.as_mut().map(|s| &mut **s)
}
