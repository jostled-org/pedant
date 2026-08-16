use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::{
    analyze_build_script_with_shape, analyze_with_shape, discover_build_script, discover_crate_root,
};
use pedant_core::project::FileShape;
use pedant_core::{AnalysisResult, SemanticContext};
use pedant_lang::FileClassification;
use pedant_types::Language;

use crate::ProcessError;

use super::{AnalysisAccumulator, AnalysisContext};

type AnalyzeFn = fn(
    &str,
    &str,
    &CheckConfig,
    Option<&SemanticContext>,
) -> Result<(AnalysisResult, FileShape), pedant_core::ParseError>;

struct RustAnalysisPlan<'a> {
    analyze_fn: AnalyzeFn,
    semantic: Option<&'a SemanticContext>,
    crate_root: Option<Box<Path>>,
    build_script: Option<PathBuf>,
}

pub(super) fn analyze_file_list(
    files: &[String],
    ctx: &AnalysisContext<'_>,
    mut sources: Option<&mut BTreeMap<Box<str>, String>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let mut seen_build_roots: BTreeSet<Box<Path>> = BTreeSet::new();
    for file_path in files {
        let path = Path::new(file_path.as_str());
        match pedant_lang::classify_path(path) {
            FileClassification::SourceAndManifest(lang) => {
                let Some(source) = read_source(file_path, acc, stderr) else {
                    continue;
                };
                analyze_non_rust_source(path, &source, lang, acc);
                analyze_manifest_source(path, &source, acc);
            }
            FileClassification::Source(lang) => {
                let Some(source) = read_source(file_path, acc, stderr) else {
                    continue;
                };
                analyze_non_rust_source(path, &source, lang, acc);
            }
            FileClassification::Manifest => {
                let Some(source) = read_source(file_path, acc, stderr) else {
                    continue;
                };
                analyze_manifest_source(path, &source, acc);
            }
            FileClassification::Unsupported => {}
            FileClassification::Rust => {
                analyze_rust_file(
                    file_path,
                    files,
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
    cli_files: &[String],
    ctx: &AnalysisContext<'_>,
    mut sources: Option<&mut BTreeMap<Box<str>, String>>,
    seen_build_roots: &mut BTreeSet<Box<Path>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(cfg) = ctx.base_config.resolve_for_path(file_path, ctx.file_config) else {
        return;
    };
    let plan = match classify_rust_analysis(file_path, ctx.semantic) {
        Ok(classification) => classification,
        Err(error) => {
            crate::report_error(stderr, format_args!("build script discovery: {error}"));
            acc.had_error = true;
            return;
        }
    };
    analyze_single_file(
        file_path,
        plan.analyze_fn,
        &cfg,
        plan.semantic,
        reborrow_sources(&mut sources),
        acc,
        stderr,
    );
    if let Err(error) = discover_and_analyze_build_script(
        cli_files,
        &cfg,
        &plan,
        sources,
        seen_build_roots,
        acc,
        stderr,
    ) {
        crate::report_error(stderr, format_args!("build script discovery: {error}"));
        acc.had_error = true;
    }
}

fn analyze_non_rust_source(
    path: &Path,
    source: &str,
    language: Language,
    acc: &mut AnalysisAccumulator,
) {
    let analysis = pedant_lang::analyze_file(path, source, language);
    acc.findings
        .extend(analysis.into_profile().findings.into_vec());
}

fn analyze_manifest_source(path: &Path, source: &str, acc: &mut AnalysisAccumulator) {
    let analysis = pedant_lang::analyze_manifest(path, source);
    acc.findings
        .extend(analysis.into_profile().findings.into_vec());
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
) -> Result<RustAnalysisPlan<'a>, ProcessError> {
    let Some(crate_root) = find_crate_root(file_path) else {
        return Ok(RustAnalysisPlan {
            analyze_fn: analyze_with_shape,
            semantic,
            crate_root: None,
            build_script: None,
        });
    };

    let build_script =
        discover_build_script(crate_root).map_err(|source| ProcessError::BuildScriptDiscovery {
            crate_root: crate_root.display().to_string().into_boxed_str(),
            source: Box::new(source),
        })?;
    let is_build_script = match build_script.as_deref() {
        Some(build_path) => paths_match(Path::new(file_path), build_path),
        None => false,
    };

    match is_build_script {
        true => Ok(RustAnalysisPlan {
            analyze_fn: analyze_build_script_with_shape,
            semantic: None,
            crate_root: Some(Box::from(crate_root)),
            build_script,
        }),
        false => Ok(RustAnalysisPlan {
            analyze_fn: analyze_with_shape,
            semantic,
            crate_root: Some(Box::from(crate_root)),
            build_script,
        }),
    }
}

/// Find the crate root by walking up from a file path to locate `Cargo.toml`.
fn find_crate_root(file_path: &str) -> Option<&Path> {
    discover_crate_root(Path::new(file_path))
}

fn paths_match(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(canonical_left), Ok(canonical_right)) => canonical_left == canonical_right,
        _ => left == right,
    }
}

fn discover_and_analyze_build_script(
    cli_files: &[String],
    config: &CheckConfig,
    plan: &RustAnalysisPlan<'_>,
    sources: Option<&mut BTreeMap<Box<str>, String>>,
    seen_roots: &mut BTreeSet<Box<Path>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Result<(), ProcessError> {
    let Some(crate_root) = plan.crate_root.as_deref() else {
        return Ok(());
    };
    if seen_roots.contains(crate_root) {
        return Ok(());
    }
    seen_roots.insert(Box::from(crate_root));
    let Some(build_path) = plan.build_script.as_ref() else {
        return Ok(());
    };
    let build_path_label = build_path.to_string_lossy().into_owned();
    // Skip if the build script is already in the CLI file list.
    if cli_files
        .iter()
        .any(|file| paths_match(Path::new(file), build_path))
    {
        return Ok(());
    }
    analyze_single_file(
        &build_path_label,
        analyze_build_script_with_shape,
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

pub(super) fn read_stdin_source() -> Result<String, ProcessError> {
    use std::io::Read;
    let mut source = String::new();
    std::io::stdin()
        .read_to_string(&mut source)
        .map_err(ProcessError::StdinRead)?;
    Ok(source)
}

pub(super) fn process_stdin(
    config: &CheckConfig,
) -> Result<(AnalysisResult, FileShape), ProcessError> {
    let source = read_stdin_source()?;
    Ok(analyze_with_shape("<stdin>", &source, config, None)?)
}

/// Reborrow an `Option<&mut T>` so the original option remains usable.
fn reborrow_sources<'a>(
    opt: &'a mut Option<&mut BTreeMap<Box<str>, String>>,
) -> Option<&'a mut BTreeMap<Box<str>, String>> {
    opt.as_mut().map(|s| &mut **s)
}
