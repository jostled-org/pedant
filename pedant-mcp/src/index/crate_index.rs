use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::gate::{GateInputSummary, GateVerdict};
use pedant_core::{AnalysisResult, Config, GateConfig, SemanticContext};
use pedant_lang::FileClassification;
use pedant_types::CapabilityProfile;
use walkdir::WalkDir;

use super::IndexError;

/// Cached analysis results for a single crate.
pub(super) struct CrateIndex {
    pub(super) root: PathBuf,
    pub(super) files: BTreeMap<Box<str>, AnalysisResult>,
    pub(super) profile: CapabilityProfile,
    pub(super) gate_verdicts: Box<[GateVerdict]>,
}

/// Build the index for a single crate: analyze Rust sources, non-Rust sources,
/// and manifest/hook-entrypoint files.
pub(super) fn build_crate_index(
    crate_root: &Path,
    config: &Config,
    gate_config: &GateConfig,
    semantic: Option<&SemanticContext>,
) -> Result<CrateIndex, IndexError> {
    let mut files = BTreeMap::new();

    for source_path in discover_rust_sources(crate_root) {
        let result = analyze_source_file(&source_path, config, semantic)?;
        let path_str: Box<str> = source_path.to_string_lossy().into();
        files.insert(path_str, result);
    }

    let build_rs = crate_root.join("build.rs");
    if build_rs.is_file() {
        let result = analyze_build_script_file(&build_rs, config, semantic)?;
        let path_str: Box<str> = build_rs.to_string_lossy().into();
        files.insert(path_str, result);
    }

    // Analyze non-Rust source files and dual-role files like `.go`.
    for source_path in discover_non_rust_sources(crate_root) {
        let result = analyze_non_rust_or_manifest(&source_path)?;
        let path_str: Box<str> = source_path.to_string_lossy().into();
        files.insert(path_str, result);
    }

    // Analyze manifest and hook-entrypoint files.
    for manifest_path in discover_manifests(crate_root) {
        let result = analyze_manifest_file(&manifest_path)?;
        let path_str: Box<str> = manifest_path.to_string_lossy().into();
        files.insert(path_str, result);
    }

    let profile = aggregate_profile(&files);
    let gate_verdicts = compute_gate_verdicts(&profile, &files, gate_config);

    Ok(CrateIndex {
        root: crate_root.to_path_buf(),
        files,
        profile,
        gate_verdicts,
    })
}

/// Recompute a crate's aggregated profile and gate verdicts from its cached file results.
pub(super) fn recompute_aggregates(crate_index: &mut CrateIndex, gate_config: &GateConfig) {
    crate_index.profile = aggregate_profile(&crate_index.files);
    crate_index.gate_verdicts =
        compute_gate_verdicts(&crate_index.profile, &crate_index.files, gate_config);
}

/// Collect all per-file capability findings into a single aggregated profile.
fn aggregate_profile(files: &BTreeMap<Box<str>, AnalysisResult>) -> CapabilityProfile {
    let findings_count: usize = files.values().map(|r| r.capabilities.findings.len()).sum();
    let mut all_findings = Vec::with_capacity(findings_count);
    all_findings.extend(
        files
            .values()
            .flat_map(|r| r.capabilities.findings.iter().cloned()),
    );
    CapabilityProfile {
        findings: all_findings.into(),
    }
}

fn compute_gate_verdicts(
    profile: &CapabilityProfile,
    files: &BTreeMap<Box<str>, AnalysisResult>,
    gate_config: &GateConfig,
) -> Box<[GateVerdict]> {
    let data_flows: Box<[_]> = files
        .values()
        .flat_map(|r| r.data_flows.iter().cloned())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let summary = GateInputSummary::from_analysis(&profile.findings, &data_flows);
    pedant_core::gate::evaluate_gate_rules(&summary, gate_config)
}

/// Find all .rs files under the crate's src/ directory.
fn discover_rust_sources(crate_root: &Path) -> impl Iterator<Item = PathBuf> {
    let src_dir = crate_root.join("src");
    let walker = match src_dir.is_dir() {
        true => Some(WalkDir::new(src_dir)),
        false => None,
    };
    walker
        .into_iter()
        .flat_map(IntoIterator::into_iter)
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
}

/// Find non-Rust source files under the crate directory.
///
/// Walks the entire crate directory, skipping `target/`, `.git/`, and `node_modules/`.
fn discover_non_rust_sources(crate_root: &Path) -> Box<[PathBuf]> {
    walk_crate_files(crate_root)
        .filter(|path| {
            matches!(
                pedant_lang::classify_path(path),
                FileClassification::Source(_) | FileClassification::SourceAndManifest(_)
            )
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Find manifest and hook-entrypoint files in the crate root directory.
///
/// Only checks the immediate crate root — manifests in subdirectories
/// are intentionally ignored.
fn discover_manifests(crate_root: &Path) -> Box<[PathBuf]> {
    fs::read_dir(crate_root)
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            matches!(
                pedant_lang::classify_path(path),
                FileClassification::Manifest
            )
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

/// Walk all files under the crate root, skipping build artifacts and VCS directories.
fn walk_crate_files(crate_root: &Path) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(crate_root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or("");
            !matches!(name, "target" | ".git" | "node_modules")
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
}

/// Analyze a non-Rust source file or manifest via `pedant-lang`.
///
/// Tries language detection first; if the file is a recognized language, analyzes
/// it as source. Otherwise falls back to manifest analysis. Used by `reindex_file`
/// for incremental updates of non-Rust files.
pub(super) fn analyze_non_rust_or_manifest(path: &Path) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    let lang_profile = pedant_lang::detect_language(path, &source)
        .map(|lang| pedant_lang::analyze_file(path, &source, lang));
    let manifest_profile = pedant_lang::analyze_manifest(path, &source);

    let mut findings = Vec::new();
    if let Some(lp) = lang_profile {
        findings.extend(lp.findings.iter().cloned());
    }
    findings.extend(manifest_profile.findings.iter().cloned());

    Ok(analysis_result_from_profile(CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }))
}

/// Analyze a manifest or hook-entrypoint file via `pedant-lang`.
fn analyze_manifest_file(path: &Path) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    let profile = pedant_lang::analyze_manifest(path, &source);
    Ok(analysis_result_from_profile(profile))
}

/// Build an `AnalysisResult` from a `CapabilityProfile` with no violations or data flows.
fn analysis_result_from_profile(profile: CapabilityProfile) -> AnalysisResult {
    AnalysisResult {
        violations: Box::new([]),
        capabilities: profile,
        data_flows: std::sync::Arc::from([]),
        fn_fingerprints: Box::new([]),
    }
}

/// Analyze a single Rust source file.
fn analyze_source_file(
    path: &Path,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let path_lossy = path.to_string_lossy();
    analyze_source_at(path, &path_lossy, config, semantic)
}

/// Analyze a source file with a pre-computed path string.
pub(super) fn analyze_source_at(
    path: &Path,
    path_str: &str,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    pedant_core::analyze(path_str, &source, config, semantic).map_err(|e| IndexError::RustParse {
        path: path_str.into(),
        source: e,
    })
}

/// Analyze a build.rs file, tagging all findings as build-script.
fn analyze_build_script_file(
    path: &Path,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let path_lossy = path.to_string_lossy();
    analyze_build_script_at(path, &path_lossy, config, semantic)
}

/// Analyze a build script with a pre-computed path string.
pub(super) fn analyze_build_script_at(
    path: &Path,
    path_str: &str,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    pedant_core::analyze_build_script(path_str, &source, config, semantic).map_err(|e| {
        IndexError::RustParse {
            path: path_str.into(),
            source: e,
        }
    })
}

pub(super) fn read_file(path: &Path) -> Result<String, IndexError> {
    fs::read_to_string(path).map_err(|e| IndexError::Io {
        path: path.to_string_lossy().into(),
        source: e,
    })
}

pub(super) fn parse_toml<T: serde::de::DeserializeOwned>(
    content: &str,
    path: &Path,
) -> Result<T, IndexError> {
    toml::from_str(content).map_err(|e| IndexError::TomlParse {
        path: path.to_string_lossy().into(),
        source: e,
    })
}
