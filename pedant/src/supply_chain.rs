use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::SystemTime;

use pedant_core::check_config::CheckConfig;
use pedant_core::hash::compute_source_hash;
use pedant_core::lint::{analyze, analyze_build_script, discover_build_script};
use pedant_types::{
    AnalysisCompleteness, AnalysisTier, AttestationContent, Capability, CapabilityDiff,
    CapabilityProfile,
};
use semver::Version;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir, tempdir};

use crate::config::FailOn;

const ECOSYSTEM: &str = "cargo";
const SPEC_VERSION: &str = "0.1.0";

#[derive(Debug, thiserror::Error)]
enum SupplyChainError {
    #[error("no Cargo.lock found in {0}; generate and commit a lockfile first")]
    MissingLockfile(Box<str>),
    #[error("failed to determine current directory: {0}")]
    CurrentDir(#[source] std::io::Error),
    #[error("failed to create temp directory: {0}")]
    TempDir(#[source] std::io::Error),
    #[error("failed to run cargo vendor: {0}")]
    CargoVendorSpawn(#[source] std::io::Error),
    #[error("cargo vendor failed: {0}")]
    CargoVendor(Box<str>),
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write file {path}: {source}")]
    WriteFile {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to delete path {path}: {source}")]
    DeletePath {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("manifest {path} is missing a [package] section")]
    MissingPackageSection { path: Box<str> },
    #[error("failed to parse manifest {path}: {source}")]
    ManifestParse {
        path: Box<str>,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to parse baseline {path}: {source}")]
    BaselineParse {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to compute attestation timestamp: {0}")]
    Timestamp(#[source] std::time::SystemTimeError),
    #[error("failed to persist temporary report: {0}")]
    PersistReport(#[source] std::io::Error),
    #[error("failed to write GitHub output {path}: {source}")]
    GithubOutput {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Deserialize, Default)]
struct CargoManifest {
    package: Option<CargoPackage>,
    workspace: Option<WorkspaceSection>,
    lib: Option<TargetSection>,
    #[serde(default, rename = "bin")]
    bins: Vec<TargetSection>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default = "default_true")]
    autobins: bool,
}

#[derive(Deserialize, Default)]
struct WorkspaceSection {
    #[serde(default)]
    members: Box<[Box<str>]>,
}

#[derive(Deserialize, Default)]
struct TargetSection {
    path: Option<String>,
}

struct VendorContext {
    _tempdir: TempDir,
    vendor_root: PathBuf,
}

struct VendoredCrate {
    dir: PathBuf,
    name: Box<str>,
    version: Box<str>,
    entry_files: Box<[PathBuf]>,
    build_script: Option<PathBuf>,
}

struct CrateAttestation {
    name: Box<str>,
    version: Box<str>,
    content: AttestationContent,
    source_files: Box<[SourceFileInput]>,
}

struct SourceFileInput {
    path: Arc<str>,
    bytes: usize,
    digest: Box<str>,
}

struct CollectedSourceInput {
    path: Arc<str>,
    source: String,
    bytes: usize,
    digest: Box<str>,
    is_build_script: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FindingLevel {
    HashMismatch,
    NewCapability,
    NewDependency,
    AnalysisIncomplete,
}

impl FindingLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash-mismatch",
            Self::NewCapability => "new-capability",
            Self::NewDependency => "new-dependency",
            Self::AnalysisIncomplete => "analysis-incomplete",
        }
    }

    fn annotation_prefix(self) -> &'static str {
        match self {
            Self::HashMismatch => "::error::",
            Self::NewCapability => "::warning::",
            Self::NewDependency => "::notice::",
            Self::AnalysisIncomplete => "::notice::",
        }
    }
}

#[derive(Serialize)]
struct ReportFinding {
    level: FindingLevel,
    ecosystem: &'static str,
    name: Box<str>,
    version: Box<str>,
    detail: Box<str>,
}

#[derive(Serialize)]
struct Report {
    findings: Vec<ReportFinding>,
}

pub(crate) fn run_init(baseline_path: &str, stderr: &mut impl Write) -> ExitCode {
    run_write_mode("initialized", baseline_path, stderr)
}

pub(crate) fn run_update(baseline_path: &str, stderr: &mut impl Write) -> ExitCode {
    match update_current_baselines(Path::new(baseline_path)) {
        Ok(count) => {
            std::mem::drop(writeln!(
                std::io::stdout().lock(),
                "updated {count} cargo baseline(s)"
            ));
            ExitCode::from(0)
        }
        Err(error) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_verify(
    baseline_path: &str,
    fail_on: FailOn,
    debug_package: Option<&str>,
    stderr: &mut impl Write,
) -> ExitCode {
    match verify_current_workspace(Path::new(baseline_path), debug_package, stderr) {
        Ok(report) => finalize_verify(report, fail_on, stderr),
        Err(error) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            ExitCode::from(2)
        }
    }
}

fn run_write_mode(verb: &str, baseline_path: &str, stderr: &mut impl Write) -> ExitCode {
    match write_current_baselines(Path::new(baseline_path)) {
        Ok(count) => {
            std::mem::drop(writeln!(
                std::io::stdout().lock(),
                "{verb} {count} cargo baseline(s)"
            ));
            ExitCode::from(0)
        }
        Err(error) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            ExitCode::from(2)
        }
    }
}

fn write_current_baselines(baseline_root: &Path) -> Result<usize, SupplyChainError> {
    let workspace_root = current_workspace_root()?;
    let vendor = vendor_cargo_deps(&workspace_root)?;
    let attestations = collect_attestations(&vendor.vendor_root)?;
    for attestation in &attestations {
        write_baseline_file(baseline_root, attestation)?;
    }
    Ok(attestations.len())
}

fn update_current_baselines(baseline_root: &Path) -> Result<usize, SupplyChainError> {
    let workspace_root = current_workspace_root()?;
    let vendor = vendor_cargo_deps(&workspace_root)?;
    let attestations = collect_attestations(&vendor.vendor_root)?;
    for attestation in &attestations {
        write_baseline_file(baseline_root, attestation)?;
    }
    prune_stale_baselines(baseline_root, &attestations)?;
    Ok(attestations.len())
}

fn verify_current_workspace(
    baseline_root: &Path,
    debug_package: Option<&str>,
    stderr: &mut impl Write,
) -> Result<Report, SupplyChainError> {
    let workspace_root = current_workspace_root()?;
    let vendor = vendor_cargo_deps(&workspace_root)?;
    let attestations = collect_attestations(&vendor.vendor_root)?;
    let mut findings = Vec::new();
    let mut emitted_debug = false;

    for attestation in &attestations {
        if debug_package.is_some_and(|name| name == attestation.name.as_ref()) {
            emit_debug_package(
                stderr,
                &attestation.name,
                &attestation.version,
                &attestation.source_files,
                &attestation.content.source_hash,
                attestation.content.analysis_completeness.as_ref(),
            );
            emitted_debug = true;
        }
        findings.extend(compare_attestation(baseline_root, attestation)?);
    }

    if let (Some(name), false) = (debug_package, emitted_debug) {
        std::mem::drop(writeln!(
            stderr,
            "debug-package: {name} not found in vendored Cargo dependencies"
        ));
    }

    Ok(Report { findings })
}

fn current_workspace_root() -> Result<PathBuf, SupplyChainError> {
    let cwd = std::env::current_dir().map_err(SupplyChainError::CurrentDir)?;
    let lockfile = cwd.join("Cargo.lock");
    match lockfile.is_file() {
        true => Ok(cwd),
        false => Err(SupplyChainError::MissingLockfile(
            cwd.display().to_string().into_boxed_str(),
        )),
    }
}

fn default_true() -> bool {
    true
}

fn vendor_cargo_deps(workspace_root: &Path) -> Result<VendorContext, SupplyChainError> {
    let tempdir = tempdir().map_err(SupplyChainError::TempDir)?;
    let vendor_root = tempdir.path().join("cargo");
    let output = Command::new("cargo")
        .arg("vendor")
        .arg(&vendor_root)
        .arg("--locked")
        .arg("--quiet")
        .current_dir(workspace_root)
        .output()
        .map_err(SupplyChainError::CargoVendorSpawn)?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(SupplyChainError::CargoVendor(message.into_boxed_str()));
    }
    Ok(VendorContext {
        _tempdir: tempdir,
        vendor_root,
    })
}

fn collect_attestations(vendor_root: &Path) -> Result<Vec<CrateAttestation>, SupplyChainError> {
    enumerate_vendored_crates(vendor_root)?
        .into_iter()
        .map(|crate_info| build_attestation_for_crate(&crate_info))
        .collect()
}

fn enumerate_vendored_crates(vendor_root: &Path) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    for entry in read_dir_sorted(vendor_root)? {
        if !entry
            .file_type()
            .map_err(|source| SupplyChainError::ReadDir {
                path: vendor_root.display().to_string().into_boxed_str(),
                source,
            })?
            .is_dir()
        {
            continue;
        }
        let dir = entry.path();
        let manifest_path = dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        crates.extend(resolve_vendored_crates(
            &dir,
            &read_manifest(&manifest_path)?,
        )?);
    }
    Ok(crates)
}

fn resolve_vendored_crates(
    root: &Path,
    manifest: &CargoManifest,
) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    if manifest.package.is_some() {
        crates.push(build_vendored_crate(root, manifest)?);
    }
    if let Some(workspace) = &manifest.workspace {
        crates.extend(collect_workspace_member_crates(root, &workspace.members)?);
    }
    Ok(crates)
}

fn collect_workspace_member_crates(
    workspace_root: &Path,
    members: &[Box<str>],
) -> Result<Vec<VendoredCrate>, SupplyChainError> {
    let mut crates = Vec::new();
    for member_dir in resolve_workspace_members(workspace_root, members)? {
        let manifest_path = member_dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let member_manifest = read_manifest(&manifest_path)?;
        if member_manifest.package.is_none() {
            continue;
        }
        crates.push(build_vendored_crate(&member_dir, &member_manifest)?);
    }
    Ok(crates)
}

fn build_vendored_crate(
    crate_dir: &Path,
    manifest: &CargoManifest,
) -> Result<VendoredCrate, SupplyChainError> {
    let package = match &manifest.package {
        Some(package) => package,
        None => return Err(missing_package_section(crate_dir)),
    };
    let entry_files = collect_entry_files(crate_dir, manifest)?;
    let build_script =
        discover_build_script(crate_dir).map_err(|source| SupplyChainError::ReadFile {
            path: crate_dir.display().to_string().into_boxed_str(),
            source: std::io::Error::other(source.to_string()),
        })?;
    Ok(VendoredCrate {
        dir: crate_dir.to_path_buf(),
        name: package.name.clone().into_boxed_str(),
        version: package.version.clone().into_boxed_str(),
        entry_files,
        build_script,
    })
}

fn read_manifest(path: &Path) -> Result<CargoManifest, SupplyChainError> {
    let raw = fs::read_to_string(path).map_err(|source| SupplyChainError::ReadFile {
        path: path.display().to_string().into_boxed_str(),
        source,
    })?;
    toml::from_str(&raw).map_err(|source| SupplyChainError::ManifestParse {
        path: path.display().to_string().into_boxed_str(),
        source,
    })
}

fn collect_entry_files(
    crate_dir: &Path,
    manifest: &CargoManifest,
) -> Result<Box<[PathBuf]>, SupplyChainError> {
    let package = match &manifest.package {
        Some(package) => package,
        None => return Err(missing_package_section(crate_dir)),
    };
    let mut entries = Vec::new();

    let default_lib = crate_dir.join("src/lib.rs");
    match manifest.lib.as_ref().and_then(|lib| lib.path.as_deref()) {
        Some(path) => push_entry_file(crate_dir, Path::new(path), &mut entries),
        None if default_lib.is_file() => entries.push(default_lib),
        None => {}
    }

    for bin in &manifest.bins {
        if let Some(path) = bin.path.as_deref() {
            push_entry_file(crate_dir, Path::new(path), &mut entries);
        }
    }

    let default_bin = crate_dir.join("src/main.rs");
    match (package.autobins, default_bin.is_file()) {
        (true, true) => {
            entries.push(default_bin);
            collect_autobin_entries(crate_dir, &mut entries)?;
        }
        (true, false) => collect_autobin_entries(crate_dir, &mut entries)?,
        (false, _) => {}
    }

    entries.sort();
    entries.dedup();
    Ok(entries.into_boxed_slice())
}

fn push_entry_file(crate_dir: &Path, relative_path: &Path, entries: &mut Vec<PathBuf>) {
    let absolute = crate_dir.join(relative_path);
    if absolute.is_file() {
        entries.push(absolute);
    }
}

fn collect_autobin_entries(
    crate_dir: &Path,
    entries: &mut Vec<PathBuf>,
) -> Result<(), SupplyChainError> {
    let bin_dir = crate_dir.join("src/bin");
    if !bin_dir.is_dir() {
        return Ok(());
    }
    for entry in read_dir_sorted(&bin_dir)? {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| SupplyChainError::ReadDir {
                path: bin_dir.display().to_string().into_boxed_str(),
                source,
            })?;
        let main_rs = path.join("main.rs");
        match (file_type.is_file(), file_type.is_dir()) {
            (true, _) if path.extension() == Some(OsStr::new("rs")) => entries.push(path),
            (_, true) if main_rs.is_file() => entries.push(main_rs),
            _ => {}
        }
    }
    Ok(())
}

fn missing_package_section(crate_dir: &Path) -> SupplyChainError {
    SupplyChainError::MissingPackageSection {
        path: crate_dir
            .join("Cargo.toml")
            .display()
            .to_string()
            .into_boxed_str(),
    }
}

fn resolve_workspace_members(
    workspace_root: &Path,
    members: &[Box<str>],
) -> Result<Vec<PathBuf>, SupplyChainError> {
    let mut dirs: Vec<PathBuf> = members
        .iter()
        .map(|member| expand_member(workspace_root, member))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

fn expand_member(workspace_root: &Path, member: &str) -> Result<Vec<PathBuf>, SupplyChainError> {
    match member.contains('*') {
        true => expand_glob_member(workspace_root, member),
        false => Ok(vec![workspace_root.join(member)]),
    }
}

fn expand_glob_member(
    workspace_root: &Path,
    member: &str,
) -> Result<Vec<PathBuf>, SupplyChainError> {
    let max_depth = member_path_segments(member).len();
    let mut matches = Vec::new();
    collect_matching_dirs(
        workspace_root,
        workspace_root,
        member,
        max_depth,
        &mut matches,
    )?;
    Ok(matches)
}

fn collect_matching_dirs(
    workspace_root: &Path,
    current_dir: &Path,
    member: &str,
    max_depth: usize,
    matches: &mut Vec<PathBuf>,
) -> Result<(), SupplyChainError> {
    for entry in read_dir_sorted(current_dir)? {
        let path = entry.path();
        match (
            path.is_dir(),
            relative_depth(workspace_root, &path) < max_depth,
        ) {
            (true, true) => {
                add_matching_dir(workspace_root, &path, member, matches);
                collect_matching_dirs(workspace_root, &path, member, max_depth, matches)?;
            }
            (true, false) => add_matching_dir(workspace_root, &path, member, matches),
            (false, _) => continue,
        }
    }
    Ok(())
}

fn add_matching_dir(workspace_root: &Path, path: &Path, member: &str, matches: &mut Vec<PathBuf>) {
    if matches_member_pattern(workspace_root, path, member) {
        matches.push(path.to_path_buf());
    }
}

fn relative_depth(workspace_root: &Path, path: &Path) -> usize {
    path.strip_prefix(workspace_root)
        .ok()
        .map(path_component_count)
        .unwrap_or(0)
}

fn matches_member_pattern(workspace_root: &Path, path: &Path, member: &str) -> bool {
    let relative = match path.strip_prefix(workspace_root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let path_segments = path_segments(relative);
    let member_segments = member_path_segments(member);
    match path_segments.len() == member_segments.len() {
        true => path_segments
            .iter()
            .zip(member_segments.iter())
            .all(|(path_segment, member_segment)| segment_matches(path_segment, member_segment)),
        false => false,
    }
}

fn path_component_count(path: &Path) -> usize {
    path.components().count()
}

fn path_segments(path: &Path) -> Vec<Box<str>> {
    path.iter()
        .map(|segment| segment.to_string_lossy().into_owned().into_boxed_str())
        .collect()
}

fn member_path_segments(member: &str) -> Vec<&str> {
    member
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn segment_matches(path_segment: &str, pattern_segment: &str) -> bool {
    let parts = pattern_segment.split('*').collect::<Vec<_>>();
    match parts.len() {
        1 => path_segment == pattern_segment,
        _ => wildcard_segment_matches(path_segment, &parts, pattern_segment.starts_with('*')),
    }
}

fn wildcard_segment_matches(
    path_segment: &str,
    parts: &[&str],
    starts_with_wildcard: bool,
) -> bool {
    let mut remaining = path_segment;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let found = match (index == 0, starts_with_wildcard) {
            (true, false) => remaining.strip_prefix(part),
            _ => remaining
                .find(part)
                .map(|offset| &remaining[offset + part.len()..]),
        };
        match found {
            Some(next) => remaining = next,
            None => return false,
        }
    }
    pattern_segment_ends_with_wildcard(parts, remaining)
}

fn pattern_segment_ends_with_wildcard(parts: &[&str], remaining: &str) -> bool {
    match parts.last() {
        Some(&"") => true,
        Some(_) => remaining.is_empty(),
        None => false,
    }
}

fn build_attestation_for_crate(
    crate_info: &VendoredCrate,
) -> Result<CrateAttestation, SupplyChainError> {
    let files = collect_reachable_sources(
        &crate_info.dir,
        &crate_info.entry_files,
        crate_info.build_script.as_deref(),
    )?;
    let collected_sources = collect_source_inputs(crate_info, &files)?;
    let source_hash = compute_hashed_source(&collected_sources);
    let source_files = source_file_inputs(&collected_sources);
    let (profile, analysis_completeness) = analyze_source_inputs(&collected_sources);

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(SupplyChainError::Timestamp)?;
    let content = AttestationContent {
        spec_version: Box::from(SPEC_VERSION),
        source_hash,
        crate_name: crate_info.name.clone(),
        crate_version: crate_info.version.clone(),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp,
        analysis_completeness: Some(analysis_completeness),
        profile,
    };

    Ok(CrateAttestation {
        name: crate_info.name.clone(),
        version: crate_info.version.clone(),
        content,
        source_files,
    })
}

fn collect_source_inputs(
    crate_info: &VendoredCrate,
    files: &[Arc<str>],
) -> Result<Vec<CollectedSourceInput>, SupplyChainError> {
    let mut collected = Vec::new();
    for relative_path in files {
        let disk_path = crate_info.dir.join(relative_path.trim_start_matches("./"));
        let source =
            fs::read_to_string(&disk_path).map_err(|source| SupplyChainError::ReadFile {
                path: disk_path.display().to_string().into_boxed_str(),
                source,
            })?;
        collected.push(CollectedSourceInput {
            path: Arc::clone(relative_path),
            bytes: source.len(),
            digest: sha256_hex(source.as_bytes()),
            is_build_script: is_build_script_path(&disk_path, crate_info.build_script.as_deref()),
            source,
        });
    }
    Ok(collected)
}

fn compute_hashed_source(collected_sources: &[CollectedSourceInput]) -> Box<str> {
    let sources = collected_sources
        .iter()
        .map(|source| (Arc::clone(&source.path), source.source.as_str()))
        .collect::<BTreeMap<_, _>>();
    compute_source_hash(&sources)
}

fn source_file_inputs(collected_sources: &[CollectedSourceInput]) -> Box<[SourceFileInput]> {
    collected_sources
        .iter()
        .map(|source| SourceFileInput {
            path: Arc::clone(&source.path),
            bytes: source.bytes,
            digest: source.digest.clone(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn analyze_source_inputs(
    collected_sources: &[CollectedSourceInput],
) -> (CapabilityProfile, AnalysisCompleteness) {
    let mut findings = Vec::new();
    let mut analyzed_files = 0;
    let mut skipped_paths = Vec::new();

    for source in collected_sources {
        match analyze_supply_chain_source(&source.path, &source.source, source.is_build_script) {
            Some(capabilities) => {
                analyzed_files += 1;
                findings.extend(capabilities.findings.into_vec());
            }
            None => skipped_paths.push(Box::from(source.path.as_ref())),
        }
    }

    (
        CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
        AnalysisCompleteness {
            analyzed_files,
            skipped_files: skipped_paths.len(),
            skipped_paths: skipped_paths.into_boxed_slice(),
        },
    )
}

fn collect_reachable_sources(
    crate_root: &Path,
    entry_files: &[PathBuf],
    build_script: Option<&Path>,
) -> Result<Box<[Arc<str>]>, SupplyChainError> {
    let mut visited: BTreeSet<Arc<str>> = BTreeSet::new();
    let mut stack: Vec<PathBuf> = entry_files
        .iter()
        .filter(|f| f.is_file())
        .cloned()
        .collect();

    if let Some(bs) = build_script.filter(|p| p.is_file()) {
        stack.push(bs.to_path_buf());
    }

    while let Some(file) = stack.pop() {
        let relative = relative_path_str(crate_root, &file);
        if !visited.insert(relative) {
            continue;
        }
        let source = fs::read_to_string(&file).map_err(|source| SupplyChainError::ReadFile {
            path: file.display().to_string().into_boxed_str(),
            source,
        })?;
        let mod_dir = module_directory(&file);
        for mod_name in extract_mod_declarations(&source) {
            let candidate_file = mod_dir.join(format!("{mod_name}.rs"));
            if candidate_file.is_file() {
                stack.push(candidate_file);
                continue;
            }
            let candidate_mod = mod_dir.join(&*mod_name).join("mod.rs");
            if candidate_mod.is_file() {
                stack.push(candidate_mod);
            }
        }
    }

    Ok(visited.into_iter().collect::<Vec<_>>().into_boxed_slice())
}

fn analyze_supply_chain_source(
    relative_path: &str,
    source: &str,
    is_build_script: bool,
) -> Option<CapabilityProfile> {
    let result = match is_build_script {
        true => analyze_build_script(relative_path, source, &CheckConfig::default(), None),
        false => analyze(relative_path, source, &CheckConfig::default(), None),
    };
    match result {
        Ok(result) => Some(result.capabilities),
        Err(_) => None,
    }
}

fn relative_path_str(crate_root: &Path, path: &Path) -> Arc<str> {
    let relative = path
        .strip_prefix(crate_root)
        .unwrap_or(path)
        .to_string_lossy();
    Arc::from(format!("./{relative}"))
}

fn module_directory(file_path: &Path) -> PathBuf {
    let stem = file_path.file_stem().and_then(OsStr::to_str).unwrap_or("");
    let parent = file_path.parent().unwrap_or(file_path);
    match stem {
        "lib" | "main" | "mod" => parent.to_path_buf(),
        _ => parent.join(stem),
    }
}

fn extract_mod_declarations(source: &str) -> Box<[Box<str>]> {
    source
        .lines()
        .filter_map(|line| {
            let code = line.split("//").next().unwrap_or("").trim();
            find_mod_declaration(code)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn find_mod_declaration(code: &str) -> Option<Box<str>> {
    if !code.ends_with(';') {
        return None;
    }
    let after_mod = match code.starts_with("mod ") {
        true => &code[4..],
        false => {
            let idx = code.find(" mod ")?;
            &code[idx + 5..]
        }
    };
    let name = after_mod.trim_end_matches(';').trim();
    match is_rust_identifier(name) {
        true => Some(Box::from(name)),
        false => None,
    }
}

fn is_rust_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_alphabetic() => chars.all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}

fn read_dir_sorted(path: &Path) -> Result<Vec<fs::DirEntry>, SupplyChainError> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| SupplyChainError::ReadDir {
            path: path.display().to_string().into_boxed_str(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| SupplyChainError::ReadDir {
            path: path.display().to_string().into_boxed_str(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn is_build_script_path(path: &Path, build_script: Option<&Path>) -> bool {
    let Some(build_script) = build_script else {
        return false;
    };
    match (path.canonicalize(), build_script.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => path == build_script,
    }
}

fn write_baseline_file(
    baseline_root: &Path,
    attestation: &CrateAttestation,
) -> Result<(), SupplyChainError> {
    let path = baseline_file_path(baseline_root, &attestation.name, &attestation.version);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SupplyChainError::WriteFile {
            path: parent.display().to_string().into_boxed_str(),
            source,
        })?;
    }
    let json = serde_json::to_vec_pretty(&attestation.content).map_err(|source| {
        SupplyChainError::BaselineParse {
            path: path.display().to_string().into_boxed_str(),
            source,
        }
    })?;
    fs::write(&path, json).map_err(|source| SupplyChainError::WriteFile {
        path: path.display().to_string().into_boxed_str(),
        source,
    })
}

fn prune_stale_baselines(
    baseline_root: &Path,
    attestations: &[CrateAttestation],
) -> Result<(), SupplyChainError> {
    let cargo_root = baseline_root.join(ECOSYSTEM);
    if !cargo_root.is_dir() {
        return Ok(());
    }

    let current_versions: BTreeMap<&str, &str> = attestations
        .iter()
        .map(|attestation| (attestation.name.as_ref(), attestation.version.as_ref()))
        .collect();

    for crate_entry in read_dir_sorted(&cargo_root)? {
        let crate_dir = crate_entry.path();
        if !crate_entry
            .file_type()
            .map_err(|source| SupplyChainError::ReadDir {
                path: cargo_root.display().to_string().into_boxed_str(),
                source,
            })?
            .is_dir()
        {
            continue;
        }

        let crate_name = crate_dir
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let Some(current_version) = current_versions.get(crate_name).copied() else {
            fs::remove_dir_all(&crate_dir).map_err(|source| SupplyChainError::DeletePath {
                path: crate_dir.display().to_string().into_boxed_str(),
                source,
            })?;
            continue;
        };

        for version_entry in read_dir_sorted(&crate_dir)? {
            let version_path = version_entry.path();
            if version_path.extension() != Some(OsStr::new("json")) {
                continue;
            }
            let version = version_path
                .file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            if version == current_version {
                continue;
            }
            fs::remove_file(&version_path).map_err(|source| SupplyChainError::DeletePath {
                path: version_path.display().to_string().into_boxed_str(),
                source,
            })?;
        }

        if read_dir_sorted(&crate_dir)?.is_empty() {
            fs::remove_dir(&crate_dir).map_err(|source| SupplyChainError::DeletePath {
                path: crate_dir.display().to_string().into_boxed_str(),
                source,
            })?;
        }
    }

    Ok(())
}

fn emit_debug_package(
    stderr: &mut impl Write,
    name: &str,
    version: &str,
    source_files: &[SourceFileInput],
    source_hash: &str,
    analysis_completeness: Option<&AnalysisCompleteness>,
) {
    std::mem::drop(writeln!(stderr, "debug-package: {name}@{version}"));
    std::mem::drop(writeln!(stderr, "source_hash: {source_hash}"));
    if let Some(completeness) = analysis_completeness {
        std::mem::drop(writeln!(
            stderr,
            "analysis: analyzed_files={} skipped_files={}",
            completeness.analyzed_files, completeness.skipped_files
        ));
        for skipped_path in &completeness.skipped_paths {
            std::mem::drop(writeln!(stderr, "skipped: {skipped_path}"));
        }
    }
    for source_file in source_files {
        std::mem::drop(writeln!(
            stderr,
            "file: {} bytes={} sha256={}",
            source_file.path, source_file.bytes, source_file.digest
        ));
    }
}

fn sha256_hex(bytes: &[u8]) -> Box<str> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    Box::from(format!("{digest:x}"))
}

fn compare_attestation(
    baseline_root: &Path,
    current: &CrateAttestation,
) -> Result<Vec<ReportFinding>, SupplyChainError> {
    let exact_baseline = baseline_file_path(baseline_root, &current.name, &current.version);
    if !exact_baseline.is_file() {
        return compare_new_or_upgraded_dependency(baseline_root, current);
    }

    let baseline = load_baseline(&exact_baseline)?;
    if baseline.source_hash == current.content.source_hash {
        return Ok(Vec::new());
    }
    Ok(vec![ReportFinding {
        level: FindingLevel::HashMismatch,
        ecosystem: ECOSYSTEM,
        name: current.name.clone(),
        version: current.version.clone(),
        detail: format!(
            "content changed (baseline: {}... current: {}...)",
            prefix16(&baseline.source_hash),
            prefix16(&current.content.source_hash),
        )
        .into_boxed_str(),
    }])
}

fn compare_new_or_upgraded_dependency(
    baseline_root: &Path,
    current: &CrateAttestation,
) -> Result<Vec<ReportFinding>, SupplyChainError> {
    let baseline_dir = baseline_root.join(ECOSYSTEM).join(current.name.as_ref());
    let Some(prior_baseline_path) = best_prior_baseline(&baseline_dir, &current.version)? else {
        let mut findings = vec![ReportFinding {
            level: FindingLevel::NewDependency,
            ecosystem: ECOSYSTEM,
            name: current.name.clone(),
            version: current.version.clone(),
            detail: format!(
                "capabilities: {}",
                capability_list(&current.content.profile)
            )
            .into_boxed_str(),
        }];
        if !attestation_is_complete(&current.content) {
            findings.push(ReportFinding {
                level: FindingLevel::AnalysisIncomplete,
                ecosystem: ECOSYSTEM,
                name: current.name.clone(),
                version: current.version.clone(),
                detail: format!(
                    "new dependency analyzed partially ({})",
                    attestation_completeness_summary(&current.content)
                )
                .into_boxed_str(),
            });
        }
        return Ok(findings);
    };

    let prior = load_baseline(&prior_baseline_path)?;
    if let Some(finding) = incomplete_analysis_finding(
        &prior,
        &current.content,
        &current.name,
        &current.version,
        prior_baseline_path
            .file_stem()
            .and_then(OsStr::to_str)
            .unwrap_or("unknown"),
    ) {
        return Ok(vec![finding]);
    }
    let diff = CapabilityDiff::compute(&prior.profile, &current.content.profile);
    if diff.new_capabilities.is_empty() {
        return Ok(Vec::new());
    }

    let prior_version = prior_baseline_path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown");
    Ok(vec![ReportFinding {
        level: FindingLevel::NewCapability,
        ecosystem: ECOSYSTEM,
        name: current.name.clone(),
        version: current.version.clone(),
        detail: format!(
            "upgraded from {prior_version} — new capabilities: {}",
            capability_names(&diff.new_capabilities)
        )
        .into_boxed_str(),
    }])
}

fn baseline_file_path(baseline_root: &Path, name: &str, version: &str) -> PathBuf {
    baseline_root
        .join(ECOSYSTEM)
        .join(name)
        .join(format!("{version}.json"))
}

fn load_baseline(path: &Path) -> Result<AttestationContent, SupplyChainError> {
    let raw = fs::read_to_string(path).map_err(|source| SupplyChainError::ReadFile {
        path: path.display().to_string().into_boxed_str(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| SupplyChainError::BaselineParse {
        path: path.display().to_string().into_boxed_str(),
        source,
    })
}

fn best_prior_baseline(
    baseline_dir: &Path,
    current_version: &str,
) -> Result<Option<PathBuf>, SupplyChainError> {
    if !baseline_dir.is_dir() {
        return Ok(None);
    }

    let current = Version::parse(current_version).ok();
    let mut candidates = Vec::new();
    for entry in read_dir_sorted(baseline_dir)? {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or_default();
        let parsed = Version::parse(stem).ok();
        candidates.push((parsed, path));
    }

    candidates.sort_by(|(left_version, left_path), (right_version, right_path)| {
        match (left_version, right_version) {
            (Some(left), Some(right)) => left.cmp(right),
            _ => left_path.cmp(right_path),
        }
    });

    for (version, path) in candidates.into_iter().rev() {
        match (&current, version) {
            (Some(current), Some(version)) if version < *current => return Ok(Some(path)),
            (None, _) => return Ok(Some(path)),
            _ => {}
        }
    }
    Ok(None)
}

fn capability_list(profile: &CapabilityProfile) -> String {
    capability_names(&profile.capabilities())
}

fn incomplete_analysis_finding(
    prior: &AttestationContent,
    current: &AttestationContent,
    name: &str,
    version: &str,
    prior_version: &str,
) -> Option<ReportFinding> {
    let prior_complete = attestation_is_complete(prior);
    let current_complete = attestation_is_complete(current);
    if prior_complete && current_complete {
        return None;
    }
    Some(ReportFinding {
        level: FindingLevel::AnalysisIncomplete,
        ecosystem: ECOSYSTEM,
        name: Box::from(name),
        version: Box::from(version),
        detail: format!(
            "upgraded from {prior_version} — capability comparison skipped ({})",
            completeness_summary(prior, current)
        )
        .into_boxed_str(),
    })
}

fn attestation_is_complete(attestation: &AttestationContent) -> bool {
    attestation
        .analysis_completeness
        .as_ref()
        .is_some_and(AnalysisCompleteness::is_complete)
}

fn completeness_summary(prior: &AttestationContent, current: &AttestationContent) -> String {
    format!(
        "prior {} ; current {}",
        attestation_completeness_summary(prior),
        attestation_completeness_summary(current)
    )
}

fn attestation_completeness_summary(attestation: &AttestationContent) -> String {
    match attestation.analysis_completeness.as_ref() {
        Some(completeness) => format!(
            "analyzed={} skipped={}{}",
            completeness.analyzed_files,
            completeness.skipped_files,
            skipped_path_suffix(completeness)
        ),
        None => String::from("analysis completeness unavailable"),
    }
}

fn skipped_path_suffix(completeness: &AnalysisCompleteness) -> String {
    if completeness.skipped_paths.is_empty() {
        return String::new();
    }
    format!(" skipped_paths={}", completeness.skipped_paths.join(", "))
}

fn capability_names(capabilities: &[Capability]) -> String {
    if capabilities.is_empty() {
        return String::from("none");
    }
    capabilities
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn prefix16(hash: &str) -> &str {
    let end = hash.len().min(16);
    &hash[..end]
}

fn finalize_verify(report: Report, fail_on: FailOn, stderr: &mut impl Write) -> ExitCode {
    if let Err(error) = emit_github_output(&report) {
        crate::report_error(stderr, format_args!("error: {error}"));
        return ExitCode::from(2);
    }

    if report.findings.is_empty() {
        std::mem::drop(writeln!(
            std::io::stdout().lock(),
            "All dependencies match baselines."
        ));
        return ExitCode::from(0);
    }

    let mut stdout = std::io::stdout().lock();
    std::mem::drop(writeln!(
        stdout,
        "=== Supply Chain Check: {} finding(s) ===",
        report.findings.len()
    ));
    for finding in &report.findings {
        std::mem::drop(writeln!(
            stdout,
            "{}[{}] {}@{} — {}",
            finding.level.annotation_prefix(),
            finding.ecosystem,
            finding.name,
            finding.version,
            finding.detail
        ));
    }

    match should_fail(&report.findings, fail_on) {
        true => ExitCode::from(1),
        false => ExitCode::from(0),
    }
}

fn emit_github_output(report: &Report) -> Result<(), SupplyChainError> {
    let Some(github_output) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };

    let report_path = persist_report(report)?;
    let mut output = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&github_output)
        .map_err(|source| SupplyChainError::GithubOutput {
            path: PathBuf::from(&github_output)
                .display()
                .to_string()
                .into_boxed_str(),
            source,
        })?;
    writeln!(output, "status={}", overall_status(&report.findings)).map_err(|source| {
        SupplyChainError::GithubOutput {
            path: PathBuf::from(&github_output)
                .display()
                .to_string()
                .into_boxed_str(),
            source,
        }
    })?;
    writeln!(output, "report={}", report_path.display()).map_err(|source| {
        SupplyChainError::GithubOutput {
            path: PathBuf::from(&github_output)
                .display()
                .to_string()
                .into_boxed_str(),
            source,
        }
    })?;
    Ok(())
}

fn persist_report(report: &Report) -> Result<PathBuf, SupplyChainError> {
    let file = NamedTempFile::new().map_err(SupplyChainError::PersistReport)?;
    serde_json::to_writer_pretty(file.as_file(), report).map_err(|source| {
        SupplyChainError::BaselineParse {
            path: file.path().display().to_string().into_boxed_str(),
            source,
        }
    })?;
    let (_file, path) = file
        .keep()
        .map_err(|error| SupplyChainError::PersistReport(error.error))?;
    Ok(path)
}

fn overall_status(findings: &[ReportFinding]) -> &'static str {
    if findings.is_empty() {
        return "clean";
    }
    findings
        .iter()
        .map(|finding| finding.level)
        .max_by_key(|level| status_rank(level.as_str()))
        .map(|level| level.as_str())
        .unwrap_or("clean")
}

fn should_fail(findings: &[ReportFinding], fail_on: FailOn) -> bool {
    let threshold = severity_rank(fail_on.as_str());
    findings
        .iter()
        .any(|finding| severity_rank(finding.level.as_str()) >= threshold && threshold > 0)
}

fn severity_rank(level: &str) -> usize {
    match level {
        "hash-mismatch" => 3,
        "new-capability" => 2,
        "new-dependency" => 1,
        "analysis-incomplete" => 0,
        _ => 0,
    }
}

fn status_rank(level: &str) -> usize {
    match level {
        "hash-mismatch" => 4,
        "new-capability" => 3,
        "new-dependency" => 2,
        "analysis-incomplete" => 1,
        _ => 0,
    }
}
