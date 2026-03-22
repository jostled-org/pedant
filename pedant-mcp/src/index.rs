use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::gate::GateVerdict;
use pedant_core::{
    AnalysisResult, Config, GateConfig, SemanticContext, analyze, analyze_build_script,
    evaluate_gate_rules,
};
use pedant_types::CapabilityProfile;
use thiserror::Error;
use walkdir::WalkDir;

/// Errors that can occur during workspace indexing.
#[derive(Debug, Error)]
pub enum IndexError {
    /// File I/O failure.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path that could not be read.
        path: Box<str>,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// TOML deserialization failure.
    #[error("failed to parse {path}: {source}")]
    TomlParse {
        /// Path of the malformed TOML file.
        path: Box<str>,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// Rust source parsing failure.
    #[error("failed to parse Rust source {path}: {source}")]
    RustParse {
        /// Path of the unparseable source file.
        path: Box<str>,
        /// Underlying parse error.
        source: pedant_core::ParseError,
    },
}

/// Cached analysis results for a single crate.
struct CrateIndex {
    root: PathBuf,
    files: BTreeMap<Box<str>, AnalysisResult>,
    profile: CapabilityProfile,
    gate_verdicts: Box<[GateVerdict]>,
}

/// In-memory index of all crates in a Cargo workspace.
pub struct WorkspaceIndex {
    crates: BTreeMap<Box<str>, CrateIndex>,
    gate_config: GateConfig,
}

/// Walk up from `start` to find a `Cargo.toml` containing `[workspace]`.
pub fn discover_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = match start.is_dir() {
        true => start.to_path_buf(),
        false => start.parent()?.to_path_buf(),
    };
    loop {
        let cargo_toml = current.join("Cargo.toml");
        let is_workspace = fs::read_to_string(&cargo_toml)
            .ok()
            .is_some_and(|contents| contents.contains("[workspace]"));
        match is_workspace {
            true => return Some(current),
            false => current = current.parent()?.to_path_buf(),
        }
    }
}

/// Minimal representation of a workspace Cargo.toml for member enumeration.
#[derive(serde::Deserialize)]
struct CargoWorkspace {
    workspace: WorkspaceSection,
}

#[derive(serde::Deserialize)]
struct WorkspaceSection {
    #[serde(default)]
    members: Box<[Box<str>]>,
}

/// Minimal representation of a crate Cargo.toml for name extraction.
#[derive(serde::Deserialize)]
struct CargoPackage {
    package: PackageSection,
}

#[derive(serde::Deserialize)]
struct PackageSection {
    name: Box<str>,
}

impl WorkspaceIndex {
    /// Build the index by discovering all workspace members and analyzing their sources.
    pub fn build(workspace_root: &Path, config: &Config) -> Result<Self, IndexError> {
        let cargo_toml_path = workspace_root.join("Cargo.toml");
        let cargo_toml_str = read_file(&cargo_toml_path)?;
        let workspace: CargoWorkspace = parse_toml(&cargo_toml_str, &cargo_toml_path)?;

        let gate_config = GateConfig::default();
        let mut crates = BTreeMap::new();
        let member_dirs = resolve_members(workspace_root, &workspace.workspace.members);

        for member_dir in member_dirs {
            let member_cargo_toml = member_dir.join("Cargo.toml");
            let member_toml_str = read_file(&member_cargo_toml)?;
            let package: CargoPackage = parse_toml(&member_toml_str, &member_cargo_toml)?;

            let crate_name = package.package.name;
            let crate_index = build_crate_index(&member_dir, config, &gate_config)?;
            crates.insert(crate_name, crate_index);
        }

        Ok(Self {
            crates,
            gate_config,
        })
    }

    /// Iterate over all indexed crate names.
    pub fn crate_names(&self) -> impl Iterator<Item = &str> {
        self.crates.keys().map(AsRef::as_ref)
    }

    /// Get the aggregated capability profile for a crate.
    pub fn crate_profile(&self, name: &str) -> Option<&CapabilityProfile> {
        self.crates.get(name).map(|c| &c.profile)
    }

    /// Get gate verdicts for a crate.
    pub fn crate_verdicts(&self, name: &str) -> Option<&[GateVerdict]> {
        self.crates.get(name).map(|c| c.gate_verdicts.as_ref())
    }

    /// Get the analysis result for a specific file path.
    pub fn file_result(&self, path: &str) -> Option<&AnalysisResult> {
        self.crates.values().find_map(|c| c.files.get(path))
    }

    /// Get all file analysis results for a crate.
    pub fn crate_files(&self, name: &str) -> Option<impl Iterator<Item = (&str, &AnalysisResult)>> {
        self.crates
            .get(name)
            .map(|c| c.files.iter().map(|(k, v)| (k.as_ref(), v)))
    }

    /// Iterate over all crates with their capability profiles.
    pub fn all_profiles(&self) -> impl Iterator<Item = (&str, &CapabilityProfile)> {
        self.crates.iter().map(|(k, v)| (k.as_ref(), &v.profile))
    }

    /// Iterate over all crates with their gate verdicts.
    pub fn all_verdicts(&self) -> impl Iterator<Item = (&str, &[GateVerdict])> {
        self.crates
            .iter()
            .map(|(k, v)| (k.as_ref(), v.gate_verdicts.as_ref()))
    }

    /// Re-analyze a single file and update the crate's cached results.
    ///
    /// Works for new files, modified files, and build.rs. The owning crate
    /// is determined by matching the file path against crate root directories.
    pub fn reindex_file(&mut self, path: &Path, config: &Config) -> Result<(), IndexError> {
        let path_lossy = path.to_string_lossy();
        let is_build_script = path.file_name().is_some_and(|n| n == "build.rs");
        let result = match is_build_script {
            true => analyze_build_script_at(path, &path_lossy, config)?,
            false => analyze_source_at(path, &path_lossy, config)?,
        };

        let crate_index = match find_owning_crate(&mut self.crates, path) {
            Some(ci) => ci,
            None => return Ok(()),
        };

        crate_index
            .files
            .insert(Box::from(path_lossy.as_ref()), result);
        recompute_aggregates(crate_index, &self.gate_config);
        Ok(())
    }

    /// Remove a file from the index and recompute the owning crate's aggregates.
    pub fn remove_file(&mut self, path: &Path) {
        let crate_index = match find_owning_crate(&mut self.crates, path) {
            Some(ci) => ci,
            None => return,
        };

        let path_lossy = path.to_string_lossy();
        crate_index.files.remove(path_lossy.as_ref());
        recompute_aggregates(crate_index, &self.gate_config);
    }

    /// Collect all crate root directories (for file watcher setup).
    pub fn crate_roots(&self) -> impl Iterator<Item = &Path> {
        self.crates.values().map(|c| c.root.as_path())
    }
}

/// Find the crate whose root directory is a prefix of the given path.
fn find_owning_crate<'a>(
    crates: &'a mut BTreeMap<Box<str>, CrateIndex>,
    path: &Path,
) -> Option<&'a mut CrateIndex> {
    crates.values_mut().find(|c| path.starts_with(&c.root))
}

/// Resolve workspace member patterns to actual directories.
///
/// Supports literal paths and simple glob patterns (e.g. `crates/*`).
fn resolve_members(workspace_root: &Path, members: &[Box<str>]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = members
        .iter()
        .flat_map(|member| expand_member(workspace_root, member))
        .filter(|p| p.join("Cargo.toml").exists())
        .collect();
    dirs.sort();
    dirs
}

/// Expand a single workspace member pattern into candidate directories.
fn expand_member(workspace_root: &Path, member: &str) -> Vec<PathBuf> {
    match member.contains('*') {
        true => {
            let prefix = workspace_root.join(member.split('*').next().unwrap_or(""));
            fs::read_dir(&prefix)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        }
        false => vec![workspace_root.join(member)],
    }
}

/// Build the index for a single crate: analyze all .rs source files and build.rs.
fn build_crate_index(
    crate_root: &Path,
    config: &Config,
    gate_config: &GateConfig,
) -> Result<CrateIndex, IndexError> {
    let mut files = BTreeMap::new();

    for source_path in discover_rust_sources(crate_root) {
        let result = analyze_source_file(&source_path, config)?;
        let path_str: Box<str> = source_path.to_string_lossy().into();
        files.insert(path_str, result);
    }

    let build_rs = crate_root.join("build.rs");
    if build_rs.is_file() {
        let result = analyze_build_script_file(&build_rs, config)?;
        let path_str: Box<str> = build_rs.to_string_lossy().into();
        files.insert(path_str, result);
    }

    let findings_count: usize = files.values().map(|r| r.capabilities.findings.len()).sum();
    let mut all_findings = Vec::with_capacity(findings_count);
    all_findings.extend(
        files
            .values()
            .flat_map(|r| r.capabilities.findings.iter().cloned()),
    );

    let profile = CapabilityProfile {
        findings: all_findings.into(),
    };

    let gate_verdicts = compute_gate_verdicts(&profile, gate_config);

    Ok(CrateIndex {
        root: crate_root.to_path_buf(),
        files,
        profile,
        gate_verdicts,
    })
}

/// Recompute a crate's aggregated profile and gate verdicts from its cached file results.
fn recompute_aggregates(crate_index: &mut CrateIndex, gate_config: &GateConfig) {
    let all_findings: Vec<_> = crate_index
        .files
        .values()
        .flat_map(|r| r.capabilities.findings.iter().cloned())
        .collect();

    crate_index.profile = CapabilityProfile {
        findings: all_findings.into(),
    };

    crate_index.gate_verdicts = compute_gate_verdicts(&crate_index.profile, gate_config);
}

fn compute_gate_verdicts(
    profile: &CapabilityProfile,
    gate_config: &GateConfig,
) -> Box<[GateVerdict]> {
    evaluate_gate_rules(&profile.findings, gate_config)
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

/// Analyze a single Rust source file.
fn analyze_source_file(path: &Path, config: &Config) -> Result<AnalysisResult, IndexError> {
    let path_lossy = path.to_string_lossy();
    analyze_source_at(path, &path_lossy, config)
}

/// Analyze a source file with a pre-computed path string.
fn analyze_source_at(
    path: &Path,
    path_str: &str,
    config: &Config,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    analyze(path_str, &source, config, Option::<&SemanticContext>::None).map_err(|e| {
        IndexError::RustParse {
            path: path_str.into(),
            source: e,
        }
    })
}

/// Analyze a build.rs file, tagging all findings as build-script.
fn analyze_build_script_file(path: &Path, config: &Config) -> Result<AnalysisResult, IndexError> {
    let path_lossy = path.to_string_lossy();
    analyze_build_script_at(path, &path_lossy, config)
}

/// Analyze a build script with a pre-computed path string.
fn analyze_build_script_at(
    path: &Path,
    path_str: &str,
    config: &Config,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    analyze_build_script(path_str, &source, config, Option::<&SemanticContext>::None).map_err(|e| {
        IndexError::RustParse {
            path: path_str.into(),
            source: e,
        }
    })
}

fn read_file(path: &Path) -> Result<String, IndexError> {
    fs::read_to_string(path).map_err(|e| IndexError::Io {
        path: path.to_string_lossy().into(),
        source: e,
    })
}

fn parse_toml<T: serde::de::DeserializeOwned>(content: &str, path: &Path) -> Result<T, IndexError> {
    toml::from_str(content).map_err(|e| IndexError::TomlParse {
        path: path.to_string_lossy().into(),
        source: e,
    })
}
