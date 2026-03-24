use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pedant_core::check_config::load_config_file;
use pedant_core::gate::GateVerdict;
use pedant_core::{
    AnalysisResult, Config, GateConfig, SemanticContext, analyze, analyze_build_script,
    evaluate_gate_rules,
};
use pedant_types::CapabilityProfile;
use thiserror::Error;
use walkdir::WalkDir;

/// Failure modes during workspace indexing.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Disk I/O failure.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Absolute path of the unreadable file.
        path: Box<str>,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// TOML syntax or schema error.
    #[error("failed to parse {path}: {source}")]
    TomlParse {
        /// Path of the malformed TOML file.
        path: Box<str>,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// `syn` could not parse a Rust source file.
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

/// Cached analysis results for every crate in a Cargo workspace.
pub struct WorkspaceIndex {
    crates: BTreeMap<Box<str>, CrateIndex>,
    gate_config: GateConfig,
    semantic_available: bool,
}

pub use pedant_core::lint::discover_workspace_root;

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

/// Load `GateConfig` from the workspace `.pedant.toml`, falling back to defaults.
///
/// Returns the default config when the file does not exist.
/// Returns an error when the file exists but contains invalid TOML.
fn load_gate_config(workspace_root: &Path) -> Result<GateConfig, IndexError> {
    let config_path = workspace_root.join(".pedant.toml");
    match load_config_file(&config_path) {
        Ok(cfg) => Ok(cfg.gate),
        Err(pedant_core::check_config::ConfigError::Read(ref io_err))
            if io_err.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(GateConfig::default())
        }
        Err(pedant_core::check_config::ConfigError::Read(io_err)) => Err(IndexError::Io {
            path: config_path.to_string_lossy().into(),
            source: io_err,
        }),
        Err(pedant_core::check_config::ConfigError::Parse(toml_err)) => {
            Err(IndexError::TomlParse {
                path: config_path.to_string_lossy().into(),
                source: toml_err,
            })
        }
    }
}

impl WorkspaceIndex {
    /// Discover workspace members, analyze all source files, and cache the results.
    ///
    /// Handles both multi-crate workspaces and single-crate projects.
    pub fn build(
        workspace_root: &Path,
        config: &Config,
        semantic: Option<SemanticContext>,
    ) -> Result<Self, IndexError> {
        let cargo_toml_path = workspace_root.join("Cargo.toml");
        let cargo_toml_str = read_file(&cargo_toml_path)?;

        let gate_config = load_gate_config(workspace_root)?;
        let mut crates = BTreeMap::new();

        let member_dirs =
            resolve_workspace_members(workspace_root, &cargo_toml_str, &cargo_toml_path)?;

        for member_dir in member_dirs {
            let member_cargo_toml = member_dir.join("Cargo.toml");
            let member_toml_str = read_file(&member_cargo_toml)?;
            let package: CargoPackage = parse_toml(&member_toml_str, &member_cargo_toml)?;

            let crate_name = package.package.name;
            let crate_index =
                build_crate_index(&member_dir, config, &gate_config, semantic.as_ref())?;
            crates.insert(crate_name, crate_index);
        }

        Ok(Self {
            crates,
            gate_config,
            semantic_available: semantic.is_some(),
        })
    }

    /// Yield every indexed crate name in sorted order.
    pub fn crate_names(&self) -> impl Iterator<Item = &str> {
        self.crates.keys().map(AsRef::as_ref)
    }

    /// Aggregated capability profile across all files in a crate.
    pub fn crate_profile(&self, name: &str) -> Option<&CapabilityProfile> {
        self.crates.get(name).map(|c| &c.profile)
    }

    /// Gate verdicts computed from the crate's aggregated profile.
    pub fn crate_verdicts(&self, name: &str) -> Option<&[GateVerdict]> {
        self.crates.get(name).map(|c| c.gate_verdicts.as_ref())
    }

    /// Look up a file's cached analysis result across all crates.
    pub fn file_result(&self, path: &str) -> Option<&AnalysisResult> {
        self.crates.values().find_map(|c| c.files.get(path))
    }

    /// Iterate over every file result in a crate, keyed by path.
    pub fn crate_files(&self, name: &str) -> Option<impl Iterator<Item = (&str, &AnalysisResult)>> {
        self.crates
            .get(name)
            .map(|c| c.files.iter().map(|(k, v)| (k.as_ref(), v)))
    }

    /// Yield every crate with its aggregated capability profile.
    pub fn all_profiles(&self) -> impl Iterator<Item = (&str, &CapabilityProfile)> {
        self.crates.iter().map(|(k, v)| (k.as_ref(), &v.profile))
    }

    /// Aggregate data flow facts across all files in a crate.
    pub fn crate_data_flows(
        &self,
        name: &str,
    ) -> Option<impl Iterator<Item = &pedant_core::ir::DataFlowFact>> {
        self.crates
            .get(name)
            .map(|c| c.files.values().flat_map(|r| r.data_flows.iter()))
    }

    /// Analysis tier based on whether semantic context was loaded and data flows detected.
    pub fn crate_tier(&self, name: &str) -> &'static str {
        let has_flows = self
            .crates
            .get(name)
            .is_some_and(|c| c.files.values().any(|r| !r.data_flows.is_empty()));
        match (has_flows, self.semantic_available) {
            (true, _) => "data_flow",
            (false, true) => "semantic",
            (false, false) => "syntactic",
        }
    }

    /// Yield every crate with its gate verdicts.
    pub fn all_verdicts(&self) -> impl Iterator<Item = (&str, &[GateVerdict])> {
        self.crates
            .iter()
            .map(|(k, v)| (k.as_ref(), v.gate_verdicts.as_ref()))
    }

    /// Incrementally re-analyze a single file and update its owning crate's cache.
    ///
    /// The owning crate is determined by matching the file path against crate roots.
    /// Handles both regular source files and `build.rs`.
    pub fn reindex_file(&mut self, path: &Path, config: &Config) -> Result<(), IndexError> {
        let path_lossy = path.to_string_lossy();
        // Incremental reindex uses syntactic analysis only — SemanticContext
        // is consumed at build time and not retained (it's not Sync).
        let is_build_script = path.file_name().is_some_and(|n| n == "build.rs");
        let result = match is_build_script {
            true => analyze_build_script_at(path, &path_lossy, config, None)?,
            false => analyze_source_at(path, &path_lossy, config, None)?,
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

    /// Drop a file's cached result and recompute the owning crate's profile.
    pub fn remove_file(&mut self, path: &Path) {
        let crate_index = match find_owning_crate(&mut self.crates, path) {
            Some(ci) => ci,
            None => return,
        };

        let path_lossy = path.to_string_lossy();
        crate_index.files.remove(path_lossy.as_ref());
        recompute_aggregates(crate_index, &self.gate_config);
    }

    /// Yield all crate root directories for file watcher registration.
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

/// Parse `Cargo.toml` to determine workspace members or single-crate layout.
///
/// Returns an error if the TOML is malformed. Returns a single-element vec
/// when the manifest is valid TOML but has no `[workspace]` key.
fn resolve_workspace_members(
    workspace_root: &Path,
    cargo_toml_str: &str,
    cargo_toml_path: &Path,
) -> Result<Vec<PathBuf>, IndexError> {
    let workspace_parse = toml::from_str::<CargoWorkspace>(cargo_toml_str);
    let valid_toml = toml::from_str::<toml::Value>(cargo_toml_str);
    match (workspace_parse, valid_toml) {
        (Ok(workspace), _) => Ok(resolve_members(
            workspace_root,
            &workspace.workspace.members,
        )),
        (Err(_), Ok(_)) => Ok(vec![workspace_root.to_path_buf()]),
        (Err(toml_err), Err(_)) => Err(IndexError::TomlParse {
            path: cargo_toml_path.to_string_lossy().into(),
            source: toml_err,
        }),
    }
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
fn recompute_aggregates(crate_index: &mut CrateIndex, gate_config: &GateConfig) {
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
    let data_flows: Vec<_> = files
        .values()
        .flat_map(|r| r.data_flows.iter().cloned())
        .collect();
    evaluate_gate_rules(&profile.findings, &data_flows, gate_config)
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
fn analyze_source_file(
    path: &Path,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let path_lossy = path.to_string_lossy();
    analyze_source_at(path, &path_lossy, config, semantic)
}

/// Analyze a source file with a pre-computed path string.
fn analyze_source_at(
    path: &Path,
    path_str: &str,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    analyze(path_str, &source, config, semantic).map_err(|e| IndexError::RustParse {
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
fn analyze_build_script_at(
    path: &Path,
    path_str: &str,
    config: &Config,
    semantic: Option<&SemanticContext>,
) -> Result<AnalysisResult, IndexError> {
    let source = read_file(path)?;
    analyze_build_script(path_str, &source, config, semantic).map_err(|e| IndexError::RustParse {
        path: path_str.into(),
        source: e,
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
