mod config;
mod crate_index;
mod workspace;

use std::collections::BTreeMap;
use std::path::Path;

use pedant_core::gate::GateVerdict;
use pedant_core::{AnalysisResult, Config, GateConfig, SemanticContext};
use pedant_types::CapabilityProfile;
use thiserror::Error;

use crate_index::{
    CrateIndex, analyze_build_script_at, analyze_non_rust_or_manifest, analyze_source_at,
    recompute_aggregates,
};

pub use workspace::discover_workspace_root;

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
    /// Cargo.toml exists but has no `package.name` field.
    #[error("{path} missing required package.name field")]
    MissingPackageName {
        /// Path of the Cargo.toml without a package name.
        path: Box<str>,
    },
}

/// Cached analysis results for every crate in a Cargo workspace.
pub struct WorkspaceIndex {
    crates: BTreeMap<Box<str>, CrateIndex>,
    gate_config: GateConfig,
    semantic_root: Option<Box<Path>>,
    semantic_available: bool,
    degraded_files: BTreeMap<Box<str>, Box<str>>,
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
        let cargo_toml_str = crate_index::read_file(&cargo_toml_path)?;

        let gate_config = config::load_gate_config(workspace_root)?;
        let mut crates = BTreeMap::new();

        let members = workspace::resolve_workspace_members_with_names(
            workspace_root,
            &cargo_toml_str,
            &cargo_toml_path,
        )?;

        for (member_dir, crate_name) in members {
            let crate_idx = crate_index::build_crate_index(
                &member_dir,
                config,
                &gate_config,
                semantic.as_ref(),
            )?;
            crates.insert(crate_name, crate_idx);
        }

        let semantic_available = semantic.is_some();
        Ok(Self {
            crates,
            gate_config,
            semantic_root: semantic_available
                .then(|| workspace_root.to_path_buf().into_boxed_path()),
            semantic_available,
            degraded_files: BTreeMap::new(),
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
    /// Handles Rust source files, `build.rs`, non-Rust source files, and manifests.
    pub fn reindex_file(&mut self, path: &Path, config: &Config) -> Result<(), IndexError> {
        let path_lossy = path.to_string_lossy();
        let path_key: Box<str> = path_lossy.as_ref().into();
        let is_rust = path.extension().is_some_and(|ext| ext == "rs");
        let is_build_script = path.file_name().is_some_and(|n| n == "build.rs");
        let result = match (is_rust, is_build_script) {
            (true, true) => {
                let semantic = load_semantic_for_reindex(self.semantic_root.as_deref());
                analyze_build_script_at(path, &path_lossy, config, semantic.as_ref())?
            }
            (true, false) => {
                let semantic = load_semantic_for_reindex(self.semantic_root.as_deref());
                analyze_source_at(path, &path_lossy, config, semantic.as_ref())?
            }
            (false, _) => analyze_non_rust_or_manifest(path)?,
        };

        {
            let crate_index = match find_owning_crate(&mut self.crates, path) {
                Some(ci) => ci,
                None => return Ok(()),
            };

            crate_index.files.insert(path_key.clone(), result);
            recompute_aggregates(crate_index, &self.gate_config);
        }
        self.degraded_files.remove(path_key.as_ref());
        Ok(())
    }

    /// Drop a file's cached result and recompute the owning crate's profile.
    pub fn remove_file(&mut self, path: &Path) {
        let path_lossy = path.to_string_lossy();
        {
            let crate_index = match find_owning_crate(&mut self.crates, path) {
                Some(ci) => ci,
                None => return,
            };
            crate_index.files.remove(path_lossy.as_ref());
            recompute_aggregates(crate_index, &self.gate_config);
        }
        self.degraded_files.remove(path_lossy.as_ref());
    }

    /// Record that a file could not be reindexed and the cached result is stale.
    pub fn mark_file_degraded(&mut self, path: &Path, error: &IndexError) {
        self.degraded_files.insert(
            path.to_string_lossy().into(),
            error.to_string().into_boxed_str(),
        );
    }

    /// Degraded files for a crate whose cached results may be stale.
    pub fn crate_degraded_files(&self, name: &str) -> Option<impl Iterator<Item = (&str, &str)>> {
        let crate_root = self.crates.get(name)?.root.as_path();
        Some(
            self.degraded_files
                .iter()
                .filter(move |(path, _)| Path::new(path.as_ref()).starts_with(crate_root))
                .map(|(path, error)| (path.as_ref(), error.as_ref())),
        )
    }

    /// Yield all crate root directories for file watcher registration.
    pub fn crate_roots(&self) -> impl Iterator<Item = &Path> {
        self.crates.values().map(|c| c.root.as_path())
    }
}

#[cfg(feature = "semantic")]
fn load_semantic_for_reindex(workspace_root: Option<&Path>) -> Option<SemanticContext> {
    workspace_root.and_then(SemanticContext::load)
}

#[cfg(not(feature = "semantic"))]
fn load_semantic_for_reindex(_workspace_root: Option<&Path>) -> Option<SemanticContext> {
    None
}

/// Find the crate whose root directory is a prefix of the given path.
fn find_owning_crate<'a>(
    crates: &'a mut BTreeMap<Box<str>, CrateIndex>,
    path: &Path,
) -> Option<&'a mut CrateIndex> {
    crates
        .values_mut()
        .filter(|crate_index| path.starts_with(&crate_index.root))
        .max_by_key(|crate_index| crate_index.root.components().count())
}
