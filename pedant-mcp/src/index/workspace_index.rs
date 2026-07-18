use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use pedant_core::gate::GateVerdict;
use pedant_core::project::{CargoMetadata, ProjectContext, check_project};
use pedant_core::{AnalysisResult, Config, SemanticContext, Violation};
use pedant_types::{AnalysisTier, CapabilityProfile};

use super::config::{self, WorkspaceConfig};
use super::crate_index::{
    self, AnalyzeAt, CrateIndex, analyze_build_script_at, analyze_non_rust_or_manifest,
    analyze_source_at, recompute_aggregates,
};
use super::error::IndexError;
use super::workspace;

/// Cached analysis results for every crate in a Cargo workspace.
pub struct WorkspaceIndex {
    crates: BTreeMap<Box<str>, CrateIndex>,
    config: WorkspaceConfig,
    workspace_root: Box<Path>,
    project_violations: Box<[Violation]>,
    semantic_root: Option<Box<Path>>,
    semantic_available: bool,
    degraded_files: BTreeMap<Box<str>, Box<str>>,
}

impl WorkspaceIndex {
    /// Discover workspace members, analyze all source files, and cache the results.
    ///
    /// The workspace's `.pedant.toml` is loaded once here, so per-file analysis
    /// honors the project's configured checks and path overrides, and the
    /// project-level structural checks run against the full source tree.
    ///
    /// Handles both multi-crate workspaces and single-crate projects.
    pub fn build(
        workspace_root: &Path,
        semantic: Option<SemanticContext>,
    ) -> Result<Self, IndexError> {
        let cargo_toml_path = workspace_root.join("Cargo.toml");
        let cargo_toml_str = crate_index::read_file(&cargo_toml_path)?;

        let config = config::load_workspace_config(workspace_root);
        let mut crates = BTreeMap::new();

        let members = workspace::resolve_workspace_members_with_names(
            workspace_root,
            &cargo_toml_str,
            &cargo_toml_path,
        )?;

        for (member_dir, crate_name) in members {
            let crate_idx =
                crate_index::build_crate_index(&member_dir, &config, semantic.as_ref())?;
            crates.insert(crate_name, crate_idx);
        }

        let project_violations = compute_project_violations(&crates, workspace_root, config.base());

        let semantic_available = semantic.is_some();
        Ok(Self {
            crates,
            config,
            workspace_root: workspace_root.to_path_buf().into_boxed_path(),
            project_violations,
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

    /// Workspace-scoped violations from the project-level structural checks.
    ///
    /// These examine the whole source tree (module layout, feature boundaries)
    /// rather than a single file, so they attach to the workspace, not a crate.
    pub fn project_violations(&self) -> &[Violation] {
        &self.project_violations
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
    pub fn crate_tier(&self, name: &str) -> AnalysisTier {
        let has_flows = self
            .crates
            .get(name)
            .is_some_and(|c| c.files.values().any(|r| !r.data_flows.is_empty()));
        workspace::crate_tier(has_flows, self.semantic_available)
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
    /// Path overrides are re-resolved so the file's effective config stays correct,
    /// and the project-level checks are recomputed since the file set may have changed.
    pub fn reindex_file(&mut self, path: &Path) -> Result<(), IndexError> {
        let path_lossy = path.to_string_lossy();
        let path_key: Box<str> = path_lossy.as_ref().into();
        let is_rust = path.extension().is_some_and(|ext| ext == "rs");
        let is_build_script = path.file_name().is_some_and(|n| n == "build.rs");
        let semantic_root = self.semantic_root.as_deref();
        let result = match (is_rust, is_build_script) {
            (true, true) => reindex_rust(
                &self.config,
                semantic_root,
                path,
                &path_lossy,
                analyze_build_script_at,
            )?,
            (true, false) => reindex_rust(
                &self.config,
                semantic_root,
                path,
                &path_lossy,
                analyze_source_at,
            )?,
            (false, _) => Some(analyze_non_rust_or_manifest(path)?),
        };

        let Some(result) = result else {
            // A path override disabled analysis for this file; drop any stale entry.
            self.remove_file(path);
            return Ok(());
        };

        {
            let crate_index = match find_owning_crate(&mut self.crates, path) {
                Some(ci) => ci,
                None => return Ok(()),
            };

            crate_index.files.insert(path_key.clone(), result);
            recompute_aggregates(crate_index, self.config.gate());
        }
        self.degraded_files.remove(path_key.as_ref());
        self.project_violations =
            compute_project_violations(&self.crates, &self.workspace_root, self.config.base());
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
            recompute_aggregates(crate_index, self.config.gate());
        }
        self.degraded_files.remove(path_lossy.as_ref());
        self.project_violations =
            compute_project_violations(&self.crates, &self.workspace_root, self.config.base());
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

/// Re-analyze a Rust file through the file's resolved config.
///
/// Returns `None` when a path override disables analysis for this file.
fn reindex_rust(
    config: &WorkspaceConfig,
    semantic_root: Option<&Path>,
    path: &Path,
    path_str: &str,
    analyze: AnalyzeAt,
) -> Result<Option<AnalysisResult>, IndexError> {
    let Some(cfg) = config.resolve_for_path(path_str) else {
        return Ok(None);
    };
    let semantic = load_semantic_for_reindex(semantic_root);
    let result = analyze(path, path_str, &cfg, semantic.as_ref())?;
    Ok(Some(result))
}

/// Run the whole-workspace structural checks over the indexed Rust files.
///
/// Mirrors the CLI's `run_project_checks`: build a [`ProjectContext`] and call
/// [`check_project`] with the base config. `cargo metadata` is loaded only when
/// the feature-boundary check needs it.
fn compute_project_violations(
    crates: &BTreeMap<Box<str>, CrateIndex>,
    workspace_root: &Path,
    config: &Config,
) -> Box<[Violation]> {
    let rust_files = collect_rust_files(crates);
    let metadata = load_cargo_metadata_if_needed(config, workspace_root);
    let ctx = ProjectContext {
        rust_files: &rust_files,
        workspace_root,
        metadata: metadata.as_ref(),
        // TODO(#57 follow-up): thread FileShapes for cross-file type checks in MCP.
        file_shapes: &[],
    };
    let mut violations = Vec::new();
    check_project(&ctx, config, &mut violations);
    violations.into_boxed_slice()
}

/// Collect every indexed Rust source path across all crates.
fn collect_rust_files(crates: &BTreeMap<Box<str>, CrateIndex>) -> Vec<String> {
    crates
        .values()
        .flat_map(|c| c.files.keys())
        .filter(|path| path.ends_with(".rs"))
        .map(ToString::to_string)
        .collect()
}

/// Run `cargo metadata` for the feature-boundary check, but only when it is
/// enabled and has rules. Failures fall back to skipping the check with a warning.
fn load_cargo_metadata_if_needed(config: &Config, workspace_root: &Path) -> Option<CargoMetadata> {
    match config.check_feature_boundary && !config.feature_boundaries.is_empty() {
        false => None,
        true => run_cargo_metadata(workspace_root),
    }
}

fn run_cargo_metadata(workspace_root: &Path) -> Option<CargoMetadata> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(workspace_root)
        .output();
    match output {
        Ok(out) if out.status.success() => serde_json::from_slice(&out.stdout).ok(),
        _ => {
            drop(writeln!(
                std::io::stderr(),
                "warning: feature-boundary: `cargo metadata` unavailable; skipping the check"
            ));
            None
        }
    }
}

#[cfg(feature = "semantic")]
fn load_semantic_for_reindex(workspace_root: Option<&Path>) -> Option<SemanticContext> {
    workspace_root.and_then(SemanticContext::load)
}

#[cfg(not(feature = "semantic"))]
fn load_semantic_for_reindex(workspace_root: Option<&Path>) -> Option<SemanticContext> {
    // Signature must mirror the `semantic` variant so both call sites compile.
    // `and` consumes the root and yields None, so there is nothing to suppress.
    workspace_root.and(None)
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
