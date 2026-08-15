//! Cargo-project orchestration: configuration authority, target selection, the
//! deterministic Tier 1 or Tier 2 pipeline, and buffered evaluation.
//!
//! Every selected target is judged separately and its verdicts are buffered.
//! One failure anywhere discards every buffered verdict, because a partial
//! answer would claim the project was judged when it was not.

use std::path::Path;
use std::sync::Arc;

use pedant_core::SemanticContext;
use pedant_core::check_config::{
    ConfigError, ConfigFile, GateConfig, ModuleBoundaryConfig, find_global_config_file,
    load_config_file,
};
use pedant_core::gate::{GateVerdict, evaluate_module_boundary_rules};
use pedant_core::resolution::rust::{
    CargoTargetKind, ResolutionLimits, RustPackage, RustProject, RustResolutionError,
    RustResolutionSnapshot, RustResolver, RustTarget, RustTargetResolution, TargetId,
};
use pedant_graph::{
    GraphAnalysis, GraphAnalysisLimits, GraphCertainty, GraphEdgeKind, GraphEdgeSelection,
    GraphLimits, build_rust_graph_with_limits,
};
use pedant_types::AnalysisTier;

use super::error::ProjectGateError;
use super::evidence;

/// What one successful project run reports.
pub(crate) struct ProjectGateReport {
    /// The one tier every analyzed target was resolved at.
    pub(crate) tier: AnalysisTier,
    /// Every analyzed root-target label, in selection order.
    pub(crate) targets: Box<[Arc<str>]>,
    /// Every buffered verdict, in target then rule then input order.
    pub(crate) verdicts: Box<[GateVerdict]>,
}

impl ProjectGateReport {
    /// Pair the buffered verdicts with the tier and the labels they were
    /// judged under, once every selected target has succeeded.
    fn assembled(
        context: &TierContext,
        targets: &[SelectedTarget],
        verdicts: Box<[GateVerdict]>,
    ) -> Self {
        Self {
            tier: context.analysis_tier(),
            targets: targets
                .iter()
                .map(|target| Arc::clone(&target.label))
                .collect(),
            verdicts,
        }
    }
}

/// One selected root target: its identity and the label its evidence carries.
struct SelectedTarget {
    id: TargetId,
    label: Arc<str>,
}

/// The one resolution context every selected target is resolved through.
///
/// Tier 1 holds nothing and invokes no toolchain. Tier 2 holds exactly one
/// context, loaded once at the canonical project root before target iteration
/// begins, so no target can be judged against a different database.
struct TierContext {
    semantic: Option<SemanticContext>,
}

impl TierContext {
    /// The tier every analyzed target reports.
    fn analysis_tier(&self) -> AnalysisTier {
        match self.semantic.is_some() {
            true => AnalysisTier::Semantic,
            false => AnalysisTier::Syntactic,
        }
    }

    /// Resolve one snapshot through the held context.
    #[cfg(feature = "semantic")]
    fn resolve(
        &self,
        snapshot: &RustResolutionSnapshot,
    ) -> Result<RustTargetResolution, RustResolutionError> {
        match self.semantic.as_ref() {
            Some(held) => RustResolver::resolve_semantic(snapshot, held),
            None => RustResolver::resolve_syntactic(snapshot),
        }
    }

    /// Resolve one snapshot; without the feature there is no other tier.
    #[cfg(not(feature = "semantic"))]
    fn resolve(
        &self,
        snapshot: &RustResolutionSnapshot,
    ) -> Result<RustTargetResolution, RustResolutionError> {
        RustResolver::resolve_syntactic(snapshot)
    }
}

/// Judge one Cargo project, buffering every target result until all succeed.
pub(crate) fn evaluate(
    root: &str,
    explicit_config: Option<&str>,
    semantic: bool,
) -> Result<ProjectGateReport, ProjectGateError> {
    let canonical =
        std::fs::canonicalize(root).map_err(|source| ProjectGateError::ProjectRoot {
            root: Box::from(root),
            source,
        })?;
    let file_config = resolve_config(explicit_config, &canonical)?;
    let defaults = GateConfig::default();
    let gate_config = file_config.as_ref().map_or(&defaults, |held| &held.gate);
    let project = load_project(&canonical)?;
    let targets = require_targets(select_targets(&project)?, &canonical)?;
    let context = tier_context(&canonical, semantic)?;
    let verdicts = buffered_verdicts(&project, &targets, gate_config, &context)?;
    Ok(ProjectGateReport::assembled(&context, &targets, verdicts))
}

/// Refuse a project that declares no independent root target.
fn require_targets(
    targets: Box<[SelectedTarget]>,
    canonical: &Path,
) -> Result<Box<[SelectedTarget]>, ProjectGateError> {
    match targets.is_empty() {
        true => Err(ProjectGateError::NoPrimaryTarget {
            root: display(canonical),
        }),
        false => Ok(targets),
    }
}

fn load_project(canonical: &Path) -> Result<RustProject, ProjectGateError> {
    RustProject::load(canonical, ResolutionLimits::default()).map_err(|source| {
        ProjectGateError::ProjectLoad {
            root: display(canonical),
            source,
        }
    })
}

/// Judge every selected target, discarding all verdicts on the first refusal.
fn buffered_verdicts(
    project: &RustProject,
    targets: &[SelectedTarget],
    config: &GateConfig,
    context: &TierContext,
) -> Result<Box<[GateVerdict]>, ProjectGateError> {
    let mut buffered = Vec::new();
    for target in targets {
        buffered.extend(target_verdicts(project, target, config, context)?);
    }
    Ok(buffered.into_boxed_slice())
}

/// The deterministic snapshot, resolution, graph, analysis, projection, and
/// policy pipeline for one root target.
fn target_verdicts(
    project: &RustProject,
    target: &SelectedTarget,
    config: &GateConfig,
    context: &TierContext,
) -> Result<Box<[GateVerdict]>, ProjectGateError> {
    let label = &target.label;
    let snapshot =
        project
            .snapshot_resolution(target.id)
            .map_err(|source| ProjectGateError::Snapshot {
                target: Box::from(&**label),
                source,
            })?;
    let resolution = context
        .resolve(&snapshot)
        .map_err(|source| ProjectGateError::Resolution {
            target: Box::from(&**label),
            source,
        })?;
    let boundary = &config.module_boundary;
    let graph = build_rust_graph_with_limits(&snapshot, &resolution, graph_limits(boundary))
        .map_err(|source| ProjectGateError::GraphBuild {
            target: Box::from(&**label),
            source,
        })?;
    let analysis =
        GraphAnalysis::new(&graph, selection(), analysis_limits(boundary)).map_err(|source| {
            ProjectGateError::Analysis {
                target: Box::from(&**label),
                source,
            }
        })?;
    let input = evidence::project_target(&analysis, Arc::clone(label)).map_err(|source| {
        ProjectGateError::Evidence {
            target: Box::from(&**label),
            source,
        }
    })?;
    Ok(evaluate_module_boundary_rules(&input, config))
}

/// The fixed selection module-boundary judgment reads.
///
/// Resolved code relations only: a `Possible` edge encodes ambiguity, and a
/// dependency edge relates build units rather than declarations, so neither can
/// support a blocking structural claim.
fn selection() -> GraphEdgeSelection {
    GraphEdgeSelection::new(
        &[
            GraphEdgeKind::Call,
            GraphEdgeKind::Import,
            GraphEdgeKind::Implementation,
            GraphEdgeKind::Reference,
        ],
        &[GraphCertainty::Resolved],
    )
}

fn graph_limits(config: &ModuleBoundaryConfig) -> GraphLimits {
    GraphLimits::new(
        config.max_nodes(),
        config.max_references(),
        config.max_edges(),
    )
}

/// Analysis ceilings, with traversal depth and betweenness work at zero because
/// this path walks no neighborhood and measures no centrality.
fn analysis_limits(config: &ModuleBoundaryConfig) -> GraphAnalysisLimits {
    GraphAnalysisLimits::new(config.max_nodes(), config.max_selected_edges(), 0, 0)
}

/// Load one semantic context when the operator asked for Tier 2.
fn tier_context(canonical: &Path, semantic: bool) -> Result<TierContext, ProjectGateError> {
    match semantic {
        false => Ok(TierContext { semantic: None }),
        true => load_semantic_context(canonical),
    }
}

#[cfg(feature = "semantic")]
fn load_semantic_context(canonical: &Path) -> Result<TierContext, ProjectGateError> {
    SemanticContext::load(canonical)
        .map(|held| TierContext {
            semantic: Some(held),
        })
        .ok_or_else(|| ProjectGateError::SemanticContext {
            root: display(canonical),
        })
}

/// Without the feature the binary states no `--semantic` argument, so an
/// explicit Tier 2 request cannot be written and this refusal cannot be reached
/// — it exists so no configuration silently reports a syntactic success.
#[cfg(not(feature = "semantic"))]
fn load_semantic_context(canonical: &Path) -> Result<TierContext, ProjectGateError> {
    Err(ProjectGateError::SemanticContext {
        root: display(canonical),
    })
}

/// Every workspace-member library, binary, and build-script target, in the
/// project's own package, kind, then name order.
fn select_targets(project: &RustProject) -> Result<Box<[SelectedTarget]>, ProjectGateError> {
    project
        .targets()
        .iter()
        .filter_map(|target| selected(project, target).transpose())
        .collect()
}

/// A kind that is not an independent root selects nothing; a package the
/// project does not hold refuses, so the two answers stay distinguishable.
fn selected(
    project: &RustProject,
    target: &RustTarget,
) -> Result<Option<SelectedTarget>, ProjectGateError> {
    let Some(token) = primary_token(target.kind()) else {
        return Ok(None);
    };
    let package =
        project
            .package(target.package())
            .ok_or_else(|| ProjectGateError::UnknownPackage {
                target: Box::from(target.name()),
            })?;
    Ok(package.is_workspace_member().then(|| SelectedTarget {
        id: target.id(),
        label: Arc::from(root_label(package, token, target.name())),
    }))
}

/// The exact evidence label one root target carries.
fn root_label(package: &RustPackage, token: &str, name: &str) -> String {
    let directory = match package.relative_directory().is_empty() {
        true => ".",
        false => package.relative_directory(),
    };
    format!("{directory}#{token}:{name}")
}

/// The label token one primary target kind takes, or nothing when the kind is
/// not an independent root.
fn primary_token(kind: CargoTargetKind) -> Option<&'static str> {
    match kind {
        CargoTargetKind::Library => Some("lib"),
        CargoTargetKind::Binary => Some("bin"),
        CargoTargetKind::BuildScript => Some("build-script"),
        CargoTargetKind::Example | CargoTargetKind::Test | CargoTargetKind::Benchmark => None,
    }
}

/// Explicit `--config` first, then the project-local file, then the global one,
/// then defaults. An explicit path is read exactly as the caller wrote it.
fn resolve_config(
    explicit: Option<&str>,
    canonical: &Path,
) -> Result<Option<ConfigFile>, ProjectGateError> {
    match explicit {
        Some(path) => required_config(Path::new(path)).map(Some),
        None => discovered_config(canonical),
    }
}

fn required_config(path: &Path) -> Result<ConfigFile, ProjectGateError> {
    load_config_file(path).map_err(config_error(path))
}

fn discovered_config(canonical: &Path) -> Result<Option<ConfigFile>, ProjectGateError> {
    match optional_config(&canonical.join(".pedant.toml"))? {
        Some(config) => Ok(Some(config)),
        None => global_config(),
    }
}

/// The global source, reached only when the project declares none of its own.
fn global_config() -> Result<Option<ConfigFile>, ProjectGateError> {
    match find_global_config_file() {
        Some(path) => optional_config(&path),
        None => Ok(None),
    }
}

/// A discovered source: an absent file advances, anything else is fatal.
fn optional_config(path: &Path) -> Result<Option<ConfigFile>, ProjectGateError> {
    match load_config_file(path) {
        Ok(config) => Ok(Some(config)),
        Err(ConfigError::Read(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(config_error(path)(source)),
    }
}

/// The one owner that names a configuration source in a refusal.
///
/// `FnOnce`, because a refusal happens at most once per source and the named
/// path is moved into it rather than copied for it.
fn config_error(path: &Path) -> impl FnOnce(ConfigError) -> ProjectGateError {
    let path = display(path);
    move |source| ProjectGateError::Config { path, source }
}

fn display(path: &Path) -> Box<str> {
    Box::from(path.display().to_string())
}
