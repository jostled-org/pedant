//! One Cargo authority's target slices.
//!
//! A selected Cargo authority emits one slice per compiled entry point — the
//! library and each binary — because those are the units whose module closures
//! a graph is built over. Test, example, and benchmark targets share those
//! closures and add no navigable unit of their own, so indexing them would
//! restate the same declarations under more keys.
//!
//! Every package the loaded project indexed is claimed, so a workspace member's
//! own `Cargo.toml` is not selected a second time as a standalone package.

use pedant_core::resolution::rust::{
    CargoTargetKind, ResolutionLimit, ResolutionLimits, RustProject, RustProjectError,
    RustResolutionError, RustResolver, RustSnapshotError, RustSourceFault, RustTarget,
    SourceClosureFailureKind, TargetId,
};
use pedant_types::Language;

use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError};
use super::graph_budget::GraphBudget;
use super::issue::IssueStage;
use super::limits::CodeIntelligenceLimits;
use super::path::CanonicalRoot;
use super::project::ProjectKey;
use super::provider::ScopedSources;
use super::retained::RetainedGraph;
use super::reuse::GraphReuse;
use super::slice::{PendingSlice, Selection, SliceFailure, beneath, directory_of, graph_failure};
use super::store::RepositorySourceStore;
use std::sync::Arc;

/// What one target's graph is built through.
///
/// The reuse store and the repository's remaining graph allowance travel
/// together through every step below. Named rather than paired, because both
/// are `&mut` borrows of unrelated state and a transposition of the pair
/// type-checks nowhere it matters and reads wrongly everywhere it does.
struct GraphWork<'work> {
    /// The bounded store an unchanged target's graph is reused from.
    reuse: &'work mut GraphReuse,
    /// What the repository will still admit into graphs.
    budget: &'work mut GraphBudget,
}

/// One compiled target of one loaded project, and the authority that selected
/// it.
struct TargetScope<'scope> {
    /// The loaded project the target belongs to.
    project: &'scope RustProject,
    /// The compiled target itself.
    target: &'scope RustTarget,
    /// The authority's own directory, in repository spelling.
    directory: &'scope str,
    /// The normalized authority path every slice of it is keyed by.
    authority: &'scope Arc<str>,
}

/// One target's graph, as this build scopes and keys it.
struct ResolutionScope<'scope> {
    /// The authority's own directory, in repository spelling.
    directory: &'scope str,
    /// The target whose compilation closure is snapshotted.
    target: TargetId,
    /// The key the resolved slice is retained under.
    key: ProjectKey,
}

/// Load one Cargo authority and resolve every entry point it declares.
pub(crate) fn select(
    store: &mut RepositorySourceStore,
    root: &CanonicalRoot,
    authority: &Arc<str>,
    reuse: (&mut GraphReuse, &mut GraphBudget),
) -> Selection {
    let (reuse, budget) = reuse;
    let mut work = GraphWork { reuse, budget };
    let limits = *store.limits();
    let directory = directory_of(authority);
    let project = match RustProject::load(&root.as_path().join(directory), limits.rust) {
        Ok(project) => project,
        Err(error) => {
            let stated = project_capacity(&error);
            return Selection::refused(SliceFailure::stated(IssueStage::Authority, stated, error));
        }
    };

    let claimed = project
        .packages()
        .iter()
        .map(|package| beneath(directory, package.manifest_path()))
        .collect();
    let mut selection = Selection {
        slices: Vec::new(),
        claimed,
        failures: Vec::new(),
    };
    for target in project.targets().iter().filter(|target| compiled(target)) {
        let scope = TargetScope {
            project: &project,
            target,
            directory,
            authority,
        };
        match selected(store, &scope, &mut work, &limits) {
            Ok(slice) => selection.slices.push(slice),
            Err(failure) => selection.failures.push(failure),
        }
    }
    selection
}

/// Resolve one compiled target, attributing a refusal to its own manifest.
///
/// The package is read once and answers both questions this target asks of it:
/// the name that keys the project, and the manifest a refusal belongs to. The
/// manifest is joined only on the refusing branch, because a resolved target
/// never names it.
fn selected(
    store: &mut RepositorySourceStore,
    scope: &TargetScope<'_>,
    work: &mut GraphWork<'_>,
    limits: &CodeIntelligenceLimits,
) -> Result<PendingSlice, SliceFailure> {
    let package = scope
        .project
        .package(scope.target.package())
        .ok_or_else(|| unnamed_package(scope.target))?;
    let stated = ResolutionScope {
        directory: scope.directory,
        target: scope.target.id(),
        key: target_key(package.name(), scope.target, scope.authority),
    };
    resolve(store, scope.project, stated, work, limits)
        .map_err(|failure| failure.for_manifest(beneath(scope.directory, package.manifest_path())))
}

/// One compiled target whose package the loaded project does not hold.
///
/// Refused rather than keyed under an empty package segment. A workspace states
/// many targets called `main`, and the package name is what tells them apart —
/// two unnamed ones would mint the same [`ProjectKey`], and an index keyed by
/// that answers one target's questions with the other's graph.
fn unnamed_package(target: &RustTarget) -> SliceFailure {
    SliceFailure::at(
        IssueStage::Authority,
        format!(
            "the loaded project holds no package for target {}",
            target.name()
        ),
    )
}

/// Whether this target is a compiled entry point a slice is built over.
fn compiled(target: &RustTarget) -> bool {
    matches!(
        target.kind(),
        CargoTargetKind::Library | CargoTargetKind::Binary
    )
}

/// The key that selects one target's graph.
///
/// The package name and the target kind and name together, because a workspace
/// states many targets called `main` and one authority path cannot tell them
/// apart.
fn target_key(package: &str, target: &RustTarget, authority: &Arc<str>) -> ProjectKey {
    let unit = format!(
        "{package}::{}::{}",
        kind_token(target.kind()),
        target.name()
    );
    ProjectKey::new(
        Language::Rust,
        Arc::clone(authority),
        Arc::from(unit.as_str()),
    )
}

/// The stable token one target kind takes in a project key.
///
/// Spelled here rather than borrowed from the resolution crate's own unit
/// vocabulary: that one keys resolution units, this one keys navigation
/// projects, and the two must be free to change apart.
fn kind_token(kind: CargoTargetKind) -> &'static str {
    match kind {
        CargoTargetKind::Library => "lib",
        CargoTargetKind::Binary => "bin",
        CargoTargetKind::Example => "example",
        CargoTargetKind::Test => "test",
        CargoTargetKind::Benchmark => "bench",
        CargoTargetKind::BuildScript => "build-script",
    }
}

/// Snapshot, resolve, and build one target's graph through the shared store.
fn resolve(
    store: &mut RepositorySourceStore,
    project: &RustProject,
    scope: ResolutionScope<'_>,
    work: &mut GraphWork<'_>,
    limits: &CodeIntelligenceLimits,
) -> Result<PendingSlice, SliceFailure> {
    let mut scoped = ScopedSources::new(store, scope.directory);
    let snapshot = match project.snapshot_resolution_with_provider(&mut scoped, scope.target) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let provider = scoped.take_capacity();
            let stated = snapshot_capacity(&error, limits.rust);
            return Err(SliceFailure::from_provider(
                IssueStage::Snapshot,
                provider,
                stated,
                error,
            ));
        }
    };
    let sources = scoped.reached();
    let resolution = RustResolver::resolve_syntactic(&snapshot).map_err(|error| {
        let stated = resolution_capacity(&error);
        SliceFailure::stated(IssueStage::Resolution, stated, error)
    })?;
    let admission = work.budget.clamped(limits.graph_build);
    let held = work
        .reuse
        .rust_graph(&snapshot, &resolution, admission.limits())
        .map_err(|error| graph_failure(error, &admission))?;
    *work.budget = work.budget.spent(held.graph());
    Ok(PendingSlice {
        key: scope.key,
        coverage: super::coverage::StructureCoverage::Resolved,
        sources,
        graph: RetainedGraph::Reused(held),
    })
}

/// A Rust provider refusal that crossed one of its own ceilings.
///
/// Every other variant is named rather than left to a catch-all. The upstream
/// enum states no `#[non_exhaustive]`, so a capacity variant added to it would
/// otherwise fall through to a `Debug`-rendered prose refusal and lose the
/// ceiling it names — silently, and to every reader downstream.
pub(crate) fn source_capacity(error: &RustSourceFault) -> Option<CodeIntelligenceError> {
    match error {
        RustSourceFault::SourceFiles { ceiling } => {
            Some(wide_capacity(CapacityCollection::File, *ceiling))
        }
        RustSourceFault::SourceBytes { ceiling } => {
            Some(wide_capacity(CapacityCollection::FileBytes, *ceiling))
        }
        RustSourceFault::TotalBytes { ceiling } => {
            Some(wide_capacity(CapacityCollection::TotalBytes, *ceiling))
        }
        RustSourceFault::SyntaxDepth { ceiling } => {
            Some(wide_capacity(CapacityCollection::SyntaxDepth, *ceiling))
        }
        RustSourceFault::Unreadable(_)
        | RustSourceFault::OutOfRoot { .. }
        | RustSourceFault::InvalidUtf8 { .. }
        | RustSourceFault::Unparsed { .. }
        | RustSourceFault::Refused { .. } => None,
    }
}

/// A Rust project refusal that crossed one project-loader ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn project_capacity(error: &RustProjectError) -> Option<CodeIntelligenceError> {
    match error {
        RustProjectError::LimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Manifest, *limit))
        }
        RustProjectError::MemberScanLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::DirectoryEntry, *limit))
        }
        RustProjectError::InvalidRoot { .. }
        | RustProjectError::OutOfRoot { .. }
        | RustProjectError::NonUtf8Path { .. }
        | RustProjectError::ManifestRead { .. }
        | RustProjectError::ManifestParse { .. }
        | RustProjectError::MissingPackageVersion { .. }
        | RustProjectError::MissingWorkspacePackageVersion { .. }
        | RustProjectError::InvalidPackageVersion { .. }
        | RustProjectError::InvalidPackageEdition { .. }
        | RustProjectError::MissingWorkspacePackageEdition { .. } => None,
    }
}

/// A Rust closure refusal that crossed one snapshot ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn snapshot_capacity(
    error: &RustSnapshotError,
    limits: ResolutionLimits,
) -> Option<CodeIntelligenceError> {
    match error {
        RustSnapshotError::SourceClosure(error) => error
            .failures()
            .iter()
            .find_map(|failure| closure_capacity(failure.kind(), limits)),
        RustSnapshotError::ForeignPackage
        | RustSnapshotError::StalePackage
        | RustSnapshotError::UnknownPackage { .. }
        | RustSnapshotError::ForeignTarget
        | RustSnapshotError::StaleTarget
        | RustSnapshotError::UnknownTarget { .. }
        | RustSnapshotError::ProjectManifestsChanged { .. }
        | RustSnapshotError::ManifestUnreadable { .. } => None,
    }
}

/// The ceiling one closure failure crossed, for the failures that cross one.
///
/// Every other kind named, for the reason [`source_capacity`] names its own.
fn closure_capacity(
    kind: SourceClosureFailureKind,
    limits: ResolutionLimits,
) -> Option<CodeIntelligenceError> {
    match kind {
        SourceClosureFailureKind::LimitExceeded(limit) => {
            Some(snapshot_limit_capacity(limit, limits))
        }
        SourceClosureFailureKind::EntryRead
        | SourceClosureFailureKind::ModuleRead
        | SourceClosureFailureKind::SourceParse
        | SourceClosureFailureKind::MissingModule
        | SourceClosureFailureKind::AmbiguousModule
        | SourceClosureFailureKind::MissingDependencyLibraryTarget
        | SourceClosureFailureKind::UnresolvedDependencyLibraryTarget
        | SourceClosureFailureKind::MissingStoredSource
        | SourceClosureFailureKind::DependencyCycle
        | SourceClosureFailureKind::OutOfRoot
        | SourceClosureFailureKind::InvalidUtf8 => None,
    }
}

/// The configured Rust snapshot field named by one crossed closure limit.
fn snapshot_limit_capacity(
    limit: ResolutionLimit,
    limits: ResolutionLimits,
) -> CodeIntelligenceError {
    let (collection, ceiling) = match limit {
        ResolutionLimit::Units => (CapacityCollection::Unit, u64::from(limits.max_units)),
        ResolutionLimit::SourceFiles => {
            (CapacityCollection::File, u64::from(limits.max_source_files))
        }
        ResolutionLimit::SourceFileBytes => {
            (CapacityCollection::FileBytes, limits.max_source_file_bytes)
        }
        ResolutionLimit::TotalSourceBytes => (
            CapacityCollection::TotalBytes,
            limits.max_total_source_bytes,
        ),
        ResolutionLimit::ModuleDepth => (
            CapacityCollection::ModuleDepth,
            u64::from(limits.max_module_depth),
        ),
        ResolutionLimit::ModuleInstances => (
            CapacityCollection::ModuleInstance,
            u64::from(limits.max_module_instances),
        ),
        ResolutionLimit::DependencyDepth => (
            CapacityCollection::DependencyDepth,
            u64::from(limits.max_dependency_depth),
        ),
        ResolutionLimit::SyntaxDepth => (
            CapacityCollection::SyntaxDepth,
            u64::from(limits.max_syntax_depth),
        ),
    };
    wide_capacity(collection, ceiling)
}

/// A Rust resolver refusal that crossed a candidate or report ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn resolution_capacity(error: &RustResolutionError) -> Option<CodeIntelligenceError> {
    match error {
        RustResolutionError::LimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Candidate, *limit))
        }
        RustResolutionError::Report(error) => {
            super::slice::report_capacity(CapacityOwner::Rust, error)
        }
        RustResolutionError::UnitMapping { .. }
        | RustResolutionError::UnitCountMismatch { .. }
        | RustResolutionError::UnknownFile { .. }
        | RustResolutionError::UnsupportedDefinitionKind { .. }
        | RustResolutionError::UnsupportedReferenceKind { .. }
        | RustResolutionError::InvalidCoordinate { .. }
        | RustResolutionError::ImportsNotConverged { .. }
        | RustResolutionError::SemanticContextMismatch { .. }
        | RustResolutionError::SemanticSharedSourceMismatch { .. } => None,
    }
}

/// One first-excess refusal owned by Rust, for a ceiling published as `u32`.
fn narrow_capacity(collection: CapacityCollection, limit: u32) -> CodeIntelligenceError {
    super::slice::language_capacity(CapacityOwner::Rust, collection, limit)
}

/// The same, for a Rust ceiling its owner already publishes as `u64`.
fn wide_capacity(collection: CapacityCollection, limit: u64) -> CodeIntelligenceError {
    super::slice::language_capacity_u64(CapacityOwner::Rust, collection, limit)
}
