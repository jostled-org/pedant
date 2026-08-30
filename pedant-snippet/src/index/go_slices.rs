//! One Go authority's module slice.
//!
//! A Go project is one graph: the main module together with every local
//! replacement it admitted. Those replacements are claimed, so a nested `go.mod`
//! that another selected module replaces is not selected a second time as its
//! own main module — while a nested module nobody replaces stays independent
//! and gets its own slice.

use std::sync::Arc;

use pedant_core::resolution::go::{
    GoProject, GoProjectError, GoResolutionError, GoResolver, GoSnapshotError, GoSourceFault,
};
use pedant_syntax::go::GoFactError;
use pedant_types::Language;

use super::coverage::StructureCoverage;
use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError};
use super::graph_budget::GraphBudget;
use super::issue::IssueStage;
use super::path::CanonicalRoot;
use super::project::ProjectKey;
use super::provider::ScopedSources;
use super::retained::RetainedGraph;
use super::slice::{PendingSlice, Selection, SliceFailure, beneath, directory_of, graph_failure};
use super::store::RepositorySourceStore;

/// Load one Go authority and resolve the module graph it states.
pub(crate) fn select(
    store: &mut RepositorySourceStore,
    root: &CanonicalRoot,
    authority: &Arc<str>,
    budget: &mut GraphBudget,
) -> Selection {
    let limits = *store.limits();
    let directory = directory_of(authority);
    let project = match GoProject::load(&root.as_path().join(directory), limits.go) {
        Ok(project) => project,
        Err(error) => {
            let stated = project_capacity(&error);
            return Selection::refused(SliceFailure::stated(IssueStage::Authority, stated, error));
        }
    };

    let claimed = project
        .modules()
        .map(|module| beneath(directory, module.manifest()))
        .collect();
    let key = ProjectKey::new(
        Language::Go,
        Arc::clone(authority),
        Arc::from(project.root_module().path()),
    );
    let (slices, failures) =
        match resolve(store, &project, directory, key, budget, limits.graph_build) {
            Ok(slice) => (vec![slice], Vec::new()),
            Err(failure) => (Vec::new(), vec![failure]),
        };
    Selection {
        slices,
        claimed,
        failures,
    }
}

/// Snapshot, resolve, and build one module graph through the shared store.
fn resolve(
    store: &mut RepositorySourceStore,
    project: &GoProject,
    directory: &str,
    key: ProjectKey,
    budget: &mut GraphBudget,
    configured: pedant_graph::GraphLimits,
) -> Result<PendingSlice, SliceFailure> {
    let mut scoped = ScopedSources::new(store, directory);
    let snapshot = match project.snapshot_resolution_with_provider(&mut scoped) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let provider = scoped.take_capacity();
            let stated = snapshot_capacity(&error);
            return Err(SliceFailure::from_provider(
                IssueStage::Snapshot,
                provider,
                stated,
                error,
            ));
        }
    };
    let sources = scoped.reached();
    let resolution = GoResolver::resolve_syntactic(&snapshot).map_err(|error| {
        let stated = resolution_capacity(&error);
        SliceFailure::stated(IssueStage::Resolution, stated, error)
    })?;
    let admission = budget.clamped(configured);
    let graph =
        pedant_graph::build_go_graph_with_limits(&snapshot, &resolution, admission.limits())
            .map_err(|error| graph_failure(error, &admission))?;
    *budget = budget.spent(&graph);
    Ok(PendingSlice {
        key,
        coverage: StructureCoverage::Resolved,
        sources,
        graph: RetainedGraph::Direct(Arc::new(graph)),
    })
}

/// A Go provider refusal that crossed one of its own ceilings.
///
/// Every other variant is named rather than left to a catch-all. The upstream
/// enum states no `#[non_exhaustive]`, so a capacity variant added to it would
/// otherwise fall through to a `Debug`-rendered prose refusal and lose the
/// ceiling it names — silently, and to every reader downstream.
pub(crate) fn source_capacity(error: &GoSourceFault) -> Option<CodeIntelligenceError> {
    match error {
        GoSourceFault::SourceFiles { ceiling } => {
            Some(narrow_capacity(CapacityCollection::File, *ceiling))
        }
        GoSourceFault::SourceBytes { ceiling } => {
            Some(wide_capacity(CapacityCollection::FileBytes, *ceiling))
        }
        GoSourceFault::TotalBytes { ceiling } => {
            Some(wide_capacity(CapacityCollection::TotalBytes, *ceiling))
        }
        GoSourceFault::FactExtraction(error) => fact_capacity(error),
        GoSourceFault::Unreadable(_)
        | GoSourceFault::OutOfRoot { .. }
        | GoSourceFault::NonUtf8Path { .. }
        | GoSourceFault::PathRead { .. }
        | GoSourceFault::NonUtf8 { .. }
        | GoSourceFault::Unparsed { .. }
        | GoSourceFault::Incomplete(_)
        | GoSourceFault::MissingPackageClause
        | GoSourceFault::Refused { .. }
        | GoSourceFault::StructureProjection { .. } => None,
    }
}

/// A Go project refusal that crossed one project-loader ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn project_capacity(error: &GoProjectError) -> Option<CodeIntelligenceError> {
    match error {
        GoProjectError::ManifestLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Manifest, *limit))
        }
        GoProjectError::DependencyDepthLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::DependencyDepth, *limit))
        }
        GoProjectError::InvalidRoot { .. }
        | GoProjectError::OutOfRoot { .. }
        | GoProjectError::NonUtf8Path { .. }
        | GoProjectError::PathRead { .. }
        | GoProjectError::ManifestRead { .. }
        | GoProjectError::ManifestParse { .. }
        | GoProjectError::MissingModuleDeclaration { .. }
        | GoProjectError::DuplicateRequirement { .. }
        | GoProjectError::DuplicateExclusion { .. }
        | GoProjectError::DuplicateReplacement { .. }
        | GoProjectError::InvalidVersion { .. }
        | GoProjectError::ExcludedRequirement { .. }
        | GoProjectError::MissingReplacementManifest { .. }
        | GoProjectError::ReplacementModuleMismatch { .. }
        | GoProjectError::ConflictingLocalModules { .. }
        | GoProjectError::MissingAdmittedModule { .. } => None,
    }
}

/// A Go snapshot refusal that crossed one snapshot ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn snapshot_capacity(error: &GoSnapshotError) -> Option<CodeIntelligenceError> {
    match error {
        GoSnapshotError::DirectoryEntryLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::DirectoryEntry, *limit))
        }
        GoSnapshotError::UnitLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Unit, *limit))
        }
        GoSnapshotError::SourceFileLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::File, *limit))
        }
        GoSnapshotError::SourceBytesLimitExceeded { limit, .. } => {
            Some(wide_capacity(CapacityCollection::FileBytes, *limit))
        }
        GoSnapshotError::TotalSourceBytesLimitExceeded { limit } => {
            Some(wide_capacity(CapacityCollection::TotalBytes, *limit))
        }
        GoSnapshotError::RetainedFactsExceeded { limit, .. } => {
            Some(narrow_capacity(CapacityCollection::Fact, *limit))
        }
        GoSnapshotError::RetainedDepthExceeded { limit, .. } => {
            Some(narrow_capacity(CapacityCollection::SyntaxDepth, *limit))
        }
        GoSnapshotError::FactExtraction { source, .. } => fact_capacity(source),
        GoSnapshotError::OutOfRoot { .. }
        | GoSnapshotError::NonUtf8Path { .. }
        | GoSnapshotError::PathRead { .. }
        | GoSnapshotError::DirectoryRead { .. }
        | GoSnapshotError::SourceRead { .. }
        | GoSnapshotError::UnnormalizedPath { .. }
        | GoSnapshotError::NonUtf8Source { .. }
        | GoSnapshotError::UnparsedSource { .. }
        | GoSnapshotError::IncompleteSource { .. }
        | GoSnapshotError::MissingPackageClause { .. }
        | GoSnapshotError::AlreadyRefused { .. }
        | GoSnapshotError::StructureProjection { .. }
        | GoSnapshotError::MissingStoredSource { .. }
        | GoSnapshotError::ConflictingPackageClause { .. } => None,
    }
}

/// One bounded Go fact-walk refusal.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn fact_capacity(error: &GoFactError) -> Option<CodeIntelligenceError> {
    match error {
        GoFactError::SyntaxDepthExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::SyntaxDepth, *limit))
        }
        GoFactError::FactCapacityExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Fact, *limit))
        }
        GoFactError::LanguageMismatch { .. } | GoFactError::DeclarationMapping { .. } => None,
    }
}

/// A Go resolver refusal that crossed a candidate, comparison, or report ceiling.
///
/// Every other variant named, for the reason [`source_capacity`] names its own.
fn resolution_capacity(error: &GoResolutionError) -> Option<CodeIntelligenceError> {
    match error {
        GoResolutionError::CandidateLimitExceeded { limit } => {
            Some(narrow_capacity(CapacityCollection::Candidate, *limit))
        }
        GoResolutionError::InterfaceComparisonLimitExceeded { limit } => Some(narrow_capacity(
            CapacityCollection::InterfaceComparison,
            *limit,
        )),
        GoResolutionError::Report(error) => super::slice::report_capacity(CapacityOwner::Go, error),
        GoResolutionError::UnitMapping { .. }
        | GoResolutionError::UnitCountMismatch { .. }
        | GoResolutionError::DefinitionMapping { .. }
        | GoResolutionError::UnknownFile { .. }
        | GoResolutionError::UnsupportedDefinitionKind { .. }
        | GoResolutionError::UnsupportedReferenceKind { .. }
        | GoResolutionError::InvalidCoordinate { .. } => None,
    }
}

/// One first-excess refusal owned by Go, for a ceiling published as `u32`.
fn narrow_capacity(collection: CapacityCollection, limit: u32) -> CodeIntelligenceError {
    super::slice::language_capacity(CapacityOwner::Go, collection, limit)
}

/// The same, for a Go ceiling its owner already publishes as `u64`.
fn wide_capacity(collection: CapacityCollection, limit: u64) -> CodeIntelligenceError {
    super::slice::language_capacity_u64(CapacityOwner::Go, collection, limit)
}
