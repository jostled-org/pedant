//! Turning one selected authority into the project graphs it states.
//!
//! Each language owner keeps its own selection, closure, ceilings, ordering,
//! errors, and fingerprints. Nothing here re-implements any of that: the
//! builder loads the project, snapshots it through the shared store, resolves
//! it, and asks the graph crate for the graph. What this module owns is the
//! join — which authority becomes which slices, what each slice is keyed by,
//! which authorities a selected project has already claimed, and which of its
//! units refused.
//!
//! A refusal is per unit rather than per authority, because one unresolvable
//! binary in a workspace is not a reason to answer nothing about its library.

use std::sync::Arc;

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use pedant_graph::{GraphBuildError, GraphCollection};
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use pedant_types::ResolutionReportError;

use super::coverage::StructureCoverage;
use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError, capacity};
use super::issue::{IssueCode, IssueStage};
use super::limits::CodeIntelligenceLimits;
use super::project::{ProjectId, ProjectKey, ProjectSlice};

/// One resolved slice, before it is given its dense identity.
pub(crate) struct PendingSlice {
    /// What selects this slice's graph.
    pub(crate) key: ProjectKey,
    /// What kind of evidence the slice can answer with.
    pub(crate) coverage: StructureCoverage,
    /// Every repository path the slice's corpus reached, sorted.
    pub(crate) sources: Box<[Arc<str>]>,
    /// The graph the slice resolved.
    pub(crate) graph: super::retained::RetainedGraph,
}

/// Why one unit of one authority states no slice.
pub(crate) struct SliceFailure {
    /// Which stage refused.
    pub(crate) stage: IssueStage,
    /// The stable reason code.
    pub(crate) code: IssueCode,
    /// The refusal that stage stated.
    pub(crate) reason: Box<str>,
    /// The package manifest whose unit produced this refusal, when one loaded
    /// project contains enough information to name it.
    required_manifest: Option<Arc<str>>,
    /// The typed capacity refusal hidden by a loader's fault vocabulary.
    capacity: Option<CodeIntelligenceError>,
}

impl SliceFailure {
    /// One failure at `stage`, described by its owner.
    ///
    /// The code is the stage's own, taken from the one table that pairs them.
    /// A producer that named both would be free to give one stage two codes in
    /// two files, and the code carries nothing the stage does not already say.
    pub(crate) fn at(stage: IssueStage, reason: impl ToString) -> Self {
        Self {
            stage,
            code: IssueCode::of_stage(stage),
            reason: reason.to_string().into_boxed_str(),
            required_manifest: None,
            capacity: None,
        }
    }

    /// One typed capacity refusal at the stage whose loader translated it.
    pub(crate) fn from_capacity(stage: IssueStage, error: CodeIntelligenceError) -> Self {
        Self {
            stage,
            code: IssueCode::of_stage(stage),
            reason: error.to_string().into_boxed_str(),
            required_manifest: None,
            capacity: Some(error),
        }
    }

    /// One stage refusal, preferring the typed capacity its loader recovered.
    ///
    /// Every language wrapper asks the same question of its own error — did a
    /// ceiling refuse, and did the mapper name which — and then chooses between
    /// the two constructors above. Eight copies of that choice were eight
    /// chances for one wrapper to drop the typed refusal and report only its
    /// loader's sentence, which is the shape the capacity translation exists to
    /// prevent.
    pub(crate) fn stated(
        stage: IssueStage,
        capacity: Option<CodeIntelligenceError>,
        reason: impl ToString,
    ) -> Self {
        match capacity {
            Some(error) => Self::from_capacity(stage, error),
            None => Self::at(stage, reason),
        }
    }

    /// The same, where the shared provider recovered a ceiling of its own.
    ///
    /// The provider's retained capacity wins over the one the stage's own
    /// vocabulary states, because the provider refused first and named the
    /// ceiling it crossed. Each language's snapshot wrapper stated that policy
    /// in its own doc comment over its own copy of one `or_else`, which is two
    /// chances for one of them to prefer the other way round and report a
    /// ceiling that is not the one that ended the snapshot.
    pub(crate) fn from_provider(
        stage: IssueStage,
        provider: Option<CodeIntelligenceError>,
        stated: Option<CodeIntelligenceError>,
        reason: impl ToString,
    ) -> Self {
        Self::stated(stage, provider.or(stated), reason)
    }

    /// Take the typed capacity refusal this failure carries, when it has one.
    pub(crate) fn take_capacity(&mut self) -> Option<CodeIntelligenceError> {
        self.capacity.take()
    }

    /// The owner of this typed capacity refusal, when this is one.
    pub(crate) fn capacity_owner(&self) -> Option<CapacityOwner> {
        match &self.capacity {
            Some(CodeIntelligenceError::Capacity { owner, .. }) => Some(*owner),
            _ => None,
        }
    }

    /// Attribute this refusal to the package manifest that produced its unit.
    #[cfg(feature = "graph-rust")]
    pub(crate) fn for_manifest(mut self, manifest: Arc<str>) -> Self {
        self.required_manifest = Some(manifest);
        self
    }

    /// The package manifest whose unit produced this refusal, when known.
    pub(crate) fn required_manifest(&self) -> Option<&str> {
        self.required_manifest.as_deref()
    }
}

/// Everything one authority produced.
pub(crate) struct Selection {
    /// The slices, in the order the language owner emitted them.
    pub(crate) slices: Vec<PendingSlice>,
    /// Every authority path this project has already claimed, so a later
    /// candidate for the same project is not selected twice.
    ///
    /// Boxed rather than grown: each producer collects the whole set from its
    /// loaded project in one pass and nothing appends to it afterwards, so the
    /// spare capacity a `Vec` keeps is capacity no writer will ever use.
    pub(crate) claimed: Box<[Arc<str>]>,
    /// Every unit of this authority that refused.
    pub(crate) failures: Vec<SliceFailure>,
}

impl Selection {
    /// An authority that produced nothing but this one refusal.
    pub(crate) fn refused(failure: SliceFailure) -> Self {
        Self {
            slices: Vec::new(),
            claimed: Box::new([]),
            failures: vec![failure],
        }
    }
}

/// The directory one normalized authority path sits in, empty at the root.
pub(crate) fn directory_of(authority: &str) -> &str {
    match authority.rfind('/') {
        Some(cut) => &authority[..cut],
        None => "",
    }
}

/// One path beneath `directory`, in repository spelling.
///
/// The rule itself belongs to [`beneath_into`](super::join::beneath_into),
/// which states it for a caller-supplied buffer. Two copies of "empty directory
/// means the relative path, otherwise the two joined by a slash" were two
/// chances for one producer's project paths to stop matching the join's lookup
/// keys, which is a graph membership that silently finds nothing.
///
/// The buffer is this function's own because its answer is shared: a
/// `Box<[Arc<str>]>` of project sources outlives every call, where the join's
/// key dies inside its lookup.
pub(crate) fn beneath(directory: &str, relative: &str) -> Arc<str> {
    let mut joined = String::new();
    super::join::beneath_into(&mut joined, directory, relative);
    Arc::from(joined.as_str())
}

/// One language owner's fixed-width resolution-report capacity refusal.
///
/// Every other variant is named rather than left to a catch-all, for the reason
/// each language's own mapper names its own: the upstream enum states no
/// `#[non_exhaustive]`, so a fifth capacity variant added to it would otherwise
/// fall through here and lose the ceiling it names — silently, and to every
/// reader downstream.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn report_capacity(
    owner: CapacityOwner,
    error: &ResolutionReportError,
) -> Option<CodeIntelligenceError> {
    let (collection, limit) = match error {
        ResolutionReportError::UnitCapacityExceeded { limit } => (CapacityCollection::Unit, *limit),
        ResolutionReportError::DefinitionCapacityExceeded { limit } => {
            (CapacityCollection::Definition, *limit)
        }
        ResolutionReportError::ReferenceCapacityExceeded { limit } => {
            (CapacityCollection::Reference, *limit)
        }
        ResolutionReportError::ResolutionCapacityExceeded { limit } => {
            (CapacityCollection::ResolutionRecord, *limit)
        }
        ResolutionReportError::ForeignUnitHandle
        | ResolutionReportError::ForeignDefinitionHandle
        | ResolutionReportError::ForeignReferenceHandle
        | ResolutionReportError::DuplicateResolution { .. }
        | ResolutionReportError::UnknownUnit { .. }
        | ResolutionReportError::UnknownDefinition { .. }
        | ResolutionReportError::UnknownReference { .. }
        | ResolutionReportError::NonDenseId { .. }
        | ResolutionReportError::UnsortedEntries { .. }
        | ResolutionReportError::DuplicateUnitKey { .. }
        | ResolutionReportError::UnitLanguageMismatch { .. }
        | ResolutionReportError::ForeignParentDefinition { .. }
        | ResolutionReportError::ForeignEnclosingDefinition { .. }
        | ResolutionReportError::DefinitionParentCycle { .. }
        | ResolutionReportError::MissingResolution { .. }
        | ResolutionReportError::DuplicateCandidate { .. }
        | ResolutionReportError::UnsortedCandidates { .. }
        | ResolutionReportError::DuplicateGap { .. }
        | ResolutionReportError::UnsortedGaps { .. }
        | ResolutionReportError::MixedCandidateCertainty { .. }
        | ResolutionReportError::ResolvedCandidateCount { .. }
        | ResolutionReportError::ResolvedWithGaps { .. }
        | ResolutionReportError::EmptyResolution { .. }
        | ResolutionReportError::InvalidSourcePath { .. }
        | ResolutionReportError::ReversedSiteSpan { .. }
        | ResolutionReportError::EmptySiteSpan { .. } => return None,
    };
    Some(capacity(
        owner,
        collection,
        super::error::first_excess(limit),
        u64::from(limit),
    ))
}

/// One graph-build capacity refusal with the clamp's retained provenance.
///
/// Every other variant named, for the reason [`report_capacity`] names its own.
/// The graph builder states one ceiling variant today and names the collection
/// inside it; a second one added beside it must be placed here rather than
/// reported as the prose refusal a join failure states.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn graph_capacity(
    error: &GraphBuildError,
    admission: &super::graph_budget::GraphAdmission,
) -> Option<CodeIntelligenceError> {
    let collection = match error {
        GraphBuildError::CapacityExceeded { collection, .. } => *collection,
        GraphBuildError::RootTargetMismatch
        | GraphBuildError::SnapshotFingerprintMismatch
        | GraphBuildError::MissingUnitBinding { .. }
        | GraphBuildError::DanglingUnitBinding { .. }
        | GraphBuildError::SharedUnitBinding { .. }
        | GraphBuildError::RepeatedUnitContainer { .. }
        | GraphBuildError::MissingUnitDeclaration { .. }
        | GraphBuildError::RepeatedUnitDeclaration { .. }
        | GraphBuildError::SharedUnitRoot { .. }
        | GraphBuildError::MissingDependencyUnit { .. }
        | GraphBuildError::MissingSourceNode { .. }
        | GraphBuildError::RepeatedUnitSource { .. }
        | GraphBuildError::ReferenceRecordMismatch { .. }
        | GraphBuildError::MissingDefinitionNode { .. }
        | GraphBuildError::UnnamedDefinitionKind { .. }
        | GraphBuildError::UnnamedReferenceKind { .. }
        | GraphBuildError::MissingReferenceRecord { .. }
        | GraphBuildError::UnknownContainmentNode { .. }
        | GraphBuildError::MultiplyContained { .. }
        | GraphBuildError::UnparentedNode { .. }
        | GraphBuildError::RootHasParent { .. }
        | GraphBuildError::ContainmentCycle { .. } => return None,
    };
    let mapped = match collection {
        GraphCollection::Node => CapacityCollection::GraphNode,
        GraphCollection::Reference => CapacityCollection::GraphReference,
        GraphCollection::Edge => CapacityCollection::GraphEdge,
    };
    let provenance = admission.provenance(collection);
    Some(capacity(
        provenance.owner,
        mapped,
        provenance.observed,
        provenance.limit,
    ))
}

/// One graph-build refusal at the stage that asked for the graph.
///
/// Named here rather than once per language: the body reads a
/// `GraphBuildError` and a clamp, and neither of those is a language's own
/// type. Two copies were byte-for-byte identical, which is what the ledger's
/// acceptance of the `of_read` twins explicitly is not — those each name their
/// own language's variants, and this one names none.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn graph_failure(
    error: GraphBuildError,
    admission: &super::graph_budget::GraphAdmission,
) -> SliceFailure {
    SliceFailure::stated(IssueStage::Graph, graph_capacity(&error, admission), error)
}

/// One first-excess refusal owned by one language.
///
/// The owner is a parameter for the same reason it is one in
/// [`report_capacity`]: the body names no language type, and two copies of it
/// were two chances for a ceiling to be reported under the wrong owner.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn language_capacity(
    owner: CapacityOwner,
    collection: CapacityCollection,
    limit: u32,
) -> CodeIntelligenceError {
    capacity(
        owner,
        collection,
        super::error::first_excess(limit),
        u64::from(limit),
    )
}

/// The same refusal for a ceiling its owner already publishes as `u64`.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn language_capacity_u64(
    owner: CapacityOwner,
    collection: CapacityCollection,
    limit: u64,
) -> CodeIntelligenceError {
    capacity(owner, collection, super::error::first_excess(limit), limit)
}

/// Every resolved slice in project-key order, beneath the slice ceiling.
///
/// Dense identities are minted here because this is where the collection stops
/// growing: a position handed out before the last authority had been loaded
/// would name a different slice by the time the index sealed.
pub(crate) fn sealed(
    mut pending: Vec<PendingSlice>,
    limits: CodeIntelligenceLimits,
) -> Result<Box<[ProjectSlice]>, CodeIntelligenceError> {
    let retained = super::count::widened(pending.len());
    let ceiling = u64::from(limits.repository.max_slices);
    if retained > ceiling {
        return Err(capacity(
            CapacityOwner::Repository,
            CapacityCollection::Slice,
            retained,
            ceiling,
        ));
    }
    pending.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(pending
        .into_iter()
        .enumerate()
        .map(|(index, slice)| {
            ProjectSlice::sealed(
                ProjectId::at(super::count::narrowed(index)),
                slice.key,
                slice.coverage,
                slice.sources,
                slice.graph,
            )
        })
        .collect())
}
