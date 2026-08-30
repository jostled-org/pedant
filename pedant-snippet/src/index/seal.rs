//! Sealing one completed build into an immutable index and a published state.
//!
//! This is where dense identities are minted, and it is deliberately the only
//! place: an identity is a position in a collection that no longer grows, so it
//! can only be handed out after the growing has stopped. It is also where both
//! revision claims are written, in the one order the claim registry states.

use std::sync::Arc;

use super::claim::{AdmittedPathKind, RevisionClaim, RevisionClaimInput};
use super::count::narrowed;
use super::issue::IndexIssue;
use super::joined::{self, StatedStructures};
use super::limit_field::LimitField;
use super::limits::CodeIntelligenceLimits;
use super::profile;
use super::project::ProjectSlice;
use super::revision::IndexRevision;
use super::state::{CodeIntelligenceIndex, CodeIntelligenceState, FileRecord};
use super::store::RepositorySourceStore;
use super::structure::{CodeStructure, StructureId};

/// One selected authority file and the digest of exactly its bytes.
pub(crate) struct AdmittedAuthority {
    /// The normalized repository path of the manifest.
    pub(crate) path: Arc<str>,
    /// SHA-256 of exactly the bytes that were read.
    pub(crate) digest: [u8; 32],
}

/// Seal everything one build admitted.
///
/// Infallible, and stated as such. Every ceiling this state rests on was proved
/// before the call — the slice ceiling in `slice::sealed`, the structure ceiling
/// in `RepositorySourceStore::retain` — so a `Result` here would name a refusal
/// no caller can be handed and no test can produce.
pub(crate) fn seal(
    limits: CodeIntelligenceLimits,
    store: &RepositorySourceStore,
    authorities: &[AdmittedAuthority],
    projects: Box<[ProjectSlice]>,
    issues: Vec<IndexIssue>,
) -> CodeIntelligenceState {
    // Entered before the mapping runs, not after it: a stage marker records the
    // trace position it began at, so one entered afterwards names a stage that
    // covers none of the work it is named for.
    #[cfg(feature = "test-support")]
    store
        .work()
        .entered(super::observe::WorkPhase::PhysicalMapping);
    let (files, stated) = physical(store);
    let joined = joined::of(&files, stated, &projects);
    let revision = index_claim(&limits, &files, authorities, &projects);
    let index = Arc::new(CodeIntelligenceIndex::sealed(
        revision,
        limits,
        files,
        joined,
        projects,
        #[cfg(feature = "test-support")]
        Arc::clone(store.work()),
    ));
    CodeIntelligenceState::published_over(index, issues)
}

/// Every admitted source and the structures it declares, in one pass.
///
/// The structure list is grouped by file and in source order inside each group,
/// so a file record needs only the position it starts at and how many it holds.
/// An owner is a position in the same source's own list, so it is rebased onto
/// the index-wide list by the same offset.
///
/// The definition sites come out of the same pass. They must stay aligned with
/// the structures index for index, and a second walk of the same store built
/// them from a second traversal that nothing held to the first one's length —
/// so a mismatch dropped instances at the `zip` that joins them, in silence.
/// Every collection is reserved against a count the store already holds. Grown
/// from empty, each doubled its way to as many as 65,536 files or 1,048,576
/// structures and the boxing at the end then reallocated and copied the whole
/// thing again.
fn physical(store: &RepositorySourceStore) -> (Box<[FileRecord]>, StatedStructures) {
    let retained = store.structure_count();
    let mut files = Vec::with_capacity(store.file_count());
    let mut structures: Vec<CodeStructure> = Vec::with_capacity(retained);
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    let mut definitions: Vec<Option<pedant_types::StructureSpan>> = Vec::with_capacity(retained);
    for (path, source) in store.records() {
        let first = narrowed(structures.len());
        for record in source.structures() {
            let id = StructureId::at(narrowed(structures.len()));
            structures.push(CodeStructure::sealed(
                id,
                source.language(),
                record.kind(),
                record.name().map(Arc::from),
                record
                    .owner()
                    .map(|owner| StructureId::at(first.saturating_add(owner))),
                Arc::clone(path),
                record.span(),
            ));
        }
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        definitions.extend((0..source.structures().len()).map(|at| source.definition_span(at)));
        files.push(FileRecord::sealed(
            Arc::clone(path),
            source.language(),
            *source.digest(),
            Arc::clone(source.text()),
            first,
            narrowed(source.structures().len()),
        ));
    }
    let stated = StatedStructures {
        structures: structures.into_boxed_slice(),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        definitions: definitions.into_boxed_slice(),
    };
    (files.into_boxed_slice(), stated)
}

/// The claim over what this index holds.
fn index_claim(
    limits: &CodeIntelligenceLimits,
    files: &[FileRecord],
    authorities: &[AdmittedAuthority],
    projects: &[ProjectSlice],
) -> IndexRevision {
    let mut claim = RevisionClaim::new();
    for language in profile::ENABLED_LANGUAGES {
        claim.write(RevisionClaimInput::EnabledLanguage(*language));
    }
    for language in profile::GRAPH_COVERAGE {
        claim.write(RevisionClaimInput::GraphCoverage(*language));
    }
    for field in LimitField::ALL {
        claim.write(RevisionClaimInput::Limit {
            field: *field,
            value: field.read(limits),
        });
    }
    for file in files {
        claim.write(RevisionClaimInput::AdmittedPath {
            kind: AdmittedPathKind::Source,
            path: file.path(),
        });
        claim.write(RevisionClaimInput::SourceLanguage(file.language()));
        claim.write(RevisionClaimInput::Digest(file.digest()));
    }
    for authority in authorities {
        claim.write(RevisionClaimInput::AdmittedPath {
            kind: AdmittedPathKind::Authority,
            path: &authority.path,
        });
        claim.write(RevisionClaimInput::Digest(&authority.digest));
    }
    for project in projects {
        claim.write(RevisionClaimInput::ProjectLanguage(
            project.key().language(),
        ));
        claim.write(RevisionClaimInput::ProjectAuthority(
            project.key().authority(),
        ));
        claim.write(RevisionClaimInput::ProjectUnit(project.key().unit()));
    }
    claim.seal_index()
}

/// The claim over what a caller is told.
///
/// Reachable beyond this build because a live update that keeps its last good
/// index still publishes a new state over new issues, and a second route to
/// that digest would be a second answer to "which state is this".
pub(super) fn state_claim(
    revision: &IndexRevision,
    issues: &[IndexIssue],
) -> super::revision::StateRevision {
    let mut claim = RevisionClaim::new();
    claim.write(RevisionClaimInput::IndexIdentity(revision));
    for issue in issues {
        claim.write(RevisionClaimInput::IssueScope(issue.scope()));
        claim.write(RevisionClaimInput::IssueStage(issue.stage()));
        claim.write(RevisionClaimInput::IssueCode(issue.code()));
        claim.write(RevisionClaimInput::IssueMessage(issue.message()));
        claim.write(RevisionClaimInput::IssueStale(issue.stale()));
    }
    claim.seal_state()
}
