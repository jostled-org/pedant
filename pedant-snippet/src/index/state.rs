//! The immutable index, the physical file records it holds, and the state a
//! caller is handed.
//!
//! Nothing here mutates after construction. That is what lets a live server
//! clone one `Arc` under a read lock, drop the lock, and answer without holding
//! anything: the value it is answering from cannot change underneath it, so the
//! answer stays consistent with the revision it names.

use std::path::Path;
use std::sync::Arc;

use pedant_types::Language;

use crate::navigation::{
    FileOutline, NavigationResponse, PageRequest, ProjectRecord, StructureDescriptor,
    StructureSource, SymbolQuery, outlined, projects_listed, structure_at_point,
    structure_by_handle, symbols_selected,
};

use super::error::CodeIntelligenceError;
use super::health::IndexHealth;
use super::issue::IndexIssue;
use super::limits::CodeIntelligenceLimits;
#[cfg(feature = "test-support")]
use super::observe::SourceWork;
use super::project::{ProjectHandle, ProjectSlice};
use super::revision::{IndexRevision, StateRevision};
use super::structure::{CodeStructure, StructureHandle};
use super::{ProjectAuthority, profile};

/// One admitted physical source, and where its structures sit in the index.
#[derive(Clone, Debug)]
pub struct FileRecord {
    path: Arc<str>,
    language: Language,
    digest: [u8; 32],
    text: Arc<str>,
    first_structure: u32,
    structure_count: u32,
}

impl FileRecord {
    /// Seal one admitted source into its revision.
    pub(crate) fn sealed(
        path: Arc<str>,
        language: Language,
        digest: [u8; 32],
        text: Arc<str>,
        first_structure: u32,
        structure_count: u32,
    ) -> Self {
        Self {
            path,
            language,
            digest,
            text,
            first_structure,
            structure_count,
        }
    }

    /// The normalized repository path this record is keyed by.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The language the source was recognized as.
    pub fn language(&self) -> Language {
        self.language
    }

    /// SHA-256 of the exact bytes that were read.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The exact UTF-8 text every structure span here slices.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// How many structures this source declares.
    pub fn structure_count(&self) -> u32 {
        self.structure_count
    }

    /// The positions this source's structures occupy in the index-wide list.
    pub(crate) fn structures(&self) -> std::ops::Range<usize> {
        let start = self.first_structure as usize;
        start..start.saturating_add(self.structure_count as usize)
    }
}

/// One immutable repository index.
#[derive(Debug)]
pub struct CodeIntelligenceIndex {
    revision: IndexRevision,
    limits: CodeIntelligenceLimits,
    files: Box<[FileRecord]>,
    structures: Box<[CodeStructure]>,
    projects: Box<[ProjectSlice]>,
    /// Every graph node this index joined to a structure, in key order. The
    /// reverse of the instances each structure carries, so a relation answer
    /// says what a node it reached is without scanning every structure.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    nodes: Box<[super::membership::NodeMembership]>,
    #[cfg(feature = "test-support")]
    work: Arc<SourceWork>,
}

impl CodeIntelligenceIndex {
    /// Index one repository beneath `root`, once.
    ///
    /// The explicit authorities are always selected and each suppresses an
    /// equal automatic candidate. A failure among them is fatal: a caller that
    /// named a project meant that project, and indexing the repository without
    /// it would answer a question nobody asked. Every other failure is
    /// degraded and recorded, because a repository with one unreadable file
    /// still has an answer for every other file.
    ///
    /// A caller that indexes the same repository again holds a
    /// [`CodeIntelligenceIndexer`](super::CodeIntelligenceIndexer) instead, so
    /// the graph work of the first revision is available to the second.
    ///
    /// # Errors
    ///
    /// Every fatal classification in the failure matrix: an unusable root, a
    /// path that escapes it, an explicit authority that does not load, and any
    /// repository-wide ceiling the admitted corpus passes.
    pub fn build(
        root: &Path,
        authorities: &[ProjectAuthority],
        limits: CodeIntelligenceLimits,
    ) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
        super::indexer::CodeIntelligenceIndexer::new(limits).index(root, authorities)
    }

    /// Seal one completed build.
    pub(super) fn sealed(
        revision: IndexRevision,
        limits: CodeIntelligenceLimits,
        files: Box<[FileRecord]>,
        joined: super::joined::Joined,
        projects: Box<[ProjectSlice]>,
        #[cfg(feature = "test-support")] work: Arc<SourceWork>,
    ) -> Self {
        Self {
            revision,
            limits,
            files,
            structures: joined.structures,
            projects,
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            nodes: joined.nodes,
            #[cfg(feature = "test-support")]
            work,
        }
    }

    /// The structure one project's graph node declares, if this index joined
    /// one to it.
    ///
    /// A node with no answer here is a file node, a container, or a
    /// declaration whose source this index retained no structure for. Every one
    /// of those stays a typed graph entity in an answer rather than vanishing
    /// from it.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn structure_of(
        &self,
        project: super::project::ProjectId,
        node: pedant_graph::GraphNodeId,
    ) -> Option<&CodeStructure> {
        let at = self
            .nodes
            .binary_search_by_key(&(project, node), |held| held.key())
            .ok()?;
        let structure = self.nodes.get(at)?.structure();
        self.structures.get(structure.position() as usize)
    }

    /// What building and answering from this index has cost in source work.
    #[cfg(feature = "test-support")]
    pub fn source_work(&self) -> &SourceWork {
        &self.work
    }

    /// This index's identity.
    pub fn revision(&self) -> IndexRevision {
        self.revision
    }

    /// The host ceilings this index was built under.
    pub fn limits(&self) -> &CodeIntelligenceLimits {
        &self.limits
    }

    /// Every language this build links a structure inventory for.
    pub fn enabled_languages(&self) -> &'static [Language] {
        profile::ENABLED_LANGUAGES
    }

    /// Every language this build links a project resolver and graph producer
    /// for.
    pub fn graph_coverage(&self) -> &'static [Language] {
        profile::GRAPH_COVERAGE
    }

    /// Every admitted physical source, in normalized path order.
    pub fn files(&self) -> &[FileRecord] {
        &self.files
    }

    /// The record one normalized repository path names.
    ///
    /// The path is normalized before it is looked up, so a request that is not
    /// a repository-relative spelling is refused rather than missed.
    pub fn file(&self, path: &str) -> Result<&FileRecord, CodeIntelligenceError> {
        let normalized = super::path::normalize(path)?;
        self.files
            .binary_search_by(|record| (*record.path).cmp(normalized))
            .ok()
            .and_then(|position| self.files.get(position))
            .ok_or_else(|| CodeIntelligenceError::UnknownFile {
                path: Box::from(normalized),
            })
    }

    /// Every physical structure, grouped by file and in source order.
    pub fn structures(&self) -> &[CodeStructure] {
        &self.structures
    }

    /// Every structure one admitted source declares, in source order.
    ///
    /// The range is the record's own, minted by the pass that sealed the
    /// structures it names, so a range this index cannot slice is a broken seal
    /// rather than a file that declares nothing. The two read identically here —
    /// an outline of no structures — and this surface states no assertion to
    /// tell them apart, because production source refuses through a typed error
    /// and an accessor returning a slice has none. The seal pass is what keeps
    /// the range sliceable; nothing downstream can.
    pub fn file_structures(&self, record: &FileRecord) -> &[CodeStructure] {
        let stated = record.structures();
        self.structures.get(stated).unwrap_or_default()
    }

    /// The structure one handle names, if the handle is this revision's.
    pub fn structure(
        &self,
        handle: StructureHandle,
    ) -> Result<&CodeStructure, CodeIntelligenceError> {
        if handle.revision() != self.revision {
            return Err(CodeIntelligenceError::StaleRevision);
        }
        self.structures
            .get(handle.id().position() as usize)
            .ok_or(CodeIntelligenceError::UnknownStructure)
    }

    /// Every resolved project slice, in project-key order.
    pub fn projects(&self) -> &[ProjectSlice] {
        &self.projects
    }

    /// The project one handle names, if the handle is this revision's.
    pub fn project(&self, handle: ProjectHandle) -> Result<&ProjectSlice, CodeIntelligenceError> {
        if handle.revision() != self.revision {
            return Err(CodeIntelligenceError::StaleRevision);
        }
        self.projects
            .get(handle.id().position() as usize)
            .ok_or(CodeIntelligenceError::UnknownProject)
    }
}

/// One immutable published state: an index and the issues that qualify it.
#[derive(Clone, Debug)]
pub struct CodeIntelligenceState {
    index: Arc<CodeIntelligenceIndex>,
    issues: Box<[IndexIssue]>,
    revision: StateRevision,
    health: IndexHealth,
}

impl CodeIntelligenceState {
    /// Publish one index over everything a build or a live update recorded.
    ///
    /// The whole sequence — sort, dedup, box, claim, publish — in one place. A
    /// build and a failed live update both publish, and written twice the two
    /// copies differed only in that one of them cloned the boxed issues to
    /// satisfy argument evaluation order.
    pub(crate) fn published_over(
        index: Arc<CodeIntelligenceIndex>,
        mut issues: Vec<IndexIssue>,
    ) -> Self {
        issues.sort();
        issues.dedup();
        let issues = issues.into_boxed_slice();
        let revision = super::seal::state_claim(&index.revision, &issues);
        let health = IndexHealth::of(&issues);
        Self {
            index,
            issues,
            revision,
            health,
        }
    }

    /// The index this state publishes.
    pub fn index(&self) -> &CodeIntelligenceIndex {
        &self.index
    }

    /// The same index, shared rather than borrowed.
    pub fn shared_index(&self) -> Arc<CodeIntelligenceIndex> {
        Arc::clone(&self.index)
    }

    /// Every issue this state carries, sorted by scope, stage, then code.
    pub fn issues(&self) -> &[IndexIssue] {
        &self.issues
    }

    /// This state's identity.
    pub fn revision(&self) -> StateRevision {
        self.revision
    }

    /// What every response says about this state.
    pub fn health(&self) -> IndexHealth {
        self.health
    }

    /// Answer one operation from this immutable state.
    fn answering<T>(&self, answer: impl FnOnce(&Self) -> T) -> T {
        #[cfg(feature = "test-support")]
        self.index
            .source_work()
            .entered(super::observe::WorkPhase::Query);
        answer(self)
    }

    /// Every project slice this index resolved, in project-key order.
    ///
    /// The records are already sorted: slices are sealed in key order, so the
    /// page is a range of that sealed collection rather than a sort taken per
    /// request.
    pub fn list_projects(
        &self,
        request: &PageRequest,
    ) -> Result<NavigationResponse<Box<[ProjectRecord]>>, CodeIntelligenceError> {
        self.answering(|state| projects_listed(state, request))
    }

    /// Every named structure this query selects, in one deterministic order.
    ///
    /// The order is normalized path, start byte, end byte, kind, then name. It
    /// is taken over the whole match set before the page is cut, because a page
    /// is a claim about a position in one order and a result ordered per page
    /// would repeat and skip rows as it went.
    pub fn search_symbols(
        &self,
        query: &SymbolQuery,
        request: &PageRequest,
    ) -> Result<NavigationResponse<Box<[StructureDescriptor]>>, CodeIntelligenceError> {
        self.answering(|state| symbols_selected(state, query, request))
    }

    /// Every structure one admitted source declares, in source order.
    ///
    /// Whole rather than paged: an outline is a forest, and a page of a forest
    /// is a set of subtrees whose owners a caller may not hold. The per-source
    /// structure ceiling is what bounds it.
    pub fn outline_file(
        &self,
        path: &str,
    ) -> Result<NavigationResponse<FileOutline>, CodeIntelligenceError> {
        self.answering(|state| outlined(state, path))
    }

    /// One revision-bound structure and the exact source it covers.
    pub fn read_structure(
        &self,
        handle: StructureHandle,
    ) -> Result<NavigationResponse<StructureSource>, CodeIntelligenceError> {
        self.answering(|state| structure_by_handle(state, handle))
    }

    /// The narrowest indexed structure containing one point, and its source.
    ///
    /// The line is one-based and the column is a one-based byte offset within
    /// that line. An omitted column is the line's first byte, which is the only
    /// position a caller who has a line and nothing else can mean.
    pub fn structure_at(
        &self,
        path: &str,
        line: u32,
        column: Option<u32>,
    ) -> Result<NavigationResponse<StructureSource>, CodeIntelligenceError> {
        self.answering(|state| structure_at_point(state, path, line, column))
    }

    /// One neighborhood per selected instance of one declaration.
    ///
    /// Paged over neighborhoods, because a neighborhood is what one seed
    /// instance states and every node, edge, containment row, and unresolved
    /// reference belongs to exactly one of them.
    ///
    /// # Errors
    ///
    /// An empty edge selection, a page size outside `1..=200`, a cursor this
    /// query did not mint, a handle from another revision, a declaration this
    /// build resolved no graph for, and every graph-analysis ceiling the walk
    /// would pass.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
    pub fn query_relations(
        &self,
        query: &crate::navigation::RelationQuery,
        request: &PageRequest,
    ) -> Result<
        NavigationResponse<Box<[crate::navigation::RelationNeighborhood]>>,
        CodeIntelligenceError,
    > {
        self.answering(|state| crate::navigation::relations_selected(state, query, request))
    }

    /// The shortest route between two declarations, inside one project graph.
    ///
    /// Never across two: separate graphs are separate compilations, and a route
    /// that stepped between them would state a relation no language states.
    /// Whole rather than paged, because a route is one answer.
    ///
    /// # Errors
    ///
    /// An empty edge selection, a handle from another revision, a pair of
    /// declarations that share no project graph, and every graph-analysis
    /// ceiling the search would pass.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
    pub fn find_path(
        &self,
        query: &crate::navigation::PathQuery,
    ) -> Result<NavigationResponse<crate::navigation::PathAnswer>, CodeIntelligenceError> {
        self.answering(|state| crate::navigation::path_selected(state, query))
    }

    /// One derived answer about one project graph.
    ///
    /// Every number is `pedant-graph`'s. A stated ceiling may only lower the
    /// host's own, and it is proved before the analysis is constructed.
    ///
    /// # Errors
    ///
    /// An empty edge selection, a stated ceiling above the host's, a project
    /// handle from another revision, and every graph-analysis ceiling the
    /// answer would pass.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
    pub fn analyze_graph(
        &self,
        query: &crate::navigation::AnalysisQuery,
    ) -> Result<NavigationResponse<crate::navigation::AnalysisAnswer>, CodeIntelligenceError> {
        self.answering(|state| crate::navigation::graph_analyzed(state, query))
    }
}

/// The state a failed live update publishes over the one it kept.
///
/// The index is the last good one, unchanged and still shared. Every issue it
/// already carried is re-stated as stale, because a scope that was already
/// degraded is now degraded *and* older than the tree; the refusal that kept it
/// joins them under the scope it names. The identity moves even though the
/// index did not, so every cursor minted against the old state stops continuing
/// and every response says what is stale.
///
/// A function rather than a method: this is a constructor over a state, not a
/// question a caller asks one.
pub(crate) fn stalled(
    held: &CodeIntelligenceState,
    error: &CodeIntelligenceError,
) -> CodeIntelligenceState {
    let mut issues: Vec<IndexIssue> = held.issues.iter().map(IndexIssue::now_stale).collect();
    issues.push(IndexIssue::stalled(error));
    CodeIntelligenceState::published_over(Arc::clone(&held.index), issues)
}
