//! Repository code intelligence: one immutable index, and the navigation
//! questions it answers.
//!
//! [`CodeIntelligenceIndex::build`] admits every recognized source beneath one
//! root, and the immutable [`CodeIntelligenceState`] it publishes answers eight
//! questions: [`list_projects`](CodeIntelligenceState::list_projects),
//! [`search_symbols`](CodeIntelligenceState::search_symbols),
//! [`outline_file`](CodeIntelligenceState::outline_file),
//! [`read_structure`](CodeIntelligenceState::read_structure),
//! [`structure_at`](CodeIntelligenceState::structure_at), `query_relations`,
//! `find_path`, and `analyze_graph`. Each answers from retained records in one
//! [`NavigationResponse`], so an answer costs no read and no second parse, and
//! each refusal is one [`QueryFailure`] naming the state it refused from.
//!
//! The last three are named without a link because they are conditional: a
//! build that selects neither graph producer resolves no project and has no
//! graph to answer about, so it declares none of them. Linking them would make
//! this page's own documentation depend on a feature it also documents building
//! without.
//!
//! A server keeps that index current with [`LiveCodeIntelligenceIndex`], which
//! publishes one immutable state per normalized change batch and keeps the last
//! good index when a rebuild refuses. [`RootWatcher`] is the observer that feeds
//! it; a caller that learns about changes another way states them itself.
//!
//! The `pedant-snippet` binary serves these same eight operations over a CLI and
//! an MCP stdio transport. Both call the methods above and serialize what they
//! return, so a CLI answer and an MCP answer to one question are one set of
//! bytes.
//!
//! The location model, the structure vocabulary, and the byte-exact extraction
//! rules belong to `pedant-syntax`; [`enclosing_unit`] and the types around it
//! are re-exported so a consumer of one point lookup needs only this dependency.
//!
//! Every language is a feature, so part of the surface is conditional. The
//! published documentation labels each conditional item with the feature that
//! supplies it; the attribute is inert unless `docsrs` is set, which only the
//! docs.rs build does.
//!
//! # Examples
//!
//! Index one repository and ask it for every function whose name opens with
//! `parse`:
//!
//! ```no_run
//! use std::path::Path;
//!
//! use pedant_snippet::{
//!     CodeIntelligenceIndex, CodeIntelligenceLimits, MatchMode, PageRequest, SymbolQuery,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let state = CodeIntelligenceIndex::build(
//!     Path::new("."),
//!     &[],
//!     CodeIntelligenceLimits::default(),
//! )?;
//!
//! let query = SymbolQuery {
//!     text: "parse".into(),
//!     mode: MatchMode::Prefix,
//!     language: None,
//!     kind: None,
//!     owner_name: None,
//!     path_prefix: None,
//! };
//! let answer = state.search_symbols(&query, &PageRequest::default())?;
//!
//! for structure in answer.result() {
//!     println!("{}: {:?}", structure.path(), structure.name());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The example is `no_run` because it indexes whatever repository the working
//! directory holds, which a documentation test has no business doing. It is
//! compiled, so the shapes above are the shapes this crate publishes.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod index;
mod live;
mod navigation;

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub use index::StructureInstance;
#[cfg(feature = "test-support")]
pub use index::{
    AdmittedPathKind, LimitField, PagedQuery, PhaseEntry, QueryField, RevisionClaim,
    RevisionClaimInput, SourceStep, SourceTallies, SourceWork, WorkEvent, WorkPhase,
    bounded_reader_for_test, stated_ceilings,
};
pub use index::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, CodeIntelligenceIndex,
    CodeIntelligenceIndexer, CodeIntelligenceLimits, CodeIntelligenceState, CodeStructure,
    ErrorCode, ErrorReport, FatalReport, FileRecord, HealthStatus, IndexHealth, IndexIssue,
    IndexRevision, IssueCode, IssueScope, IssueStage, ProjectAuthority, ProjectHandle, ProjectId,
    ProjectKey, ProjectSlice, RepositoryLimits, StateRevision, StructureCoverage, StructureHandle,
    StructureId,
};
#[cfg(feature = "test-support")]
pub use live::requires_rescan;
pub use live::{
    ChangeKind, ChangeRole, EventBatch, LiveCodeIntelligenceIndex, LiveIndexError, LiveLedger,
    LiveTransaction, ObservedChange, PoisonedOwner, RootWatcher, SourceChange, TransactionOutcome,
};
/// The graph navigation surface, and the `pedant-graph` vocabulary its requests
/// and answers are stated in.
///
/// Re-exported for the reason the syntax vocabulary is: a consumer that holds a
/// `RelationNeighborhood` reads graph edges, graph node kinds, and graph
/// identities out of it, and a library that returned another crate's types
/// without publishing them would leave every caller to add a dependency this
/// one already has.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
pub use navigation::{
    AnalysisAnswer, AnalysisLimitRequest, AnalysisMode, AnalysisQuery, BetweennessRecord,
    BoundaryRecord, CohesionRecord, ComponentRecord, CondensationAnswer, CondensationEdgeRecord,
    DegreeRecord, DivergenceAnswer, EdgeCertainty, EdgeKind, EdgeSelection, GraphEntity,
    MisplacementRecord, NavigationEntity, PathAnswer, PathQuery, RelationDirection,
    RelationNeighbor, RelationNeighborhood, RelationQuery, RoutedPath, StructureEntity,
};
pub use navigation::{
    DEFAULT_PAGE_SIZE, FileOutline, MatchMode, NavigationResponse, PageCursor, PageRequest,
    ProjectRecord, QueryFailure, StructureDescriptor, StructureSource, SymbolQuery,
};
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
pub use pedant_graph::{
    CodeGraph, ContainmentEdge, DependencyEvidence, GraphAnalysis, GraphAnalysisError,
    GraphAnalysisLimits, GraphCacheLimits, GraphCacheStats, GraphCertainty, GraphComponentId,
    GraphDependencyKind, GraphDirection, GraphEdge, GraphEdgeId, GraphEdgeKind, GraphEdgeOrigin,
    GraphEdgeSelection, GraphLimits, GraphNode, GraphNodeId, GraphNodeKind, GraphNodeLocation,
    GraphReference, GraphReferenceId, GraphReferenceKind,
};
/// The Rust parser cache is the only one with a caller-released thread-local
/// source map, so `pedant-syntax` publishes this only with its Rust backend and
/// so does this crate.
#[cfg(feature = "lang-rust")]
#[cfg_attr(docsrs, doc(cfg(feature = "lang-rust")))]
pub use pedant_syntax::invalidate_parser_cache;
pub use pedant_syntax::{LineSpan, Location, SourceUnit, SourceUnitKind, enclosing_unit};
/// The structure vocabulary this crate's own signatures are stated in.
///
/// Re-exported for the reason the syntax and graph vocabularies are. A
/// [`SymbolQuery`] is written with a [`Language`] and a [`StructureKind`], and
/// a [`StructureDescriptor`] answers with both of those and a
/// [`StructureSpan`], so a caller that had to add a `pedant-types` dependency
/// to name a field of a type this crate publishes is exactly the case these
/// re-exports exist to prevent.
pub use pedant_types::{Language, StructureKind, StructureSpan};
