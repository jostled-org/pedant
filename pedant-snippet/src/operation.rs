//! The eight questions, stated once for both transports.
//!
//! The CLI and the MCP server are two ways of spelling one request. They meet
//! here: each builds an [`Operation`], hands it the state to answer from, and
//! serializes what comes back. Neither renders anything of its own, which is
//! what makes a CLI answer and an MCP answer to the same question one set of
//! bytes rather than two that happen to agree.
//!
//! Every query rule a question carries is assembled here too, by one
//! constructor per rule. A command line and a tool call arrive as different
//! shapes and mean the same thing, so the rules that turn either shape into a
//! query — which revision a selected project is bound to, which edges a walk
//! admits, what an unstated page size means — are stated once and neither
//! transport is in a position to state them differently.
//!
//! A query with no rule to state is not constructed here. Each transport writes
//! its struct literal with named fields, which is the one shape in which two
//! same-typed neighbouring fields cannot be handed over the wrong way round.
//!
//! [`Answered`] is typed rather than pre-serialized because the CLI also
//! projects it as text. One value, two renderings, and the JSON one is the same
//! call on both transports.

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, FileOutline, NavigationResponse, PageCursor,
    PageRequest, ProjectRecord, StructureDescriptor, StructureHandle, StructureSource, SymbolQuery,
};

/// One question a caller asks of one published state.
#[derive(Debug)]
pub(crate) enum Operation {
    /// Every project slice this index resolved.
    ListProjects(PageRequest),
    /// Every named structure one query selects.
    SearchSymbols(SymbolQuery, PageRequest),
    /// One file's complete structure forest.
    OutlineFile(Box<str>),
    /// One revision-bound structure and its exact source.
    ReadStructure(StructureHandle),
    /// The narrowest structure containing one point, and its source.
    StructureAt {
        /// The normalized repository path to look in.
        path: Box<str>,
        /// The one-based line.
        line: u32,
        /// The one-based UTF-8 byte offset within that line.
        column: Option<u32>,
    },
    /// One neighborhood per selected instance of one declaration.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    QueryRelations(pedant_snippet::RelationQuery, PageRequest),
    /// The shortest route between two declarations, inside one project graph.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    FindPath(pedant_snippet::PathQuery),
    /// One derived answer about one project graph.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    AnalyzeGraph(pedant_snippet::AnalysisQuery),
}

/// One answer, still typed.
///
/// `read` and `at` share [`Answered::Source`] because they return the same
/// thing: the narrowest structure a caller named, one by handle and one by
/// point, together with the exact bytes its span covers.
#[derive(Debug)]
pub(crate) enum Answered {
    /// Every project slice, paged.
    Projects(NavigationResponse<Box<[ProjectRecord]>>),
    /// Every selected structure, paged.
    Symbols(NavigationResponse<Box<[StructureDescriptor]>>),
    /// One file's whole forest.
    Outline(NavigationResponse<FileOutline>),
    /// One structure and its source.
    Source(NavigationResponse<StructureSource>),
    /// Every selected neighborhood, paged.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Relations(NavigationResponse<Box<[pedant_snippet::RelationNeighborhood]>>),
    /// One selected route, whole.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Path(NavigationResponse<pedant_snippet::PathAnswer>),
    /// One derived answer, whole.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Analysis(NavigationResponse<pedant_snippet::AnalysisAnswer>),
}

/// Which page of a paged answer one question asks for.
///
/// One constructor, because an unstated size and an unstated cursor mean the
/// same two things on both transports — the host default and the first page —
/// and a transport that filled either in itself would page differently from the
/// other under one question's name.
pub(crate) fn page(size: Option<u32>, cursor: Option<PageCursor>) -> PageRequest {
    PageRequest { size, cursor }
}

/// Which edges one graph question admits.
///
/// Shared by both transports because both receive the two lists as tokens and
/// neither may normalize them: a selection widened on one transport and not the
/// other would answer two different questions under one name.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn selection(
    kinds: &[pedant_snippet::EdgeKind],
    certainties: &[pedant_snippet::EdgeCertainty],
) -> pedant_snippet::EdgeSelection {
    pedant_snippet::EdgeSelection {
        kinds: kinds.into(),
        certainties: certainties.into(),
    }
}

/// The project a graph question selects, under the revision that issued its
/// seed.
///
/// The revision is taken from the seed rather than from the caller: a graph
/// selected under a different one names a slice this index never issued. Both
/// transports receive the project as a bare position, so this is the one place
/// that rule is spelled and neither of them can spell it differently.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn graph_project(
    seed: pedant_snippet::IndexRevision,
    project_id: Option<u32>,
) -> Option<pedant_snippet::ProjectHandle> {
    project_id.map(|position| pedant_snippet::ProjectHandle::new(seed, position))
}

/// One declaration's graph neighborhood.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn relation_query(
    structure: StructureHandle,
    project_id: Option<u32>,
    direction: pedant_snippet::RelationDirection,
    kinds: &[pedant_snippet::EdgeKind],
    certainties: &[pedant_snippet::EdgeCertainty],
    max_depth: u32,
) -> pedant_snippet::RelationQuery {
    pedant_snippet::RelationQuery {
        structure,
        project: graph_project(structure.revision(), project_id),
        direction,
        edges: selection(kinds, certainties),
        max_depth,
    }
}

/// The shortest route between two declarations.
///
/// The project is bound to the starting endpoint's revision. A route whose two
/// ends were issued by different indexes is refused when it is answered, so
/// there is no second revision here to choose between.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn path_query(
    from: StructureHandle,
    to: StructureHandle,
    project_id: Option<u32>,
    kinds: &[pedant_snippet::EdgeKind],
    certainties: &[pedant_snippet::EdgeCertainty],
) -> pedant_snippet::PathQuery {
    pedant_snippet::PathQuery {
        from,
        to,
        project: graph_project(from.revision(), project_id),
        edges: selection(kinds, certainties),
    }
}

/// One derived answer about one project graph.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) fn analysis_query(
    project: pedant_snippet::ProjectHandle,
    mode: pedant_snippet::AnalysisMode,
    kinds: &[pedant_snippet::EdgeKind],
    certainties: &[pedant_snippet::EdgeCertainty],
    limits: pedant_snippet::AnalysisLimitRequest,
) -> pedant_snippet::AnalysisQuery {
    pedant_snippet::AnalysisQuery {
        project,
        edges: selection(kinds, certainties),
        mode,
        limits,
    }
}

impl Operation {
    /// Answer this question from `state`.
    ///
    /// # Errors
    ///
    /// Every typed refusal the library operation states, unchanged.
    pub(crate) fn answered(
        &self,
        state: &CodeIntelligenceState,
    ) -> Result<Answered, CodeIntelligenceError> {
        match self {
            Self::ListProjects(page) => state.list_projects(page).map(Answered::Projects),
            Self::SearchSymbols(query, page) => {
                state.search_symbols(query, page).map(Answered::Symbols)
            }
            Self::OutlineFile(path) => state.outline_file(path).map(Answered::Outline),
            Self::ReadStructure(handle) => state.read_structure(*handle).map(Answered::Source),
            Self::StructureAt { path, line, column } => state
                .structure_at(path, *line, *column)
                .map(Answered::Source),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::QueryRelations(query, page) => {
                state.query_relations(query, page).map(Answered::Relations)
            }
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::FindPath(query) => state.find_path(query).map(Answered::Path),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::AnalyzeGraph(query) => state.analyze_graph(query).map(Answered::Analysis),
        }
    }
}

impl Answered {
    /// The shared response envelope, as both transports send it.
    ///
    /// # Errors
    ///
    /// The serializer's own error, which no answer this crate builds produces:
    /// every field is a string, a number, a list, or a map with string keys.
    pub(crate) fn json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Projects(response) => serde_json::to_string(response),
            Self::Symbols(response) => serde_json::to_string(response),
            Self::Outline(response) => serde_json::to_string(response),
            Self::Source(response) => serde_json::to_string(response),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Relations(response) => serde_json::to_string(response),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Path(response) => serde_json::to_string(response),
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Analysis(response) => serde_json::to_string(response),
        }
    }
}
