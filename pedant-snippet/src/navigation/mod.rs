//! The navigation questions one immutable index answers.
//!
//! Every operation here reads retained records and nothing else. None of them
//! opens a file, runs a parser, walks declarations, resolves a project, or
//! builds a graph — the index did all of that once, and a query that did any of
//! it again would be answering from a repository that may no longer be the one
//! the revision names.
//!
//! Each answer is one [`NavigationResponse`]: both revisions, the health of the
//! state it was answered from, the typed result, and — where the result pages —
//! the cursor that continues it. One envelope, because the CLI writes its JSON
//! and the MCP tool moves the same bytes, and two renderers would be two
//! answers to one question.

mod cursor;
mod describe;
mod failure;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
mod graph;
mod outline;
mod page;
mod page_request;
mod paged_query;
mod point;
mod project_list;
mod project_record;
mod record;
mod request;
mod response;
mod search;

pub use cursor::PageCursor;
pub use failure::QueryFailure;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub use graph::{
    AnalysisAnswer, AnalysisLimitRequest, AnalysisMode, AnalysisQuery, BetweennessRecord,
    BoundaryRecord, CohesionRecord, ComponentRecord, CondensationAnswer, CondensationEdgeRecord,
    DegreeRecord, DivergenceAnswer, EdgeCertainty, EdgeKind, EdgeSelection, GraphEntity,
    MisplacementRecord, NavigationEntity, PathAnswer, PathQuery, RelationDirection,
    RelationNeighbor, RelationNeighborhood, RelationQuery, RoutedPath, StructureEntity,
};
pub use page::DEFAULT_PAGE_SIZE;
pub use page_request::PageRequest;
pub use project_record::ProjectRecord;
pub use record::{FileOutline, StructureDescriptor, StructureSource};
pub use request::{MatchMode, SymbolQuery};
pub use response::NavigationResponse;

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(crate) use graph::{graph_analyzed, path_selected, relations_selected};
pub(crate) use outline::outlined;
pub(crate) use point::{structure_at_point, structure_by_handle};
pub(crate) use project_list::projects_listed;
pub(crate) use search::symbols_selected;
