//! The three questions one index answers from the project graphs it built.
//!
//! Relations, routes, and derived analysis. All three read retained graphs and
//! delegate every walk, every metric, and every ceiling to `pedant-graph`: this
//! module states which graph, which selection, and which seed, then says what
//! each answer means in terms of the declarations the index retained.
//!
//! Graph identity never travels alone. Every node, component, and edge an
//! answer carries sits beside the project handle whose graph issued it, because
//! position seven exists in every graph this index holds and names a different
//! entity in each of them.

mod analysis;
mod analysis_request;
mod betweenness;
mod budget;
mod certainty;
mod component;
mod degree;
mod direction;
mod divergence;
mod edge_kind;
mod entity;
mod neighborhood;
mod path_record;
mod refusal;
mod relation_request;
mod relations;
mod route;
mod seed;
mod selection;

pub use analysis::AnalysisAnswer;
pub use analysis_request::{AnalysisMode, AnalysisQuery};
pub use betweenness::BetweennessRecord;
pub use budget::AnalysisLimitRequest;
pub use certainty::EdgeCertainty;
pub use component::{ComponentRecord, CondensationAnswer, CondensationEdgeRecord};
pub use degree::DegreeRecord;
pub use direction::RelationDirection;
pub use divergence::{BoundaryRecord, CohesionRecord, DivergenceAnswer, MisplacementRecord};
pub use edge_kind::EdgeKind;
pub use entity::{GraphEntity, NavigationEntity, StructureEntity};
pub use neighborhood::{RelationNeighbor, RelationNeighborhood};
pub use path_record::{PathAnswer, RoutedPath};
pub use relation_request::RelationQuery;
pub use route::PathQuery;
pub use selection::EdgeSelection;

pub(crate) use analysis::graph_analyzed;
pub(crate) use relations::relations_selected;
pub(crate) use route::path_selected;
