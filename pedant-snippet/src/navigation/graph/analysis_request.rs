//! Which derived question one analysis query asks of one project graph.
//!
//! The modes are closed and explicit. Each of them is a distinct answer shape
//! rather than a variation of one, so a request that named a family and let the
//! host choose would be a request whose answer type nobody could state.

use serde::{Deserialize, Serialize};

use crate::index::ProjectHandle;

use super::budget::AnalysisLimitRequest;
use super::selection::EdgeSelection;

/// Which derived answer one analysis query asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    /// How many selected edges each entity states at each of its ends.
    DegreeCentrality,
    /// How much shortest-path traffic each entity carries.
    BetweennessCentrality,
    /// The strongly connected components of the selected topology.
    Components,
    /// The acyclic view over those components.
    Condensation,
    /// Where the declared module tree and the selected topology disagree.
    ModuleDivergence,
}

impl AnalysisMode {
    /// Every mode, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 5] = [
        Self::DegreeCentrality,
        Self::BetweennessCentrality,
        Self::Components,
        Self::Condensation,
        Self::ModuleDivergence,
    ];

    /// The stable token this mode is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::DegreeCentrality => "degree_centrality",
            Self::BetweennessCentrality => "betweenness_centrality",
            Self::Components => "components",
            Self::Condensation => "condensation",
            Self::ModuleDivergence => "module_divergence",
        }
    }
}

/// One derived question about one project graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisQuery {
    /// The project graph to analyze. Required: an analysis is a statement
    /// about one topology, and two graphs have no shared one.
    pub project: ProjectHandle,
    /// Which edges to admit.
    pub edges: EdgeSelection,
    /// Which derived answer to state.
    pub mode: AnalysisMode,
    /// How far to lower the host's own analysis ceilings.
    #[serde(default)]
    pub limits: AnalysisLimitRequest,
}
