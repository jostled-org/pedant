//! The ceilings one caller states before an analysis is built.

/// How much work one analysis of one graph may cost.
///
/// A graph describes a repository someone else supplied, so every superlinear
/// operation and every indexed allocation is admitted against a stated ceiling
/// first. There is no default: an interactive editor, a CI job, and a batch
/// run have different acceptable budgets, and a library that picked one would
/// make that policy implicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphAnalysisLimits {
    max_nodes: u32,
    max_selected_edges: u32,
    max_depth: u32,
    max_betweenness_work: u64,
}

impl GraphAnalysisLimits {
    /// Ceilings for the admitted node count, the admitted selected-edge count,
    /// the depth one query may walk, and the betweenness work bound.
    pub fn new(
        max_nodes: u32,
        max_selected_edges: u32,
        max_depth: u32,
        max_betweenness_work: u64,
    ) -> Self {
        Self {
            max_nodes,
            max_selected_edges,
            max_depth,
            max_betweenness_work,
        }
    }

    /// The node ceiling analysis construction refuses above.
    pub fn max_nodes(self) -> u32 {
        self.max_nodes
    }

    /// The selected-edge ceiling analysis construction refuses above.
    pub fn max_selected_edges(self) -> u32 {
        self.max_selected_edges
    }

    /// The depth ceiling a neighborhood or subgraph query refuses above.
    pub fn max_depth(self) -> u32 {
        self.max_depth
    }

    /// The betweenness work bound centrality refuses above.
    pub fn max_betweenness_work(self) -> u64 {
        self.max_betweenness_work
    }
}
