//! Which `pedant-graph` entry point each graph answer delegates to.
//!
//! Load-Bearing Constraint 2: graph algorithms are a published contract of
//! `pedant-graph`, and this crate projects them. A module that stopped calling
//! one of these entry points would be one that started walking the graph
//! itself, and its answers would be a second implementation of a published
//! algorithm — right today and drifting from tomorrow.

/// One graph answer, and the `pedant-graph` entry point it delegates to.
pub(crate) struct GraphDelegation {
    /// The module that answers, repository-relative.
    pub(crate) module: &'static str,
    /// Every `pedant-graph` call it must make.
    pub(crate) entries: &'static [&'static str],
}

/// One row per answering module, each naming every entry point that module must
/// reach.
pub(crate) const GRAPH_DELEGATIONS: &[GraphDelegation] = &[
    GraphDelegation {
        module: "pedant-snippet/src/navigation/graph/relations.rs",
        entries: &[".neighbors("],
    },
    GraphDelegation {
        module: "pedant-snippet/src/navigation/graph/route.rs",
        entries: &[".path("],
    },
    GraphDelegation {
        module: "pedant-snippet/src/navigation/graph/analysis.rs",
        entries: &[
            ".strongly_connected_components(",
            ".condensation(",
            ".divergence(",
        ],
    },
];
