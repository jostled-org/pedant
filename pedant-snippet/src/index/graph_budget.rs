//! The repository's remaining allowance for graph records.
//!
//! Graph nodes, references, and edges are retained records like any other, so a
//! repository ceiling on them must not be bypassable by splitting one
//! collection across projects. The build clamps the graph crate's own ceilings
//! to what is left before each construction, which is what makes the refusal
//! happen inside the builder — before the first excess record exists — rather
//! than after a whole graph has been assembled and then measured.

use pedant_graph::{CodeGraph, GraphLimits};

use super::count::{narrowed, widened};
use super::error::{CapacityOwner, first_excess};
use super::limits::RepositoryLimits;

/// One graph construction's effective ceilings and who supplied each one.
#[derive(Debug)]
pub(crate) struct GraphAdmission {
    limits: GraphLimits,
    nodes: CapacityProvenance,
    references: CapacityProvenance,
    edges: CapacityProvenance,
}

/// What one effective graph ceiling must report at the public boundary.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CapacityProvenance {
    pub(crate) owner: CapacityOwner,
    pub(crate) observed: u64,
    pub(crate) limit: u64,
}

impl GraphAdmission {
    /// The exact limits passed to the graph builder.
    pub(crate) fn limits(&self) -> GraphLimits {
        self.limits
    }

    /// The owner whose effective ceiling one graph collection crossed.
    pub(crate) fn provenance(
        &self,
        collection: pedant_graph::GraphCollection,
    ) -> CapacityProvenance {
        match collection {
            pedant_graph::GraphCollection::Node => self.nodes,
            pedant_graph::GraphCollection::Reference => self.references,
            pedant_graph::GraphCollection::Edge => self.edges,
        }
    }
}

/// What the repository will still admit into graphs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphBudget {
    nodes: u64,
    references: u64,
    edges: u64,
    /// The repository's own configured ceilings, at their declared width. The
    /// first count each one refuses is derived from the narrow value, so the
    /// one owner of that derivation answers for a repository ceiling and a
    /// graph-build ceiling alike.
    node_limit: u32,
    reference_limit: u32,
    edge_limit: u32,
}

impl GraphBudget {
    /// The whole repository allowance, unspent.
    pub(crate) fn new(limits: RepositoryLimits) -> Self {
        Self {
            nodes: u64::from(limits.max_graph_nodes),
            references: u64::from(limits.max_graph_references),
            edges: u64::from(limits.max_graph_edges),
            node_limit: limits.max_graph_nodes,
            reference_limit: limits.max_graph_references,
            edge_limit: limits.max_graph_edges,
        }
    }

    /// The graph ceilings one construction may run under.
    ///
    /// The repository owns an equal ceiling: it is the retained-record budget
    /// that forced clamping, while graph-build owns only a strictly lower
    /// configured ceiling. This tie rule makes provenance stable when both
    /// owners happen to state the same number.
    pub(crate) fn clamped(self, configured: GraphLimits) -> GraphAdmission {
        let nodes = admitted(self.nodes, self.node_limit, configured.max_nodes());
        let references = admitted(
            self.references,
            self.reference_limit,
            configured.max_references(),
        );
        let edges = admitted(self.edges, self.edge_limit, configured.max_edges());
        GraphAdmission {
            limits: GraphLimits::new(nodes.ceiling, references.ceiling, edges.ceiling),
            nodes: nodes.provenance,
            references: references.provenance,
            edges: edges.provenance,
        }
    }

    /// The allowance left after one graph retained what it built.
    ///
    /// The three configured ceilings ride along unchanged: they are what the
    /// repository was configured with, not what it has left, so spending
    /// restates none of them.
    pub(crate) fn spent(self, graph: &CodeGraph) -> Self {
        Self {
            nodes: self.nodes.saturating_sub(widened(graph.nodes().len())),
            references: self
                .references
                .saturating_sub(widened(graph.references().len())),
            edges: self.edges.saturating_sub(widened(graph.edges().len())),
            ..self
        }
    }
}

/// One effective graph ceiling and the owner that supplied it.
#[derive(Clone, Copy, Debug)]
struct AdmittedCeiling {
    /// The exact ceiling the graph builder is handed.
    ceiling: u32,
    /// Who supplied it, and what a refusal beneath it must report.
    provenance: CapacityProvenance,
}

/// The ceiling one graph collection runs under, and whose it is.
///
/// `remaining` is what the repository will still admit into graphs, `stated` is
/// the repository's own configured ceiling at its declared width, and
/// `configured` is what the graph builder was asked for. The two owners are
/// named rather than read out of one pair positionally, because they are the
/// difference the provenance reports.
fn admitted(remaining: u64, stated: u32, configured: u32) -> AdmittedCeiling {
    match remaining <= u64::from(configured) {
        true => AdmittedCeiling {
            ceiling: narrowed(remaining),
            provenance: CapacityProvenance {
                owner: CapacityOwner::Repository,
                observed: first_excess(stated),
                limit: u64::from(stated),
            },
        },
        false => AdmittedCeiling {
            ceiling: configured,
            provenance: CapacityProvenance {
                owner: CapacityOwner::GraphBuild,
                observed: first_excess(configured),
                limit: u64::from(configured),
            },
        },
    }
}
