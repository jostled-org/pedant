//! How many admitted values one cache may retain, by category.

/// The retention ceilings one cache is bounded by.
///
/// There is no default. An editor, a continuous-integration process, and a
/// batch consumer have different retention budgets, and a library that chose
/// one implicitly would spend a host's memory on its behalf. Zero disables
/// retention for a category without disabling the computation behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphCacheLimits {
    max_source_projections: u32,
    max_exact_graphs: u32,
    max_selected_indexes_per_graph: u32,
    max_derived_products_per_graph: u32,
}

impl GraphCacheLimits {
    /// Ceilings for the four retention categories.
    pub fn new(
        max_source_projections: u32,
        max_exact_graphs: u32,
        max_selected_indexes_per_graph: u32,
        max_derived_products_per_graph: u32,
    ) -> Self {
        Self {
            max_source_projections,
            max_exact_graphs,
            max_selected_indexes_per_graph,
            max_derived_products_per_graph,
        }
    }

    /// How many source-unit projections may be retained.
    pub fn max_source_projections(self) -> u32 {
        self.max_source_projections
    }

    /// How many exact graphs may be retained.
    pub fn max_exact_graphs(self) -> u32 {
        self.max_exact_graphs
    }

    /// How many edge-selection index sets may be retained per cached graph.
    pub fn max_selected_indexes_per_graph(self) -> u32 {
        self.max_selected_indexes_per_graph
    }

    /// How many derived products may be retained per cached graph.
    pub fn max_derived_products_per_graph(self) -> u32 {
        self.max_derived_products_per_graph
    }
}
