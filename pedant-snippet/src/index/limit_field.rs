//! The closed registry of host ceilings, one row per field.
//!
//! One table rather than one match per question. A hand-written encoder hashes
//! the fields its author remembered and a hand-written perturbation table
//! perturbs the fields its author remembered; those two lists drifting apart is
//! exactly how a ceiling stops entering an identity without anything going red.
//! Here the revision claim, the identity proof, and every diagnostic read this
//! one list, so a field is in all three or in none.
//!
//! A row carries the token it is named by and the two accessors that reach its
//! value, because the owning limit types are other crates' and several of them
//! publish private fields behind a whole-value constructor. Reaching them
//! through a function pointer keeps the row a statement about one field even
//! when writing it rebuilds the value that holds it.

#[cfg(feature = "test-support")]
use super::count::narrowed;
use super::limits::CodeIntelligenceLimits;

/// One host ceiling, named and reachable.
#[derive(Clone, Copy, Debug)]
pub struct LimitField {
    token: &'static str,
    read: fn(&CodeIntelligenceLimits) -> u64,
    #[cfg(feature = "test-support")]
    write: fn(&mut CodeIntelligenceLimits, u64),
}

macro_rules! field {
    ($token:expr, $read:expr, $write:expr $(,)?) => {{
        #[cfg(feature = "test-support")]
        {
            LimitField::at($token, $read, $write)
        }
        #[cfg(not(feature = "test-support"))]
        {
            LimitField::at($token, $read)
        }
    }};
}

impl LimitField {
    /// One registry row.
    #[cfg(feature = "test-support")]
    const fn at(
        token: &'static str,
        read: fn(&CodeIntelligenceLimits) -> u64,
        write: fn(&mut CodeIntelligenceLimits, u64),
    ) -> Self {
        Self { token, read, write }
    }

    /// One production registry row without the test-only writer.
    #[cfg(not(feature = "test-support"))]
    const fn at(token: &'static str, read: fn(&CodeIntelligenceLimits) -> u64) -> Self {
        Self { token, read }
    }

    /// The stable token this ceiling is named by in a claim and a message.
    pub fn token(self) -> &'static str {
        self.token
    }

    /// The value this ceiling currently holds.
    pub fn read(self, limits: &CodeIntelligenceLimits) -> u64 {
        (self.read)(limits)
    }

    /// The same limits with this one ceiling set to `value`.
    ///
    /// A value wider than the field it addresses saturates rather than wrapping:
    /// a ceiling that silently became small is a ceiling that refuses a
    /// repository the caller asked to admit.
    ///
    /// Eleven rows rebuild the whole owning value through an all-`u32`
    /// constructor, passing this field's new value beside its siblings' current
    /// ones, and a transposition there type-checks. Nothing here can catch it:
    /// production source states no assertion, so the guard is the identity
    /// proof in `interfaces_support::index`, which writes each row and requires
    /// every other row to read exactly what it read before.
    #[cfg(feature = "test-support")]
    pub fn written(self, limits: &CodeIntelligenceLimits, value: u64) -> CodeIntelligenceLimits {
        let mut written = *limits;
        (self.write)(&mut written, value);
        written
    }

    /// Every ceiling this build's limits state, in claim order.
    ///
    /// Written out rather than derived, because this list is the claim: two
    /// builds that hashed the same fields in a different order would state
    /// different identities for one repository.
    pub const ALL: &'static [Self] = &[
        field!(
            "syntax.max_syntax_depth",
            |limits| u64::from(limits.syntax.max_syntax_depth()),
            |limits, value| {
                limits.syntax = pedant_syntax::StructureInventoryLimits::new(
                    clamped(value),
                    limits.syntax.max_structures_per_source(),
                )
                .unwrap_or(limits.syntax);
            },
        ),
        field!(
            "syntax.max_structures_per_source",
            |limits| u64::from(limits.syntax.max_structures_per_source()),
            |limits, value| {
                limits.syntax = pedant_syntax::StructureInventoryLimits::new(
                    limits.syntax.max_syntax_depth(),
                    clamped(value),
                )
                .unwrap_or(limits.syntax);
            },
        ),
        field!(
            "repository.max_directory_entries",
            |limits| u64::from(limits.repository.max_directory_entries),
            |limits, value| limits.repository.max_directory_entries = narrowed(value),
        ),
        field!(
            "repository.max_authorities",
            |limits| u64::from(limits.repository.max_authorities),
            |limits, value| limits.repository.max_authorities = narrowed(value),
        ),
        field!(
            "repository.max_files",
            |limits| u64::from(limits.repository.max_files),
            |limits, value| limits.repository.max_files = narrowed(value),
        ),
        field!(
            "repository.max_source_file_bytes",
            |limits| limits.repository.max_source_file_bytes,
            |limits, value| limits.repository.max_source_file_bytes = value,
        ),
        field!(
            "repository.max_total_source_bytes",
            |limits| limits.repository.max_total_source_bytes,
            |limits, value| limits.repository.max_total_source_bytes = value,
        ),
        field!(
            "repository.max_structures",
            |limits| u64::from(limits.repository.max_structures),
            |limits, value| limits.repository.max_structures = narrowed(value),
        ),
        field!(
            "repository.max_slices",
            |limits| u64::from(limits.repository.max_slices),
            |limits, value| limits.repository.max_slices = narrowed(value),
        ),
        field!(
            "repository.max_graph_nodes",
            |limits| u64::from(limits.repository.max_graph_nodes),
            |limits, value| limits.repository.max_graph_nodes = narrowed(value),
        ),
        field!(
            "repository.max_graph_references",
            |limits| u64::from(limits.repository.max_graph_references),
            |limits, value| limits.repository.max_graph_references = narrowed(value),
        ),
        field!(
            "repository.max_graph_edges",
            |limits| u64::from(limits.repository.max_graph_edges),
            |limits, value| limits.repository.max_graph_edges = narrowed(value),
        ),
        field!(
            "repository.max_page_items",
            |limits| u64::from(limits.repository.max_page_items),
            |limits, value| limits.repository.max_page_items = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_manifests",
            |limits| u64::from(limits.rust.max_manifests),
            |limits, value| limits.rust.max_manifests = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_member_scan_entries",
            |limits| u64::from(limits.rust.max_member_scan_entries),
            |limits, value| limits.rust.max_member_scan_entries = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_units",
            |limits| u64::from(limits.rust.max_units),
            |limits, value| limits.rust.max_units = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_source_files",
            |limits| u64::from(limits.rust.max_source_files),
            |limits, value| limits.rust.max_source_files = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_source_file_bytes",
            |limits| limits.rust.max_source_file_bytes,
            |limits, value| limits.rust.max_source_file_bytes = value,
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_total_source_bytes",
            |limits| limits.rust.max_total_source_bytes,
            |limits, value| limits.rust.max_total_source_bytes = value,
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_module_depth",
            |limits| u64::from(limits.rust.max_module_depth),
            |limits, value| limits.rust.max_module_depth = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_module_instances",
            |limits| u64::from(limits.rust.max_module_instances),
            |limits, value| limits.rust.max_module_instances = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_dependency_depth",
            |limits| u64::from(limits.rust.max_dependency_depth),
            |limits, value| limits.rust.max_dependency_depth = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_syntax_depth",
            |limits| u64::from(limits.rust.max_syntax_depth),
            |limits, value| limits.rust.max_syntax_depth = narrowed(value),
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "rust.max_candidates_per_reference",
            |limits| u64::from(limits.rust.max_candidates_per_reference),
            |limits, value| limits.rust.max_candidates_per_reference = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_module_manifests",
            |limits| u64::from(limits.go.max_module_manifests),
            |limits, value| limits.go.max_module_manifests = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_directory_entries",
            |limits| u64::from(limits.go.max_directory_entries),
            |limits, value| limits.go.max_directory_entries = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_units",
            |limits| u64::from(limits.go.max_units),
            |limits, value| limits.go.max_units = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_source_files",
            |limits| u64::from(limits.go.max_source_files),
            |limits, value| limits.go.max_source_files = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_source_file_bytes",
            |limits| limits.go.max_source_file_bytes,
            |limits, value| limits.go.max_source_file_bytes = value,
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_total_source_bytes",
            |limits| limits.go.max_total_source_bytes,
            |limits, value| limits.go.max_total_source_bytes = value,
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_dependency_depth",
            |limits| u64::from(limits.go.max_dependency_depth),
            |limits, value| limits.go.max_dependency_depth = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_syntax_depth",
            |limits| u64::from(limits.go.max_syntax_depth),
            |limits, value| limits.go.max_syntax_depth = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_facts_per_source",
            |limits| u64::from(limits.go.max_facts_per_source),
            |limits, value| limits.go.max_facts_per_source = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_candidates_per_reference",
            |limits| u64::from(limits.go.max_candidates_per_reference),
            |limits, value| limits.go.max_candidates_per_reference = narrowed(value),
        ),
        #[cfg(feature = "graph-go")]
        field!(
            "go.max_interface_comparisons",
            |limits| u64::from(limits.go.max_interface_comparisons),
            |limits, value| limits.go.max_interface_comparisons = narrowed(value),
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_build.max_nodes",
            |limits| u64::from(limits.graph_build.max_nodes()),
            |limits, value| {
                limits.graph_build = pedant_graph::GraphLimits::new(
                    narrowed(value),
                    limits.graph_build.max_references(),
                    limits.graph_build.max_edges(),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_build.max_references",
            |limits| u64::from(limits.graph_build.max_references()),
            |limits, value| {
                limits.graph_build = pedant_graph::GraphLimits::new(
                    limits.graph_build.max_nodes(),
                    narrowed(value),
                    limits.graph_build.max_edges(),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_build.max_edges",
            |limits| u64::from(limits.graph_build.max_edges()),
            |limits, value| {
                limits.graph_build = pedant_graph::GraphLimits::new(
                    limits.graph_build.max_nodes(),
                    limits.graph_build.max_references(),
                    narrowed(value),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_analysis.max_nodes",
            |limits| u64::from(limits.graph_analysis.max_nodes()),
            |limits, value| {
                limits.graph_analysis = pedant_graph::GraphAnalysisLimits::new(
                    narrowed(value),
                    limits.graph_analysis.max_selected_edges(),
                    limits.graph_analysis.max_depth(),
                    limits.graph_analysis.max_betweenness_work(),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_analysis.max_selected_edges",
            |limits| u64::from(limits.graph_analysis.max_selected_edges()),
            |limits, value| {
                limits.graph_analysis = pedant_graph::GraphAnalysisLimits::new(
                    limits.graph_analysis.max_nodes(),
                    narrowed(value),
                    limits.graph_analysis.max_depth(),
                    limits.graph_analysis.max_betweenness_work(),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_analysis.max_depth",
            |limits| u64::from(limits.graph_analysis.max_depth()),
            |limits, value| {
                limits.graph_analysis = pedant_graph::GraphAnalysisLimits::new(
                    limits.graph_analysis.max_nodes(),
                    limits.graph_analysis.max_selected_edges(),
                    narrowed(value),
                    limits.graph_analysis.max_betweenness_work(),
                );
            },
        ),
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        field!(
            "graph_analysis.max_betweenness_work",
            |limits| limits.graph_analysis.max_betweenness_work(),
            |limits, value| {
                limits.graph_analysis = pedant_graph::GraphAnalysisLimits::new(
                    limits.graph_analysis.max_nodes(),
                    limits.graph_analysis.max_selected_edges(),
                    limits.graph_analysis.max_depth(),
                    value,
                );
            },
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "graph_cache.max_source_projections",
            |limits| u64::from(limits.graph_cache.max_source_projections()),
            |limits, value| {
                limits.graph_cache = pedant_graph::GraphCacheLimits::new(
                    narrowed(value),
                    limits.graph_cache.max_exact_graphs(),
                    limits.graph_cache.max_selected_indexes_per_graph(),
                    limits.graph_cache.max_derived_products_per_graph(),
                );
            },
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "graph_cache.max_exact_graphs",
            |limits| u64::from(limits.graph_cache.max_exact_graphs()),
            |limits, value| {
                limits.graph_cache = pedant_graph::GraphCacheLimits::new(
                    limits.graph_cache.max_source_projections(),
                    narrowed(value),
                    limits.graph_cache.max_selected_indexes_per_graph(),
                    limits.graph_cache.max_derived_products_per_graph(),
                );
            },
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "graph_cache.max_selected_indexes_per_graph",
            |limits| u64::from(limits.graph_cache.max_selected_indexes_per_graph()),
            |limits, value| {
                limits.graph_cache = pedant_graph::GraphCacheLimits::new(
                    limits.graph_cache.max_source_projections(),
                    limits.graph_cache.max_exact_graphs(),
                    narrowed(value),
                    limits.graph_cache.max_derived_products_per_graph(),
                );
            },
        ),
        #[cfg(feature = "graph-rust")]
        field!(
            "graph_cache.max_derived_products_per_graph",
            |limits| u64::from(limits.graph_cache.max_derived_products_per_graph()),
            |limits, value| {
                limits.graph_cache = pedant_graph::GraphCacheLimits::new(
                    limits.graph_cache.max_source_projections(),
                    limits.graph_cache.max_exact_graphs(),
                    limits.graph_cache.max_selected_indexes_per_graph(),
                    narrowed(value),
                );
            },
        ),
    ];
}

/// One wide value, for a field whose owner admits no zero.
///
/// [`StructureInventoryLimits`](pedant_syntax::StructureInventoryLimits) refuses
/// a zero ceiling, so a row that only narrowed downwards had one input — zero —
/// that wrote nothing at all and returned the limits it was handed. Clamping up
/// as well as down makes the write total, which is what every other row in the
/// registry already is.
#[cfg(feature = "test-support")]
fn clamped(value: u64) -> u32 {
    narrowed(value).max(1)
}
