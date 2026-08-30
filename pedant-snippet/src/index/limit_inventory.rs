//! The same ceilings the registry names, listed by the compiler instead.
//!
//! [`LimitField::ALL`](super::limit_field::LimitField) is the claim: one row per
//! host ceiling, in the order every revision hashes them. What that list cannot
//! do is notice a ceiling nobody wrote a row for. A field added to
//! [`RepositoryLimits`] without one leaves the registry the same length, leaves
//! every identity unchanged, and leaves two installs running under different
//! numbers while agreeing on one revision — which is the exact disagreement the
//! claim exists to prevent.
//!
//! So this module states the same set a second time, in the one form a compiler
//! checks. A plain-field limit type is destructured by a pattern that names
//! every field, so a new field stops the pattern compiling. A limit type with
//! private fields behind a checked constructor is rebuilt through that
//! constructor with every accessor this build reads, so a new field changes the
//! arity and stops the call compiling. Either way the author is stopped here,
//! and the identity proof then holds the registry to this list.
//!
//! Each row's token comes from the field's own name, so the registry and this
//! list cannot drift in spelling either.

#[cfg(feature = "graph-go")]
use pedant_core::resolution::go::GoResolutionLimits;
#[cfg(feature = "graph-rust")]
use pedant_core::resolution::rust::ResolutionLimits;
#[cfg(feature = "graph-rust")]
use pedant_graph::GraphCacheLimits;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use pedant_graph::{GraphAnalysisLimits, GraphLimits};
use pedant_syntax::StructureInventoryLimits;

use super::limits::{CodeIntelligenceLimits, RepositoryLimits};

/// Every field of one plain-field limit type, each named by itself.
///
/// The pattern is exhaustive on purpose: it is the whole device. `stringify!`
/// then takes the token from the same name it just bound, so renaming a field
/// renames its row rather than leaving the old spelling behind for the registry
/// to keep agreeing with.
macro_rules! stated_fields {
    ($group:literal, $limits:expr, $type:ident { $($field:ident),+ $(,)? }) => {{
        let $type { $($field),+ } = $limits;
        [$((concat!($group, ".", stringify!($field)), u64::from($field))),+]
    }};
}

/// Every ceiling one accessor-fronted limit type states, each named by itself.
///
/// The twin of [`stated_fields`] for a type whose fields are private: the value
/// is rebuilt through its own constructor with every accessor this build reads,
/// so a field added there changes the arity and stops the call compiling.
/// `stringify!` then takes each row's token from the accessor it just read,
/// which is what the module doc claims of every row — thirteen of them used to
/// be hand-spelled literals restating the registry's own strings, and a
/// misspelling in either copy read as drift in the other.
macro_rules! stated_accessors {
    ($group:literal, $rebuilt:expr, { $($accessor:ident),+ $(,)? }) => {{
        let stated = $rebuilt;
        [$((concat!($group, ".", stringify!($accessor)), u64::from(stated.$accessor()))),+]
    }};
}

/// Every ceiling this build's limit types state, in claim order.
///
/// [`LimitField::ALL`](super::limit_field::LimitField::ALL)'s control, not its
/// copy: this list is complete because the compiler will not accept it
/// otherwise, and the registry is complete only because it agrees with this one.
///
/// A free function rather than a second inherent `impl LimitField`. The type's
/// own API belongs in one file, and this list is not part of it: it is the
/// statement the registry is checked against.
pub fn stated_ceilings(limits: &CodeIntelligenceLimits) -> Box<[(&'static str, u64)]> {
    let CodeIntelligenceLimits {
        syntax,
        repository,
        #[cfg(feature = "graph-rust")]
        rust,
        #[cfg(feature = "graph-go")]
        go,
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        graph_build,
        #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
        graph_analysis,
        #[cfg(feature = "graph-rust")]
        graph_cache,
    } = *limits;

    // One chain of fixed-length arrays, collected once. Each group's length is
    // a constant in its own return type and `Chain` sums them exactly, so the
    // collection reserves what the build states and a row added to any group
    // changes the reservation with it. Seven `extend` calls onto an unreserved
    // `Vec` doubled their way to fifty rows and then reallocated once more to
    // box them, against a total the compiler already knew.
    //
    // Each step shadows the last rather than mutating it, because the chained
    // type is what carries the length and a build that links no graph owner
    // must not name a group it does not have.
    let stated = syntax_rows(syntax)
        .into_iter()
        .chain(repository_rows(repository));
    #[cfg(feature = "graph-rust")]
    let stated = stated.chain(rust_rows(rust));
    #[cfg(feature = "graph-go")]
    let stated = stated.chain(go_rows(go));
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    let stated = stated
        .chain(graph_build_rows(graph_build))
        .chain(graph_analysis_rows(graph_analysis));
    #[cfg(feature = "graph-rust")]
    let stated = stated.chain(graph_cache_rows(graph_cache));
    stated.collect()
}

/// The bounded-inventory ceilings, read back through their own constructor.
fn syntax_rows(limits: StructureInventoryLimits) -> [(&'static str, u64); 2] {
    stated_accessors!(
        "syntax",
        StructureInventoryLimits::new(
            limits.max_syntax_depth(),
            limits.max_structures_per_source(),
        )
        .unwrap_or(limits),
        {
            max_syntax_depth,
            max_structures_per_source,
        }
    )
}

/// The repository-wide ceilings this index owns.
fn repository_rows(limits: RepositoryLimits) -> [(&'static str, u64); 11] {
    stated_fields!(
        "repository",
        limits,
        RepositoryLimits {
            max_directory_entries,
            max_authorities,
            max_files,
            max_source_file_bytes,
            max_total_source_bytes,
            max_structures,
            max_slices,
            max_graph_nodes,
            max_graph_references,
            max_graph_edges,
            max_page_items,
        }
    )
}

/// The Rust resolution owner's ceilings.
#[cfg(feature = "graph-rust")]
fn rust_rows(limits: ResolutionLimits) -> [(&'static str, u64); 11] {
    stated_fields!(
        "rust",
        limits,
        ResolutionLimits {
            max_manifests,
            max_member_scan_entries,
            max_units,
            max_source_files,
            max_source_file_bytes,
            max_total_source_bytes,
            max_module_depth,
            max_module_instances,
            max_dependency_depth,
            max_syntax_depth,
            max_candidates_per_reference,
        }
    )
}

/// The Go resolution owner's ceilings.
#[cfg(feature = "graph-go")]
fn go_rows(limits: GoResolutionLimits) -> [(&'static str, u64); 11] {
    stated_fields!(
        "go",
        limits,
        GoResolutionLimits {
            max_module_manifests,
            max_directory_entries,
            max_units,
            max_source_files,
            max_source_file_bytes,
            max_total_source_bytes,
            max_dependency_depth,
            max_syntax_depth,
            max_facts_per_source,
            max_candidates_per_reference,
            max_interface_comparisons,
        }
    )
}

/// What one graph build may produce, read back through its own constructor.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn graph_build_rows(limits: GraphLimits) -> [(&'static str, u64); 3] {
    stated_accessors!(
        "graph_build",
        GraphLimits::new(
            limits.max_nodes(),
            limits.max_references(),
            limits.max_edges(),
        ),
        {
            max_nodes,
            max_references,
            max_edges,
        }
    )
}

/// What one graph analysis may cost, read back through its own constructor.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn graph_analysis_rows(limits: GraphAnalysisLimits) -> [(&'static str, u64); 4] {
    stated_accessors!(
        "graph_analysis",
        GraphAnalysisLimits::new(
            limits.max_nodes(),
            limits.max_selected_edges(),
            limits.max_depth(),
            limits.max_betweenness_work(),
        ),
        {
            max_nodes,
            max_selected_edges,
            max_depth,
            max_betweenness_work,
        }
    )
}

/// What the bounded graph cache may retain, read back through its own
/// constructor.
#[cfg(feature = "graph-rust")]
fn graph_cache_rows(limits: GraphCacheLimits) -> [(&'static str, u64); 4] {
    stated_accessors!(
        "graph_cache",
        GraphCacheLimits::new(
            limits.max_source_projections(),
            limits.max_exact_graphs(),
            limits.max_selected_indexes_per_graph(),
            limits.max_derived_products_per_graph(),
        ),
        {
            max_source_projections,
            max_exact_graphs,
            max_selected_indexes_per_graph,
            max_derived_products_per_graph,
        }
    )
}
