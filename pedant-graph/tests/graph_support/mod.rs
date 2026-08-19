//! Helper modules for the public graph boundary root.
//!
//! Every registered `#[test]` wrapper lives in `tests/graph.rs`; nothing below
//! declares one, so libtest identities equal the fixed owner inventory.

/// Degree and directed betweenness over the shared selected indexes.
pub mod analysis_centrality;
/// Strongly connected components, condensation, and iterative shape.
pub mod analysis_components;
/// What the derived answers may read, and what the layout proves before it
/// describes anything.
pub mod analysis_derived_bounds;
/// The derived evidence answered equally, however the library was written.
pub mod analysis_derived_determinism;
/// Equal graphs answered equally, whatever order their files were created in.
pub mod analysis_determinism;
/// Cohesion, modularity, affinity, and the cycles that cross a partition.
pub mod analysis_divergence;
/// One divergence answer, taken apart so two of them can be compared.
pub mod analysis_divergence_model;
/// Real workspaces, shared analysis views, and comparable analysis text.
pub mod analysis_fixture;
/// Coordinate-free metadata projected for a renderer or a ranker.
pub mod analysis_layout;
/// Independent models of every derived answer, taken from the raw graph.
pub mod analysis_oracle;
/// What the analysis family holds and publishes.
pub mod analysis_ownership;
/// How the analysis family proves a ceiling before it spends against it.
pub mod analysis_ownership_bounds;
/// The written-down model of what the analysis family publishes.
pub mod analysis_ownership_model;
/// One selection applied once, and who may read what it produced.
pub mod analysis_ownership_sharing;
/// The declared module partition derived from logical containment.
pub mod analysis_partition;
/// The two ways a corpus is perturbed without changing what it states.
pub mod analysis_perturbation;
/// One explicit edge selection and the admission ceilings it is bounded by.
pub mod analysis_selection;
/// The published package's manifest, module tree, and registered predicates.
pub mod analysis_source_boundary;
/// Bounded neighborhoods, shortest paths, and induced subgraphs.
pub mod analysis_traversal;
/// Cached analysis answered exactly as the direct analysis answers it.
pub mod cache_analysis;
/// What a caller still holds after the cache clears, evicts, or is dropped.
pub mod cache_analysis_lifetime;
/// The arguments a cached-analysis case asks over, and how the answers read.
pub mod cache_analysis_reading;
/// What one graph's derived state retains, drops first, and counts.
pub mod cache_analysis_retention;
/// One allocation per repeated claim, and what states a different claim.
pub mod cache_analysis_sharing;
/// The published counter vocabulary and the exact deltas a case reads by it.
pub mod cache_counting;
/// Exact graph reuse, ceilings, retention, and equality with direct builds.
pub mod cache_exact;
/// Real workspaces and the cached and direct builders every case enters by.
pub mod cache_fixture;
/// What the cache boundary publishes, and what it may name.
pub mod cache_ownership;
/// Which owner every graph a caller reuses passes through.
pub mod cache_ownership_path;
/// The one lock over a graph's derived state, and the one counter owner.
pub mod cache_ownership_state;
/// Source-unit reuse, the seam that decides it, and bounded retention.
pub mod cache_projection;
/// Tied definition identities, and what a retained projection joins through.
pub mod cache_remapping;
/// One repository state, one change, the reuse it owes, and the direct graph.
pub mod cache_revision;
/// The published package's dependency closure, inventory, and reading surface.
pub mod cache_source_boundary;
/// The public reading, identity, and lifecycle surface.
pub mod contract;
/// The temporary Cargo repositories every case projects, written out.
pub mod corpus;
/// The temporary Cargo repositories the derived-analysis cases project.
pub mod corpus_analysis;
/// The temporary Cargo repositories a case states as a rule over a count.
pub mod corpus_generated;
/// The temporary Cargo repositories the revision matrix is read over.
pub mod corpus_revision;
/// Refusals taken before a graph exists.
pub mod defensive;
/// Reference records, candidate edges, and dependency evidence.
pub mod evidence;
/// Real fixtures and the production path to a snapshot-bound resolution.
pub mod fixture;
/// Every source these cases read, beside its compile-time text.
pub mod inventory;
/// Projection after the fixture repository is gone.
pub mod isolation;
/// Structural ownership of this crate's own production sources.
pub mod ownership;
/// The written-down model those ownership cases are read against.
pub mod ownership_model;
/// One syntactic report restated at the semantic tier.
pub mod promotion;
/// Comparable text taken from the public reading surface.
pub mod render;
/// Readers over this crate's own production sources.
pub mod scan;
/// The declared items, derives, fields, and constructors those sources state.
pub mod surface;
/// Node inventory, source association, and the containment forest.
pub mod topology;
/// Tier propagation and the exact version-1 serialized contract.
pub mod wire;
