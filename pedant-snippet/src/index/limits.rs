//! Every ceiling one code-intelligence index runs beneath.
//!
//! A host limit is not configuration: it is part of the index's identity, so
//! every field here enters the revision claim. The registry that names them one
//! at a time lives beside this file in
//! [`limit_field`](super::limit_field), because the claim encoder and the
//! identity proof both read that list and neither reads these structs directly.

use pedant_syntax::StructureInventoryLimits;

/// Repository-wide ceilings the index itself owns.
///
/// These bound retained physical records — one charge per physical file, byte,
/// structure, slice, and graph record — rather than what any one project
/// selects. A language owner's own ceilings measure the corpus that owner
/// selected, and two projects that share a source both selected it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryLimits {
    /// Directory entries the corpus walk may visit. Default 262,144.
    pub max_directory_entries: u32,
    /// Project authorities discovery may select. Default 4,096.
    pub max_authorities: u32,
    /// Distinct physical source files the index may admit. Default 65,536.
    pub max_files: u32,
    /// Bytes one source file may hold. Default 8 MiB.
    pub max_source_file_bytes: u64,
    /// Bytes all retained source text may hold. Default 512 MiB.
    pub max_total_source_bytes: u64,
    /// Physical logical structures the index may retain. Default 1,048,576.
    pub max_structures: u32,
    /// Resolved project slices the index may retain. Default 16,384.
    pub max_slices: u32,
    /// Graph nodes across every slice. Default 1,000,000.
    pub max_graph_nodes: u32,
    /// Graph reference records across every slice. Default 4,000,000.
    pub max_graph_references: u32,
    /// Graph edges across every slice. Default 4,000,000.
    pub max_graph_edges: u32,
    /// Items one page may carry. Default 200.
    pub max_page_items: u32,
}

impl Default for RepositoryLimits {
    fn default() -> Self {
        Self {
            max_directory_entries: 262_144,
            max_authorities: 4_096,
            max_files: 65_536,
            max_source_file_bytes: 8 * 1_024 * 1_024,
            max_total_source_bytes: 512 * 1_024 * 1_024,
            max_structures: 1_048_576,
            max_slices: 16_384,
            max_graph_nodes: 1_000_000,
            max_graph_references: 4_000_000,
            max_graph_edges: 4_000_000,
            max_page_items: 200,
        }
    }
}

/// The exact owner limit values each subsystem of one index runs beneath.
///
/// Each field is the owning crate's own limit type rather than a copy of its
/// numbers, so raising a ceiling here raises the one that crate actually
/// checks. A language or graph field exists only in a build that links that
/// owner, which is why two feature profiles state different identities for the
/// same repository: they are running different subsystems over it.
///
/// In a build with no graph owner every field's own default is the whole
/// answer, so that profile derives `Default` rather than restating two values a
/// derive already states.
#[cfg_attr(
    not(any(feature = "graph-rust", feature = "graph-go")),
    derive(Default)
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeIntelligenceLimits {
    /// Syntax depth and structures per source for every loose inventory.
    pub syntax: StructureInventoryLimits,
    /// Repository-wide retained-record ceilings.
    pub repository: RepositoryLimits,
    /// The Rust resolution owner's ceilings.
    #[cfg(feature = "graph-rust")]
    pub rust: pedant_core::resolution::rust::ResolutionLimits,
    /// The Go resolution owner's ceilings.
    #[cfg(feature = "graph-go")]
    pub go: pedant_core::resolution::go::GoResolutionLimits,
    /// What one graph build may produce.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub graph_build: pedant_graph::GraphLimits,
    /// What one graph analysis may cost.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub graph_analysis: pedant_graph::GraphAnalysisLimits,
    /// What the bounded Rust graph cache may retain.
    #[cfg(feature = "graph-rust")]
    pub graph_cache: pedant_graph::GraphCacheLimits,
}

/// Two of the graph ceilings are this crate's own, so this profile states them
/// rather than deriving them.
///
/// Every other field takes its owner's published default, three lines below.
/// `graph_analysis` and `graph_cache` are the two the graph crate leaves to its
/// host, because both bound what an *answer* may cost rather than what a graph
/// may hold: the analysis ceilings are set beneath the repository's own graph
/// allowance so one query cannot walk a graph this index would not have
/// retained, and the cache ceilings are set to a working set a live server can
/// hold across revisions rather than to a fraction of one repository.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
impl Default for CodeIntelligenceLimits {
    fn default() -> Self {
        Self {
            syntax: StructureInventoryLimits::default(),
            repository: RepositoryLimits::default(),
            #[cfg(feature = "graph-rust")]
            rust: pedant_core::resolution::rust::ResolutionLimits::default(),
            #[cfg(feature = "graph-go")]
            go: pedant_core::resolution::go::GoResolutionLimits::default(),
            graph_build: pedant_graph::GraphLimits::default(),
            graph_analysis: pedant_graph::GraphAnalysisLimits::new(
                100_000, 400_000, 256, 50_000_000,
            ),
            #[cfg(feature = "graph-rust")]
            graph_cache: pedant_graph::GraphCacheLimits::new(4_096, 64, 16, 256),
        }
    }
}
