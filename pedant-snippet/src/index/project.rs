//! One resolved project slice, its key, its dense identity, and the handle that
//! carries that identity out of the revision that minted it.
//!
//! A slice is one graph's worth of project: one Cargo target or one Go main
//! module with its admitted local replacements. Rust target graphs and Go
//! module graphs stay separate, and the index never joins unrelated graphs into
//! a synthetic workspace graph — a path between two of them would be a claim
//! the compiler never makes.

use std::sync::Arc;

use pedant_types::Language;
use serde::{Deserialize, Serialize};

use super::coverage::StructureCoverage;
use super::revision::IndexRevision;

/// The position of one project slice in one index revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId {
    position: u32,
}

impl ProjectId {
    /// The identity of the project retained at `position`.
    pub(crate) fn at(position: u32) -> Self {
        Self { position }
    }

    /// The position this identity names.
    pub fn position(self) -> u32 {
        self.position
    }
}

/// One project identity, together with the revision that issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectHandle {
    revision: IndexRevision,
    id: ProjectId,
}

impl ProjectHandle {
    /// A handle naming `position` inside `revision`.
    pub fn new(revision: IndexRevision, position: u32) -> Self {
        Self {
            revision,
            id: ProjectId::at(position),
        }
    }

    /// The revision that issued this handle.
    pub fn revision(self) -> IndexRevision {
        self.revision
    }

    /// The identity this handle carries.
    pub fn id(self) -> ProjectId {
        self.id
    }
}

/// What selects exactly one project graph.
///
/// The language, the normalized authority path, and the language-owned label
/// that picks one graph inside that authority: a Cargo package-and-target for
/// Rust, the module path for Go. Ordering by these three is what makes project
/// identity independent of the order the filesystem was walked in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectKey {
    language: Language,
    authority: Arc<str>,
    unit: Arc<str>,
}

impl ProjectKey {
    /// The key naming one graph inside one authority.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn new(language: Language, authority: Arc<str>, unit: Arc<str>) -> Self {
        Self {
            language,
            authority,
            unit,
        }
    }

    /// The language this project resolves.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The normalized path of the authority file that selected it.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The target or unit label that selects one graph inside that authority.
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

/// One resolved project graph and the physical sources it reached.
#[derive(Debug)]
pub struct ProjectSlice {
    id: ProjectId,
    key: ProjectKey,
    coverage: StructureCoverage,
    sources: Box<[Arc<str>]>,
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    graph: super::retained::RetainedGraph,
}

impl ProjectSlice {
    /// Seal one resolved slice into its revision.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(super) fn sealed(
        id: ProjectId,
        key: ProjectKey,
        coverage: StructureCoverage,
        sources: Box<[Arc<str>]>,
        graph: super::retained::RetainedGraph,
    ) -> Self {
        Self {
            id,
            key,
            coverage,
            sources,
            graph,
        }
    }

    /// This slice's identity in the revision that indexed it.
    pub fn id(&self) -> ProjectId {
        self.id
    }

    /// What selects this slice's graph.
    pub fn key(&self) -> &ProjectKey {
        &self.key
    }

    /// What kind of evidence this slice can answer with.
    pub fn coverage(&self) -> StructureCoverage {
        self.coverage
    }

    /// Every normalized source path this slice's corpus reached, sorted.
    pub fn sources(&self) -> &[Arc<str>] {
        &self.sources
    }

    /// The graph this slice resolved.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
    pub fn graph(&self) -> &pedant_graph::CodeGraph {
        self.graph.graph()
    }

    /// This slice's graph, ready to be asked under `selection` and `limits`.
    ///
    /// The one route to an answer about this graph, so a Rust slice's selected
    /// indexes and derived products are retained beneath the two per-graph
    /// ceilings this crate's revision claim already states.
    ///
    /// # Errors
    ///
    /// Every refusal the graph crate's own analysis constructor states, in the
    /// same order.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn analyzed(
        &self,
        selection: pedant_graph::GraphEdgeSelection,
        limits: pedant_graph::GraphAnalysisLimits,
    ) -> Result<super::analysis::SliceAnalysis<'_>, pedant_graph::GraphAnalysisError> {
        super::analysis::SliceAnalysis::opened(&self.graph, selection, limits)
    }
}
