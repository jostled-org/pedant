//! The owner that indexes one repository, again and again, under one set of
//! ceilings.
//!
//! An index is immutable, so a repository that changed is a new index rather
//! than an edited one. What survives a revision is the work, not the answer:
//! the indexer holds the bounded graph reuse store, so the second revision of a
//! repository where one file moved rebuilds only the graphs whose snapshot or
//! resolution actually changed.
//!
//! The ceilings belong to the indexer rather than to each call, because every
//! one of them is part of the identity a revision claims. An owner that took new
//! limits per build would publish two revisions of one repository and leave a
//! caller to work out that the numbers, not the sources, were what differed.

use std::path::Path;

use super::authority::ProjectAuthority;
use super::build;
use super::error::CodeIntelligenceError;
use super::limits::CodeIntelligenceLimits;
use super::reuse::GraphReuse;
use super::state::CodeIntelligenceState;

/// One repository indexer, and the graph work it carries between revisions.
pub struct CodeIntelligenceIndexer {
    limits: CodeIntelligenceLimits,
    reuse: GraphReuse,
}

impl CodeIntelligenceIndexer {
    /// An indexer that publishes revisions beneath `limits`.
    pub fn new(limits: CodeIntelligenceLimits) -> Self {
        Self {
            reuse: GraphReuse::new(&limits),
            limits,
        }
    }

    /// The ceilings every revision this indexer publishes runs beneath.
    pub fn limits(&self) -> &CodeIntelligenceLimits {
        &self.limits
    }

    /// Index the repository beneath `root` and publish one immutable state.
    ///
    /// The explicit authorities are always selected and each suppresses an
    /// equal automatic candidate. A failure among them is fatal: a caller that
    /// named a project meant that project, and indexing the repository without
    /// it would answer a question nobody asked. Every other failure is
    /// degraded and recorded, because a repository with one unreadable file
    /// still has an answer for every other file.
    ///
    /// # Errors
    ///
    /// Every fatal classification in the failure matrix: an unusable root, a
    /// path that escapes it, an explicit authority that does not load, and any
    /// repository-wide ceiling the admitted corpus passes.
    pub fn index(
        &mut self,
        root: &Path,
        authorities: &[ProjectAuthority],
    ) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
        build::build(root, authorities, self.limits, &mut self.reuse)
    }

    /// What the bounded Rust graph store has reused and what it has built.
    ///
    /// Cost, never an answer. No revision claim reads a counter here, so an
    /// eviction moves no identity and a hit and a miss publish the same bytes.
    #[cfg(feature = "graph-rust")]
    #[cfg_attr(docsrs, doc(cfg(feature = "graph-rust")))]
    pub fn graph_cache_stats(&self) -> pedant_graph::GraphCacheStats {
        self.reuse.stats()
    }
}
