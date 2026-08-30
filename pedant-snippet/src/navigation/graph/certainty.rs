//! How much of an admitted edge a graph request requires to be known.
//!
//! `pedant-graph` deliberately deserializes nothing: every identity it publishes
//! is a position into a graph a caller must have read it out of, and a record it
//! could hydrate from bytes would be one nothing proved. That decision is the
//! graph owner's and this crate does not widen it — so a request that arrives
//! over a transport states its selection in this crate's own vocabulary and is
//! translated once, in the module that owns it.
//!
//! The match below is total in both directions, so a new graph variant fails to
//! compile here rather than falling silently out of a selection or a cursor
//! claim.

use pedant_graph::GraphCertainty;
use serde::{Deserialize, Serialize};

/// How much of an admitted edge a graph query requires to be known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeCertainty {
    /// Language rules identify the target without inference.
    Resolved,
    /// Source evidence identifies the target, but proof is not available.
    Possible,
}

impl EdgeCertainty {
    /// Every certainty, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 2] = [Self::Resolved, Self::Possible];

    /// The stable token this certainty is claimed under.
    pub fn token(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Possible => "possible",
        }
    }

    /// How much one graph edge is known, in this vocabulary.
    ///
    /// No caller: an answer carries `pedant_graph::GraphEdge` itself, which
    /// serializes in the graph crate's own spelling. The compiler is what reads
    /// this match — it is the half of the translation that names every
    /// `GraphCertainty`, so a third certainty fails to compile here rather than
    /// dropping silently out of the vocabulary a caller selects with.
    pub fn of(certainty: GraphCertainty) -> Self {
        match certainty {
            GraphCertainty::Resolved => Self::Resolved,
            GraphCertainty::Possible => Self::Possible,
        }
    }

    /// The same certainty, as the graph crate names it.
    pub(super) fn admitted(self) -> GraphCertainty {
        match self {
            Self::Resolved => GraphCertainty::Resolved,
            Self::Possible => GraphCertainty::Possible,
        }
    }
}
