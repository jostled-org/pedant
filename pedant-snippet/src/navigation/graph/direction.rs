//! Which way a relation walk follows an admitted edge.
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

use pedant_graph::GraphDirection;
use serde::{Deserialize, Serialize};

/// Which way a relation walk follows an admitted edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationDirection {
    /// Follow edges away from their source.
    Outgoing,
    /// Follow edges back towards their source.
    Incoming,
    /// Follow edges either way.
    Both,
}

impl RelationDirection {
    /// Every direction, in the order they are declared.
    ///
    /// The one list a transport describes its vocabulary from, so a schema that
    /// tells a client which tokens it may send is built from the same table the
    /// deserializer reads them back through.
    pub const ALL: [Self; 3] = [Self::Outgoing, Self::Incoming, Self::Both];

    /// The stable token this direction is claimed under.
    pub fn token(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
            Self::Both => "both",
        }
    }

    /// Which way one graph walk follows an edge, in this vocabulary.
    ///
    /// No caller: a walk is asked for in this crate's spelling, and the records
    /// it answers with carry no direction of their own. The compiler is what
    /// reads this match — it is the half of the translation that names every
    /// `GraphDirection`, so a fourth way of following an edge fails to compile
    /// here rather than dropping silently out of the vocabulary a caller selects
    /// with.
    pub fn of(direction: GraphDirection) -> Self {
        match direction {
            GraphDirection::Outgoing => Self::Outgoing,
            GraphDirection::Incoming => Self::Incoming,
            GraphDirection::Both => Self::Both,
        }
    }

    /// The same direction, as the graph crate names it.
    pub(super) fn admitted(self) -> GraphDirection {
        match self {
            Self::Outgoing => GraphDirection::Outgoing,
            Self::Incoming => GraphDirection::Incoming,
            Self::Both => GraphDirection::Both,
        }
    }
}
