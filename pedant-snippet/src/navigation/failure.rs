//! The envelope a refused query travels in.
//!
//! A query that refuses still knows which state it refused from, so it says so.
//! The revisions and the health come from that state — the same three fields a
//! successful answer carries — because a client that has to decide whether to
//! retry needs to know whether the index moved, and a bare error would leave it
//! guessing.

use serde::Serialize;

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceState, ErrorReport, IndexHealth, IndexRevision,
    StateRevision,
};

/// One refused query, and the state it was refused from.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct QueryFailure {
    index_revision: IndexRevision,
    state_revision: StateRevision,
    health: IndexHealth,
    error: ErrorReport,
}

impl QueryFailure {
    /// The envelope one refused query sends.
    pub fn of(state: &CodeIntelligenceState, error: &CodeIntelligenceError) -> Self {
        Self {
            index_revision: state.index().revision(),
            state_revision: state.revision(),
            health: state.health(),
            error: ErrorReport::of(error),
        }
    }

    /// The identity of the index this was refused from.
    pub fn index_revision(&self) -> IndexRevision {
        self.index_revision
    }

    /// The identity of the state this was refused from.
    pub fn state_revision(&self) -> StateRevision {
        self.state_revision
    }

    /// What that state says about itself.
    pub fn health(&self) -> IndexHealth {
        self.health
    }

    /// The refusal it carries.
    pub fn error(&self) -> &ErrorReport {
        &self.error
    }
}
