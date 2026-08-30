//! The one envelope every navigation answer travels in.
//!
//! Both revisions and the health come from the state that answered, never from
//! the caller and never from a transport. That is what makes CLI JSON and MCP
//! content the same bytes for the same question: there is one place they are
//! assembled, and neither transport can add to it or leave anything out.

use serde::{Deserialize, Serialize};

use crate::index::{CodeIntelligenceState, IndexHealth, IndexRevision, StateRevision};

use super::cursor::PageCursor;

/// One answer, and the state it was answered from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NavigationResponse<T> {
    index_revision: IndexRevision,
    state_revision: StateRevision,
    health: IndexHealth,
    result: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_page: Option<PageCursor>,
}

impl<T> NavigationResponse<T> {
    /// One whole answer, which no cursor continues.
    pub(super) fn whole(state: &CodeIntelligenceState, result: T) -> Self {
        Self::paged(state, result, None)
    }

    /// One page of an answer, and the cursor that continues it.
    pub(super) fn paged(
        state: &CodeIntelligenceState,
        result: T,
        next_page: Option<PageCursor>,
    ) -> Self {
        Self {
            index_revision: state.index().revision(),
            state_revision: state.revision(),
            health: state.health(),
            result,
            next_page,
        }
    }

    /// The identity of the index this was answered from.
    pub fn index_revision(&self) -> IndexRevision {
        self.index_revision
    }

    /// The identity of the state this was answered from.
    pub fn state_revision(&self) -> StateRevision {
        self.state_revision
    }

    /// What that state says about itself.
    pub fn health(&self) -> IndexHealth {
        self.health
    }

    /// The answer.
    pub fn result(&self) -> &T {
        &self.result
    }

    /// The answer, taken out of its envelope.
    pub fn into_result(self) -> T {
        self.result
    }

    /// Where this answer continues, absent when it is whole or last.
    pub fn next_page(&self) -> Option<PageCursor> {
        self.next_page
    }
}
