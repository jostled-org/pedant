//! What a paged query is, as a cursor binding has to record it.
//!
//! A cursor is a claim about a query as well as about an index, so every paged
//! operation states which operation it is and which normalized parameters it
//! selected by. Those two answers are the whole of what this trait asks for:
//! the binding, the ordering, and the refusal belong to [`page`](super::page),
//! which is the one place they are written.

use crate::index::{PagedQuery, RevisionClaim};

/// One paged query's identity and normalized parameters.
pub(super) trait PagedRequest {
    /// Which paged operation this is.
    fn kind(&self) -> PagedQuery;

    /// Write every normalized parameter this query selects by.
    fn claim(&self, claim: &mut RevisionClaim);
}

/// `list_projects`, which selects by nothing but the index it reads.
pub(super) struct ProjectListing;

impl PagedRequest for ProjectListing {
    fn kind(&self) -> PagedQuery {
        PagedQuery::Projects
    }

    fn claim(&self, _: &mut RevisionClaim) {}
}
