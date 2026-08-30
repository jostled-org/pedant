//! What a degree answer says about each node it measured.
//!
//! The numbers are `pedant-graph`'s, unranked. This layer states which
//! declaration each measured node is; ordering, thresholds, and what counts as
//! "central" are the caller's, and a projection that sorted or cut the list
//! would be making that decision for it.

use serde::Serialize;

use super::entity::NavigationEntity;

/// How many selected edges one entity states at each of its ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DegreeRecord {
    entity: NavigationEntity,
    incoming: u32,
    outgoing: u32,
}

impl DegreeRecord {
    /// One measured node.
    pub(super) fn stated(entity: NavigationEntity, incoming: u32, outgoing: u32) -> Self {
        Self {
            entity,
            incoming,
            outgoing,
        }
    }

    /// What the measured node is.
    pub fn entity(&self) -> &NavigationEntity {
        &self.entity
    }

    /// Selected edges arriving at it.
    pub fn incoming(&self) -> u32 {
        self.incoming
    }

    /// Selected edges leaving it.
    pub fn outgoing(&self) -> u32 {
        self.outgoing
    }
}
