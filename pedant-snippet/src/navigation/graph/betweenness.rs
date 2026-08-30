//! What a betweenness answer says about each node it measured.
//!
//! Both scores travel: the raw one and the same score over the largest this
//! graph could state. Rounding either would be a rendering decision, and a
//! caller comparing two revisions of one repository is the one entitled to make
//! it.

use serde::Serialize;

use super::entity::NavigationEntity;

/// How much of the selected topology's shortest-path traffic one entity
/// carries.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BetweennessRecord {
    entity: NavigationEntity,
    raw: f64,
    normalized: f64,
}

impl BetweennessRecord {
    /// One measured node.
    pub(super) fn stated(entity: NavigationEntity, raw: f64, normalized: f64) -> Self {
        Self {
            entity,
            raw,
            normalized,
        }
    }

    /// What the measured node is.
    pub fn entity(&self) -> &NavigationEntity {
        &self.entity
    }

    /// The unnormalized score.
    pub fn raw(&self) -> f64 {
        self.raw
    }

    /// The same score over the largest one this graph could state.
    pub fn normalized(&self) -> f64 {
        self.normalized
    }
}
