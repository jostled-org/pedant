//! What a navigation answer says about one resolved project.
//!
//! The health is the project's own: it is taken over the issues its authority
//! carries, not over the whole index. A record that reported the index's health
//! would call every project of a degraded repository degraded, which is the
//! opposite of what a caller deciding whether to trust one project needs.

use pedant_types::Language;
use serde::{Deserialize, Serialize};

use crate::index::{IndexHealth, ProjectHandle, StructureCoverage};

/// One resolved project, as the public listing states it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    handle: ProjectHandle,
    language: Language,
    authority: Box<str>,
    unit: Box<str>,
    coverage: StructureCoverage,
    health: IndexHealth,
}

impl ProjectRecord {
    /// State one resolved slice.
    pub(super) fn stated(
        handle: ProjectHandle,
        language: Language,
        authority: Box<str>,
        unit: Box<str>,
        coverage: StructureCoverage,
        health: IndexHealth,
    ) -> Self {
        Self {
            handle,
            language,
            authority,
            unit,
            coverage,
            health,
        }
    }

    /// This project's revision-bound identity.
    pub fn handle(&self) -> ProjectHandle {
        self.handle
    }

    /// The language it resolves.
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

    /// What kind of evidence its slice can answer with.
    pub fn coverage(&self) -> StructureCoverage {
        self.coverage
    }

    /// What its own authority refused, if anything.
    pub fn health(&self) -> IndexHealth {
        self.health
    }
}
