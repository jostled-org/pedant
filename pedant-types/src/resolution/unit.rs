//! One language compilation and name-resolution context.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Language;

use super::id::ResolutionUnitId;

/// One compilation context a report resolves names inside.
///
/// Rust maps each unit to one Cargo target instance. `key` is the stable
/// structural identity a consumer joins on; `name` is what the language calls
/// the unit.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionUnit {
    id: ResolutionUnitId,
    language: Language,
    key: Arc<str>,
    name: Arc<str>,
}

impl ResolutionUnit {
    pub(crate) fn new(
        id: ResolutionUnitId,
        language: Language,
        key: Arc<str>,
        name: Arc<str>,
    ) -> Self {
        Self {
            id,
            language,
            key,
            name,
        }
    }

    /// This unit's identifier.
    pub fn id(&self) -> ResolutionUnitId {
        self.id
    }

    /// The language whose resolution rules this unit follows.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The stable structural key units are sorted and deduplicated by.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The unit's display name.
    pub fn name(&self) -> &str {
        &self.name
    }
}
