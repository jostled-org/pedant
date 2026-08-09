//! Dense report identifiers branded by the collection they index.

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// One dense `u32` index whose marker fixes the collection it addresses.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Id<K> {
    index: u32,
    #[serde(skip)]
    kind: PhantomData<fn() -> K>,
}

impl<K> Id<K> {
    /// The identifier's position in its report slice.
    pub fn index(self) -> u32 {
        self.index
    }

    pub(crate) fn new(index: u32) -> Self {
        Self {
            index,
            kind: PhantomData,
        }
    }
}

/// Marker distinguishing unit identifiers from the other ID kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitIdKind;

/// Marker distinguishing definition identifiers from the other ID kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionIdKind;

/// Marker distinguishing reference identifiers from the other ID kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceIdKind;

/// A resolution unit's dense identifier within one report.
pub type ResolutionUnitId = Id<UnitIdKind>;

/// A definition's dense identifier within one report.
pub type DefinitionId = Id<DefinitionIdKind>;

/// A reference's dense identifier within one report.
pub type ReferenceId = Id<ReferenceIdKind>;
