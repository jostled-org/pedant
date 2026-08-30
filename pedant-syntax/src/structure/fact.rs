//! One logical structure, exactly as its source states it.

use pedant_types::{StructureKind, StructureSpan};

/// One logical structure a source declares.
///
/// Bound to the source its inventory was extracted from, the way a Go fact is:
/// the span slices that exact string, and the name is borrowed from it. A
/// consumer that retains structures past the parse owns them at its boundary.
///
/// The owner is a position in the same inventory rather than a second span,
/// because an inventory holds one structure per site: the index is the
/// identity, and it cannot name a structure in another file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructureFact<'source> {
    kind: StructureKind,
    name: Option<&'source str>,
    span: StructureSpan,
    owner: Option<u32>,
}

impl<'source> StructureFact<'source> {
    /// One structure of `kind` covering `span`, owned by `owner`.
    #[cfg(any(feature = "rust", feature = "_ts"))]
    pub(crate) fn new(
        kind: StructureKind,
        name: Option<&'source str>,
        span: StructureSpan,
        owner: Option<u32>,
    ) -> Self {
        Self {
            kind,
            name,
            span,
            owner,
        }
    }

    /// What this structure declares.
    pub fn kind(self) -> StructureKind {
        self.kind
    }

    /// The declared name, in its source spelling.
    ///
    /// Absent for a structure its grammar states no name for. This contract
    /// states two: the Rust `impl` block, and the file module a Python or
    /// ECMAScript source declares no node for.
    pub fn name(self) -> Option<&'source str> {
        self.name
    }

    /// The extent of the whole declaration.
    pub fn span(self) -> StructureSpan {
        self.span
    }

    /// The nearest structure that lexically owns this one, as a position in the
    /// same inventory.
    ///
    /// Absent for a structure no other structure in its source contains.
    pub fn owner(self) -> Option<u32> {
        self.owner
    }
}
