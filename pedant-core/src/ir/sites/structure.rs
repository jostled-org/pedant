//! One physical declaration site, and the definition it declares.

use pedant_types::StructureKind;

use super::range::IrRange;

/// The position of one definition in `FileIr::definition_sites`.
///
/// Opaque, because it is an identity rather than a number: it is minted where
/// the definition is recognized, and a caller that could build one from a count
/// could name a definition the visitor never recorded.
///
/// This is the join key a graph node follows to reach the physical declaration
/// that states it. A name is not a join key — two functions can share one — and
/// neither is a span, because a declaration and the attribute above it can
/// share theirs. The ordinal is the one identity the visitor already
/// established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionSiteId(usize);

impl DefinitionSiteId {
    /// The identity of the definition recorded at `ordinal`.
    pub(crate) fn new(ordinal: usize) -> Self {
        Self(ordinal)
    }

    /// The position this identity names in `FileIr::definition_sites`.
    pub fn index(self) -> usize {
        self.0
    }
}

/// The position of one physical declaration in `FileIr::structure_sites`.
///
/// Opaque for the reason [`DefinitionSiteId`] is, and a distinct type from it
/// for one more: the two tables are filled by one call, in one order, and both
/// ordinals are `usize`. A caller holding the pair as bare numbers can pass them
/// the other way round and every arithmetic on them still typechecks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructureSiteId(usize);

impl StructureSiteId {
    /// The identity of the declaration recorded at `ordinal`.
    pub(crate) fn new(ordinal: usize) -> Self {
        Self(ordinal)
    }

    /// The position this identity names in `FileIr::structure_sites`.
    pub fn index(self) -> usize {
        self.0
    }
}

/// One physical declaration, covering everything its source writes for it.
///
/// A definition site names where a declared *name* sits, because that is what a
/// resolution report points at. A structure site covers the whole declaration —
/// attributes, signature, and body — because that is what an outline shows and
/// what a reader asks to read.
///
/// Both are recorded by one traversal, so a source is walked once for the pair
/// and the ordinal linking them is the visitor's own rather than a later
/// re-derivation.
#[derive(Debug)]
pub struct StructureSite {
    /// What this declaration declares.
    pub kind: StructureKind,
    /// The extent of the whole declaration.
    pub range: IrRange,
    /// The declaration that lexically owns this one, inside the same source.
    pub parent: Option<StructureSiteId>,
    /// The definition this declaration states, absent for an `impl` block.
    ///
    /// An `impl` block declares no name, so it names no definition either.
    /// Minting one for it would put an entry in the resolution report that no
    /// reference can ever denote.
    ///
    /// This is also where a reader takes the declared name. The site stores no
    /// second copy of it: a name and a definition ordinal are recorded by one
    /// call and are present or absent together, so a stored name could only
    /// ever agree with this one or be a bug.
    pub definition: Option<DefinitionSiteId>,
}
