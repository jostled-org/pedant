//! The bounded, source-bound structure inventory one source states.

use pedant_types::StructureRecord;

use crate::language::SyntaxLanguage;
use crate::structure::fact::StructureFact;

/// Every logical structure one source declares, in source order.
///
/// Bound to the source it was extracted from, the way `go::GoFileFacts` is:
/// every span slices that exact string and every name borrows it. A consumer
/// that keeps structures past the parse owns them at its own boundary, so
/// nothing here copies a declaration body.
///
/// An inventory exists only when its walk completed beneath both ceilings and
/// its parser stated a complete tree, so holding one is the claim that this is
/// every structure the source declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructureInventory<'source> {
    source: &'source str,
    language: SyntaxLanguage,
    structures: Box<[StructureFact<'source>]>,
}

impl<'source> StructureInventory<'source> {
    /// Seal one completed walk.
    #[cfg(any(feature = "rust", feature = "_ts"))]
    pub(crate) fn seal(
        source: &'source str,
        language: SyntaxLanguage,
        structures: Box<[StructureFact<'source>]>,
    ) -> Self {
        Self {
            source,
            language,
            structures,
        }
    }

    /// The exact source every span here indexes.
    pub fn source(&self) -> &'source str {
        self.source
    }

    /// The grammar this inventory was read through.
    pub fn language(&self) -> SyntaxLanguage {
        self.language
    }

    /// Every structure, in source order.
    ///
    /// Source order is by opening byte, and an owner always precedes the
    /// structures it owns, so a consumer building an outline reads the forest
    /// in one forward pass.
    pub fn structures(&self) -> &[StructureFact<'source>] {
        &self.structures
    }

    /// The same structures, owned rather than bound to this parse.
    ///
    /// A consumer that outlives the source string cannot hold a
    /// [`StructureFact`]: its name borrows the exact text the walk read. This
    /// is that same inventory with each name copied and nothing else changed,
    /// so the order, the spans, and the owner positions are the ones this
    /// inventory states.
    pub fn retained(&self) -> Box<[StructureRecord]> {
        self.structures
            .iter()
            .map(|fact| {
                StructureRecord::new(
                    fact.kind(),
                    fact.name().map(Box::from),
                    fact.span(),
                    fact.owner(),
                )
            })
            .collect()
    }

    /// The byte-exact source text one structure covers.
    ///
    /// Absent when `structure` is not a position in this inventory. A position
    /// no `usize` can name is one of those, and it is narrowed rather than cast:
    /// every other conversion in this crate is checked, and an unchecked one
    /// here would name a different structure's text on a platform whose `usize`
    /// is narrower than the published index. The span itself always slices,
    /// because the walk that minted it read it off this same string.
    pub fn text_of(&self, structure: u32) -> Option<&'source str> {
        let fact = self.structures.get(usize::try_from(structure).ok()?)?;
        self.source.get(fact.span().byte_range())
    }
}
