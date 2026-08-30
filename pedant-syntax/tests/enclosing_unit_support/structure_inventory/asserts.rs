//! Readings every structure case shares.

use pedant_syntax::{
    StructureFact, StructureInventory, StructureInventoryLimits, StructureKind, SyntaxLanguage,
    structure_inventory,
};

/// The one language no structure table states a source for.
///
/// TSX shares TypeScript's row and its recognizer, and the dispatch case proves
/// that pairing, so a fixture of its own would restate a table already stated.
/// Named rather than left to a smaller count: an exempt language that gains a
/// fixture fails below too, so the list cannot go stale.
const FIXTURE_EXEMPT: [SyntaxLanguage; 1] = [SyntaxLanguage::Tsx];

/// A depth ceiling above every fixture's own nesting.
///
/// Named rather than repeated, so a case about the structure ceiling cannot
/// accidentally be answered by the depth one.
pub(super) const AMPLE_DEPTH: u32 = 64;

/// A structure ceiling above every fixture's own inventory.
pub(super) const AMPLE_STRUCTURES: u32 = 100_000;

/// The caller's own table named every language the model states, once each.
///
/// Every case here ends with this guard, handing it the languages its loop
/// actually reached. A count against a written-down length says a loop ran that
/// many times and nothing more: a table naming one language twice and omitting
/// another counts identically, and a seventh [`SyntaxLanguage`] — forced into
/// `language_name`, `extraction_enabled`, and `minimal_declaration` by their
/// exhaustive matches, and into no hand-written table by anything — would leave
/// every such count passing. Comparing the reached set against the language
/// model closes both, and it closes them for the caller's table rather than for
/// one table standing in for all of them.
pub(super) fn assert_every_fixture_ran(reached: &[SyntaxLanguage]) {
    for language in crate::fixtures::ALL_LANGUAGES {
        let stated = reached.iter().filter(|it| **it == language).count();
        assert_eq!(
            stated,
            usize::from(!FIXTURE_EXEMPT.contains(&language)),
            "{language:?} is reached once by this case's table unless it is named exempt"
        );
    }
}

/// The complete inventory of one fixture, beneath ample ceilings.
///
/// Panics rather than returning, because every fixture states a complete
/// structure set by construction: a refusal here is the fixture breaking, not a
/// case's subject.
pub(super) fn inventory_of(source: &str, language: SyntaxLanguage) -> StructureInventory<'_> {
    structure_inventory(source, language, ample())
        .unwrap_or_else(|refusal| panic!("{language:?} states a complete inventory: {refusal}"))
}

/// Limits above every fixture's own nesting and inventory.
pub(super) fn ample() -> StructureInventoryLimits {
    StructureInventoryLimits::new(AMPLE_DEPTH, AMPLE_STRUCTURES).expect("nonzero ceilings")
}

/// What one structure is, apart from where it sits.
///
/// The head every comparable row in this tree opens with. Three cases wrote it
/// out — one comparing identities alone, one appending byte extents, one
/// appending lines — and three copies were three chances for a column to be
/// dropped from one of them and for that case to keep passing over a narrower
/// claim than it states.
pub(super) type StructureIdentity<'source> = (StructureKind, Option<&'source str>, Option<u32>);

/// One structure's kind, declared name, and owner position.
pub(super) fn identity_of<'source>(fact: &StructureFact<'source>) -> StructureIdentity<'source> {
    (fact.kind(), fact.name(), fact.owner())
}

/// One inventory's kinds and names, for a failure message that has to say which
/// structures were stated.
///
/// A projection rather than the inventory itself, because a span and an owner
/// position say nothing to a reader counting rows.
pub(super) fn kinds_and_names<'source>(
    inventory: &StructureInventory<'source>,
) -> Box<[(StructureKind, Option<&'source str>)]> {
    inventory
        .structures()
        .iter()
        .map(|fact| (fact.kind(), fact.name()))
        .collect()
}

/// The one-based line holding `offset`, counted from the source itself.
///
/// Deliberately not the crate's own line index: a case that read line numbers
/// through the same table that produced them would agree with any table.
pub(super) fn line_at(source: &str, offset: usize) -> u32 {
    let counted = source[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    u32::try_from(counted + 1).expect("a fixture under four billion lines")
}
