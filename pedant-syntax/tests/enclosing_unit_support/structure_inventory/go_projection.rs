//! What a retained Go inventory projects, and the ceiling it is projected
//! beneath.
//!
//! The Go row is the one taken through another inventory: its structures are
//! projected out of the fact walk this crate already owns. That makes
//! `GoFileFacts::structure_inventory` the one route where the walk's own ceiling
//! and the reader's can differ, and the one route where a narrowing could state
//! a different set from the whole inventory it narrows.
//!
//! Beside [`super::limits`] rather than inside it, because neither claim here is
//! about a ceiling refusing during a walk. Nothing below descends: one asks what
//! a finished inventory is held to, the other asks whether two finished
//! inventories agree.

use pedant_syntax::go::GoFactLimits;
use pedant_syntax::tree_sitter::parse_bound;
use pedant_syntax::{
    StructureError, StructureInventory, StructureInventoryLimits, SyntaxLanguage,
    structure_inventory,
};

use super::asserts::{AMPLE_STRUCTURES, StructureIdentity, ample, identity_of};
use super::fixtures::STRUCTURE_GO_SOURCE;

/// The deepest grammar level the unbounded Go fact walk enters over
/// [`STRUCTURE_GO_SOURCE`], the root counting as zero.
///
/// Written down rather than read back from that walk. The retained-inventory
/// case below states one ceiling that admits and one that refuses; taking the
/// admitting one from the subject makes both halves relative to whatever it
/// counted, so a walk measuring every level one too deep — or one too shallow —
/// finds its own answer and passes both.
///
/// Not `StructureFixture`'s `depth` for the same source, which is a different
/// claim: that number is the shallowest ceiling the *structure* route is
/// admitted beneath, stated by the structure table for the structure cases. The
/// two are read from two contracts and must be free to disagree.
const GO_FACT_DEPTH: u32 = 9;

/// A retained inventory is held to the ceiling its reader states, and a narrowed
/// walk states exactly what the whole inventory states.
#[test]
fn projected_go_structures_hold_their_readers_ceiling_and_match_the_whole_inventory() {
    a_retained_go_walk_refuses_a_depth_ceiling_it_already_passed();
    the_narrowed_go_walk_states_what_the_whole_inventory_states();
}

/// A retained Go inventory is held to the ceiling its reader states, not to the
/// one its walk ran beneath.
///
/// The public `GoFileFacts::structure_inventory` route is the one place the two
/// depth ceilings can differ: the walk spends its own, and a caller holding the
/// finished inventory then asks for structures beneath a ceiling of its own
/// choosing. Nothing descends here, so a descent check cannot make the claim —
/// the depth that walk already reported is what the stated ceiling is compared
/// against. Without it a caller's ceiling was accepted and silently waived,
/// while the Rust and tree-sitter routes both enforced theirs.
///
/// Both ceilings are driven from [`GO_FACT_DEPTH`], and the walk's own reported
/// depth is asserted against it once, so the pair below is a claim about this
/// source rather than about whatever the walk counted.
fn a_retained_go_walk_refuses_a_depth_ceiling_it_already_passed() {
    let parsed =
        parse_bound(STRUCTURE_GO_SOURCE, SyntaxLanguage::Go).expect("the Go grammar parses");
    let facts = parsed
        .go_file_facts(GoFactLimits::UNBOUNDED)
        .expect("an unbounded inventory");
    assert_eq!(
        facts.syntax_depth(),
        GO_FACT_DEPTH,
        "the unbounded fact walk spends the depth this case writes down"
    );

    let admitted =
        StructureInventoryLimits::new(GO_FACT_DEPTH, AMPLE_STRUCTURES).expect("nonzero ceilings");
    assert!(
        facts.structure_inventory(admitted).is_ok(),
        "the depth the walk spent is admitted"
    );

    let shallow = StructureInventoryLimits::new(GO_FACT_DEPTH - 1, AMPLE_STRUCTURES)
        .expect("nonzero ceilings");
    assert_eq!(
        facts.structure_inventory(shallow),
        Err(StructureError::SyntaxDepthExceeded {
            limit: GO_FACT_DEPTH - 1
        }),
        "an inventory walked deeper than the stated ceiling is refused, not projected"
    );
}

/// The narrowed Go walk states exactly what the whole inventory states.
///
/// The structure router walks for declarations, the scopes that place them, and
/// the package clause, because that is all the projection reads. Taking the
/// same source through a retained whole-inventory walk and projecting that
/// instead must give the same rows: a narrowing that dropped the package clause
/// would shift every owner position by one, and one that dropped a declaration
/// would lose a row outright.
fn the_narrowed_go_walk_states_what_the_whole_inventory_states() {
    let parsed =
        parse_bound(STRUCTURE_GO_SOURCE, SyntaxLanguage::Go).expect("the Go grammar parses");
    let whole = parsed
        .go_file_facts(GoFactLimits::UNBOUNDED)
        .expect("an unbounded inventory");
    let projected = whole
        .structure_inventory(ample())
        .expect("the whole inventory projects a complete structure set");
    let routed = structure_inventory(STRUCTURE_GO_SOURCE, SyntaxLanguage::Go, ample())
        .expect("the routed walk states a complete structure set");
    assert_eq!(
        rows(&routed),
        rows(&projected),
        "the narrowed walk and the whole inventory state one Go structure set"
    );
}

/// One inventory's identities and the byte extents behind them.
type GoStructureRow<'source> = (StructureIdentity<'source>, u64, u64);

/// The comparable whole of one inventory.
///
/// The identity is [`identity_of`], the head every comparable row in this tree
/// shares; the byte columns are this case's own, because two walks of one source
/// must agree on the exact bytes each structure covers.
fn rows<'source>(inventory: &StructureInventory<'source>) -> Box<[GoStructureRow<'source>]> {
    inventory
        .structures()
        .iter()
        .map(|fact| {
            (
                identity_of(fact),
                fact.span().start_byte(),
                fact.span().end_byte(),
            )
        })
        .collect()
}
