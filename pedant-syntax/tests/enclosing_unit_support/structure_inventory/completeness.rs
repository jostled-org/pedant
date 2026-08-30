//! Each language's closed structure table, stated in full by one fixture.

use pedant_syntax::{StructureError, SyntaxLanguage, structure_inventory};

use super::asserts::{
    StructureIdentity, ample, assert_every_fixture_ran, identity_of, inventory_of, kinds_and_names,
};
use super::fixtures::{FIXTURES, StructureFixture};

/// A source per language whose declarations are all anonymous or local.
///
/// None of them is a logical structure, so each language's inventory of this
/// source holds only what the file itself is: a module for Python and the
/// ECMAScript family, and nothing at all for Rust, Go, and Bash.
///
/// A hand-written length, held to the language model by the guard that closes
/// the loop below: a seventh language is forced into `language_name` and into
/// no array, so only a set comparison notices it is missing here.
const ANONYMOUS: [(SyntaxLanguage, &str, usize); 6] = [
    (
        SyntaxLanguage::Rust,
        "fn main() {\n    let run = |value: u32| value + 1;\n    let _ = run(1);\n}\n",
        1,
    ),
    (
        SyntaxLanguage::Go,
        "package p\n\nfunc main() {\n\trun := func(value int) int { return value + 1 }\n\t_ = run\n}\n",
        2,
    ),
    (
        SyntaxLanguage::Python,
        "run = lambda value: value + 1\ntotal = run(1)\n",
        1,
    ),
    (
        SyntaxLanguage::JavaScript,
        "const run = (value) => value + 1;\nconst Job = class {};\nconst total = run(1);\n",
        1,
    ),
    (
        SyntaxLanguage::TypeScript,
        "const run = (value: number): number => value + 1;\nconst total = run(1);\n",
        1,
    ),
    (SyntaxLanguage::Bash, "value=1\necho \"${value}\"\n", 0),
];

/// Every language, beside the inventory it states for a source of no bytes.
///
/// An empty file is complete: no parser recovered anything, and it declares
/// nothing. Python and the ECMAScript family still state the file module they
/// always state, over a range of no bytes; Rust, Go, and Bash state nothing at
/// all.
///
/// Read by [`super::spans`] as well, which is the one written-down statement of
/// which walks state a file module at all: a nonzero count here is that walk
/// saying so. Its own module-extent claim is required to name every language
/// with one, so a seventh language forced into this table by
/// [`assert_every_fixture_ran`] is forced into that claim too.
pub(super) const EMPTY: [(SyntaxLanguage, usize); 6] = [
    (SyntaxLanguage::Rust, 0),
    (SyntaxLanguage::Go, 0),
    (SyntaxLanguage::Python, 1),
    (SyntaxLanguage::JavaScript, 1),
    (SyntaxLanguage::TypeScript, 1),
    (SyntaxLanguage::Bash, 0),
];

/// A source per language whose parser cannot state a complete inventory.
///
/// Held to the language model by the same guard as [`ANONYMOUS`], and for the
/// same reason: a language that gains a grammar and no malformed row here would
/// ship with its recovery refusal untested.
const MALFORMED: [(SyntaxLanguage, &str); 6] = [
    (SyntaxLanguage::Rust, "fn broken( {\n"),
    (SyntaxLanguage::Go, "package p\n\nfunc broken( {\n"),
    (SyntaxLanguage::Python, "def broken(:\n    pass\n"),
    (SyntaxLanguage::JavaScript, "function broken( {\n"),
    (SyntaxLanguage::TypeScript, "interface Broken {\n"),
    (SyntaxLanguage::Bash, "greet() {\n  echo hi\n"),
];

/// Every language's row is stated in full, in source order, with no anonymous
/// or local construct, and no recovery tree claiming completeness.
#[test]
fn six_language_structure_inventories_are_complete_source_bound_and_ordered() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for fixture in FIXTURES {
        each_row_is_stated_once_in_source_order(fixture);
        reached.push(fixture.language);
    }
    assert_every_fixture_ran(&reached);

    anonymous_and_local_constructs_are_not_structures();
    an_empty_source_states_an_empty_inventory();
    a_recovered_or_failed_parse_states_no_inventory();
}

/// One fixture states exactly its language's expected structures, in order.
///
/// The whole table is compared at once rather than field by field, so a
/// structure that moved, changed owner, or disappeared fails as one difference
/// rather than as the first assertion that happens to notice.
fn each_row_is_stated_once_in_source_order(fixture: &StructureFixture) {
    let inventory = inventory_of(fixture.source, fixture.language);
    let stated: Box<[StructureIdentity<'_>]> =
        inventory.structures().iter().map(identity_of).collect();
    let expected: Box<[StructureIdentity<'_>]> = fixture
        .expected
        .iter()
        .map(|row| (row.kind, row.name, row.owner))
        .collect();
    assert_eq!(
        stated, expected,
        "{:?} states its complete row in source order",
        fixture.language
    );

    let mut opened = 0_u64;
    for (position, fact) in inventory.structures().iter().enumerate() {
        assert!(
            fact.span().start_byte() >= opened,
            "{:?} structure {position} opens no earlier than the one before it",
            fixture.language
        );
        opened = fact.span().start_byte();
        assert!(
            fact.owner().is_none_or(|owner| (owner as usize) < position),
            "{:?} structure {position} is owned by an earlier position",
            fixture.language
        );
    }
}

/// A lambda, an arrow function, a class expression, and a local binding are not
/// logical structures in any language's row.
fn anonymous_and_local_constructs_are_not_structures() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for (language, source, expected) in ANONYMOUS {
        let inventory = inventory_of(source, language);
        assert_eq!(
            inventory.structures().len(),
            expected,
            "{language:?} states only its file-level structures: {:?}",
            kinds_and_names(&inventory)
        );
        reached.push(language);
    }
    assert_every_fixture_ran(&reached);
}

/// A source of no bytes states an empty inventory rather than a refusal.
///
/// Go is the row this was written for. Its structures are projected from a fact
/// walk that opens the file scope before it reads a node, and the fact ceiling
/// that walk runs beneath is measured from the source — so a source of zero
/// bytes handed the walk a ceiling of zero and refused it at its own base fact.
/// A valid empty Go file answered with a capacity refusal where the contract
/// states an empty inventory, and every repository holding one recorded an
/// index defect.
fn an_empty_source_states_an_empty_inventory() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for (language, expected) in EMPTY {
        let inventory = structure_inventory("", language, ample()).unwrap_or_else(|refusal| {
            panic!("{language:?} states a complete inventory of an empty source: {refusal}")
        });
        assert_eq!(
            inventory.structures().len(),
            expected,
            "{language:?} states only what an empty file itself is: {:?}",
            kinds_and_names(&inventory)
        );
        reached.push(language);
    }
    assert_every_fixture_ran(&reached);
}

/// A parser that recovered and a parser that failed each refuse.
///
/// An empty inventory would read as "this source declares nothing", which is
/// exactly the claim a recovery tree cannot support: the declarations it
/// dropped look the same as declarations the source never wrote.
fn a_recovered_or_failed_parse_states_no_inventory() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for (language, source) in MALFORMED {
        let refusal = structure_inventory(source, language, ample())
            .err()
            .unwrap_or_else(|| panic!("{language:?} refuses a source it cannot state in full"));
        // The position a failed parse may carry is not this claim: a
        // tree-sitter parser that produced no tree names no node, so only the
        // language every refusal states is compared here.
        assert!(
            matches!(
                refusal,
                StructureError::Recovered { language: refused }
                | StructureError::Unparsed { language: refused, .. }
                    if refused == language
            ),
            "{language:?} refuses by naming its own incomplete parse, not {refusal:?}"
        );
        reached.push(language);
    }
    assert_every_fixture_ran(&reached);
}
