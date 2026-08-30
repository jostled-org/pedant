//! What a spent ceiling refuses, and when it refuses it.
//!
//! Every case here descends. What a ceiling means to a caller holding an
//! inventory the walk already finished is [`super::go_projection`], split off
//! for the source-file budget and because nothing in it walks.

use pedant_syntax::{
    StructureError, StructureInventory, StructureInventoryLimits, SyntaxLanguage,
    structure_inventory,
};

use super::asserts::{AMPLE_DEPTH, AMPLE_STRUCTURES, assert_every_fixture_ran};
use super::fixtures::{FIXTURES, StructureFixture};

/// The three languages whose loose sources are generated a declaration at a
/// time, and how many structures a file of theirs holds beyond its own
/// declarations.
///
/// Python states its file as a module; Rust names its modules with `mod` items
/// and Bash declares none, so both hold exactly what they declare.
const GENERATED: [(SyntaxLanguage, usize); 3] = [
    (SyntaxLanguage::Rust, 0),
    (SyntaxLanguage::Python, 1),
    (SyntaxLanguage::Bash, 0),
];

/// One source per grammar whose deepest region is written first, beside the
/// shallowest ceiling that admits it whole.
///
/// Each states three trailing declarations the leading region never reaches, so
/// the two ceilings can be exceeded together and still refuse in one order. The
/// deepest region is a nest the contract states no structure for wherever a
/// grammar allows one — Rust counts declarations rather than grammar nodes, so
/// its nest is modules.
///
/// Both numbers are written down for the reason `StructureFixture::depth`
/// states: derived by running the walk under test, either would agree with any
/// walk, and this case's whole claim is which of two ceilings that walk reaches
/// first. The structure count was read back from the subject until 2026-08-30,
/// which let a walk retaining one structure too few take its own smaller number
/// as the ceiling, admit itself at it, and refuse one below it.
///
/// The counts are what each language's row states for its own source: Python and
/// the ECMAScript family add the file module their walk always states, Rust
/// counts its five modules and the function inside them, and Go counts its
/// package clause and its `var`.
///
/// Held to the language model by the guard that closes the loop below, so a
/// seventh language cannot leave these hand-written numbers behind.
const DEEP_BEFORE_MANY: [(SyntaxLanguage, &str, u32, u32); 6] = [
    (SyntaxLanguage::Rust, RUST_DEEP_FIRST, 6, 9),
    (SyntaxLanguage::Go, GO_DEEP_FIRST, 16, 5),
    (SyntaxLanguage::Python, PYTHON_DEEP_FIRST, 15, 4),
    (SyntaxLanguage::JavaScript, JAVASCRIPT_DEEP_FIRST, 15, 4),
    (SyntaxLanguage::TypeScript, JAVASCRIPT_DEEP_FIRST, 15, 4),
    (SyntaxLanguage::Bash, BASH_DEEP_FIRST, 8, 3),
];

const RUST_DEEP_FIRST: &str = "\
mod l1 {
    mod l2 {
        mod l3 {
            mod l4 {
                mod l5 {
                    pub fn deep() {}
                }
            }
        }
    }
}

pub fn alpha() {}

pub fn bravo() {}

pub fn charlie() {}
";

const GO_DEEP_FIRST: &str = "\
package deep

var Deep = ((((((((((((1))))))))))))

func Alpha() {}

func Bravo() {}

func Charlie() {}
";

const PYTHON_DEEP_FIRST: &str = "\
DEEP = ((((((((((((1))))))))))))


def alpha():
    return 1


def bravo():
    return 1


def charlie():
    return 1
";

/// Read as JavaScript and again as TypeScript, because both grammars state the
/// same declarations for it and the claim is about the walk they share.
const JAVASCRIPT_DEEP_FIRST: &str = "\
const deep = ((((((((((((1))))))))))));

function alpha() {}

function bravo() {}

function charlie() {}
";

const BASH_DEEP_FIRST: &str = "\
if true; then
  if true; then
    if true; then
      if true; then
        if true; then
          echo 1
        fi
      fi
    fi
  fi
fi

alpha() {
  echo 1
}

bravo() {
  echo 1
}

charlie() {
  echo 1
}
";

/// A Go source stating two structures and a great many other facts.
const FACT_DENSE_GO: &str = "\
package dense

import (
\t\"fmt\"
\t\"os\"
\t\"strings\"
)

func Report() {
\ta := 1
\tb := a + 1
\tc := b + a
\td := c + b
\te := d + c
\tf := e + d
\tfmt.Println(a, b, c, d, e, f, os.Args, strings.TrimSpace(\"\"))
}
";

/// Both ceilings refuse at the first excess, before the descent or the
/// retention they bound, and neither answers with a partial inventory.
#[test]
fn loose_structure_limits_refuse_before_descent_and_retention() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for fixture in FIXTURES {
        the_structure_ceiling_refuses_the_first_excess(fixture);
        the_depth_ceiling_refuses_the_level_below_the_source(fixture);
        reached.push(fixture.language);
    }
    assert_every_fixture_ran(&reached);

    the_same_declarations_in_another_order_refuse_identically();
    the_first_excess_in_source_order_decides_which_ceiling_refuses();
    a_go_source_dense_in_facts_is_admitted_at_its_own_structure_ceiling();
}

/// A ceiling equal to the source's own inventory admits it whole; one below it
/// refuses and states that ceiling.
///
/// The inventory's size is the fixture's own written-down row count, not a
/// length read back from the walk under test. Reading it back makes both
/// assertions relative to whatever that walk produced: a walk retaining one
/// structure too few would take its own smaller number as the ceiling, admit
/// itself at it, and refuse one below it, which is the shape this case is
/// supposed to catch.
fn the_structure_ceiling_refuses_the_first_excess(fixture: &StructureFixture) {
    let (source, language) = (fixture.source, fixture.language);
    let stated = fixture.expected.len() as u32;
    assert!(stated > 1, "{language:?} declares more than one structure");

    assert_eq!(
        held(source, language, AMPLE_DEPTH, stated),
        Ok(stated),
        "{language:?} admits exactly the inventory it states"
    );
    assert_eq!(
        held(source, language, AMPLE_DEPTH, stated - 1),
        Err(StructureError::StructureCapacityExceeded { limit: stated - 1 }),
        "{language:?} refuses the first structure past its ceiling"
    );
}

/// The written-down ceiling that admits a source admits it whole; one below it
/// refuses before descending and states that ceiling.
///
/// Both halves are asserted against one number the fixture writes down. A
/// ceiling searched for by running the walk is the walk's own answer, so the
/// refusal below it says only that some level exists that this walk rejects —
/// a walk counting every level one too deep, or one too shallow, states its
/// shifted answer and passes both. Pinning the admitting ceiling is what makes
/// the level below it a claim about the source rather than about the walk.
fn the_depth_ceiling_refuses_the_level_below_the_source(fixture: &StructureFixture) {
    let (source, language, depth) = (fixture.source, fixture.language, fixture.depth);
    assert!(
        depth > 1,
        "{language:?} nests deeply enough for a level below it to exist"
    );
    assert_eq!(
        held(source, language, depth, AMPLE_STRUCTURES),
        Ok(fixture.expected.len() as u32),
        "{language:?} is admitted whole at the ceiling its fixture states"
    );
    assert_eq!(
        held(source, language, depth - 1, AMPLE_STRUCTURES),
        Err(StructureError::SyntaxDepthExceeded { limit: depth - 1 }),
        "{language:?} refuses the first level past its ceiling"
    );
}

/// Writing the same declarations in another order changes neither answer.
///
/// The ceiling is a claim about how many structures a source states, not about
/// which one arrives first. A check applied after a whole walk — by truncating
/// a finished list — would pass the same count rows above and still be a
/// different rule; reordering the source is what separates them, because a
/// truncating implementation keeps whichever declarations the walk reached
/// first and calls the result complete.
///
/// The one case table here that deliberately names three languages rather than
/// six, so `assert_every_fixture_ran` cannot close it. The guard it closes with
/// instead is [`assert_every_written_declaration_is_generated`].
fn the_same_declarations_in_another_order_refuse_identically() {
    assert_every_written_declaration_is_generated();
    for (language, beyond_declarations) in GENERATED {
        let names = ["alpha", "bravo", "charlie", "delta"];
        let forward: Box<[&str]> = Box::from(names);
        let reversed: Box<[&str]> = names.iter().rev().copied().collect();
        let stated = (names.len() + beyond_declarations) as u32;

        for order in [forward, reversed] {
            let source = generate(language, &order);
            assert_eq!(
                held(&source, language, AMPLE_DEPTH, stated),
                Ok(stated),
                "{language:?} admits every declaration in {order:?}"
            );
            assert_eq!(
                held(&source, language, AMPLE_DEPTH, stated - 1),
                Err(StructureError::StructureCapacityExceeded { limit: stated - 1 }),
                "{language:?} refuses the same excess in {order:?}"
            );
        }
    }
}

/// Whichever ceiling the walk reaches first is the one that refuses.
///
/// The other half of the order claim, and the half a count cannot make. Each
/// source below writes its deepest region before the declarations that pass the
/// structure ceiling, and is then taken beneath both ceilings at once. A walk
/// that checks depth before descending refuses in that leading region, with the
/// later declarations still unread. A walk that descended freely and compared
/// the deepest level it reached afterwards would pass every row above and fail
/// here: it would read the whole source, spend the structure ceiling on
/// declarations the first walk never reaches, and refuse with the wrong answer.
///
/// Both single-ceiling rows are asserted beside it, so the combined row is a
/// claim about which refusal comes first rather than about which ceiling is
/// exceeded at all.
///
/// Both ceilings come from the row rather than from the subject, for the reason
/// [`DEEP_BEFORE_MANY`] states: a structure count read back from the walk under
/// test is that walk's own answer, and the crowded ceiling below it is then a
/// claim about the walk rather than about the source.
fn the_first_excess_in_source_order_decides_which_ceiling_refuses() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for (language, source, admitting, stated) in DEEP_BEFORE_MANY {
        assert!(stated > 2, "{language:?} declares more than two structures");

        let deep = admitting - 1;
        let crowded = stated - 1;
        assert_eq!(
            held(source, language, deep, AMPLE_STRUCTURES),
            Err(StructureError::SyntaxDepthExceeded { limit: deep }),
            "{language:?} passes the depth ceiling on its own"
        );
        assert_eq!(
            held(source, language, AMPLE_DEPTH, crowded),
            Err(StructureError::StructureCapacityExceeded { limit: crowded }),
            "{language:?} passes the structure ceiling on its own"
        );
        assert_eq!(
            held(source, language, deep, crowded),
            Err(StructureError::SyntaxDepthExceeded { limit: deep }),
            "{language:?} refuses at the deep region it reads first, not at the \
             declarations behind it"
        );
        assert_eq!(
            held(source, language, admitting, AMPLE_STRUCTURES),
            Ok(stated),
            "{language:?} is admitted whole at the ceiling this row states, so the \
             refusal above is the level below it"
        );
        reached.push(language);
    }
    assert_every_fixture_ran(&reached);
}

/// A Go source stating many facts and few structures is admitted whole.
///
/// The Go row is the one taken through another inventory: its structures are
/// projected from the fact walk this crate already owns. That walk's ceiling
/// counts imports, references, scopes, and bindings, none of which this
/// contract publishes, so a fact ceiling taken from the structure ceiling would
/// refuse this source long before its second structure — while the structure
/// ceiling it is actually taken beneath admits it at exactly two.
fn a_go_source_dense_in_facts_is_admitted_at_its_own_structure_ceiling() {
    let stated = 2;
    assert_eq!(
        held(FACT_DENSE_GO, SyntaxLanguage::Go, AMPLE_DEPTH, stated),
        Ok(stated),
        "Go admits a fact-dense source at the ceiling its structures need"
    );
    assert_eq!(
        held(FACT_DENSE_GO, SyntaxLanguage::Go, AMPLE_DEPTH, stated - 1),
        Err(StructureError::StructureCapacityExceeded { limit: stated - 1 }),
        "the ceiling it is refused at is still the structure ceiling"
    );
}

/// How many structures one source states beneath a given pair of ceilings.
///
/// A refusal carries the error and no inventory, so a count here is only ever
/// read from a walk that completed.
fn held(
    source: &str,
    language: SyntaxLanguage,
    depth: u32,
    structures: u32,
) -> Result<u32, StructureError> {
    let limits = StructureInventoryLimits::new(depth, structures).expect("nonzero ceilings");
    structure_inventory(source, language, limits).map(count)
}

/// The size of one completed inventory.
fn count(inventory: StructureInventory<'_>) -> u32 {
    inventory.structures().len() as u32
}

/// One source declaring `names`, in that order, in `language`.
///
/// Built once and only ever borrowed as text, so it is owned as the immutable
/// string it is rather than as one still holding room to grow.
fn generate(language: SyntaxLanguage, names: &[&str]) -> Box<str> {
    names
        .iter()
        .map(|name| {
            declaration(language, name)
                .unwrap_or_else(|| panic!("{language:?} states a generated declaration"))
        })
        .collect()
}

/// [`GENERATED`] names exactly the languages [`declaration`] writes one for.
///
/// The two were hand-kept lists with nothing binding them. A language given a
/// declaration here and no row there is never taken through the reordering
/// claim at all; a row there whose language this refuses reaches a panic instead
/// of an assertion. Asked over the whole language model, so a seventh language
/// is caught in both directions, and by an equality rather than a containment,
/// so a table naming one language twice fails too.
fn assert_every_written_declaration_is_generated() {
    for language in crate::fixtures::ALL_LANGUAGES {
        assert_eq!(
            GENERATED.iter().filter(|(it, _)| *it == language).count(),
            usize::from(declaration(language, "alpha").is_some()),
            "{language:?} is generated once by this table exactly when a declaration \
             is written for it"
        );
    }
}

/// One declaration, written the way its language writes one.
///
/// Absent for a language this module generates no source for. An answer rather
/// than a panic, so the guard above can read the arms that answer and compare
/// them with [`GENERATED`]'s own rows. Exhaustive, so a seventh language fails
/// to compile here rather than falling into a catch-all.
fn declaration(language: SyntaxLanguage, name: &str) -> Option<String> {
    match language {
        SyntaxLanguage::Rust => Some(format!("pub fn {name}() -> u32 {{\n    1\n}}\n\n")),
        SyntaxLanguage::Python => Some(format!("def {name}():\n    return 1\n\n\n")),
        SyntaxLanguage::Bash => Some(format!("{name}() {{\n  echo 1\n}}\n\n")),
        SyntaxLanguage::Go
        | SyntaxLanguage::JavaScript
        | SyntaxLanguage::TypeScript
        | SyntaxLanguage::Tsx => None,
    }
}
