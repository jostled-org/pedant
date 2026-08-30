//! Exact extents and the owner forest they form.

use pedant_syntax::{StructureFact, StructureInventory, StructureKind, SyntaxLanguage};

use super::asserts::{
    assert_every_fixture_ran, identity_of, inventory_of, kinds_and_names, line_at,
};
use super::fixtures::FIXTURES;

/// Rust identifiers, text, and an emoji past the basic multilingual plane.
///
/// The Rust backend is the one that converts a parser's *character* columns
/// into byte offsets, so a source whose characters and bytes disagree is where
/// a confusion between the two stops being invisible.
const RUST_MULTIBYTE: &str = "\
pub struct Grüße {
    wert: u32,
}

pub fn grüßen() -> &'static str {
    \"Grüße 🌍\"
}
";

/// The same disagreement in a grammar whose nodes already carry byte ranges.
const PYTHON_MULTIBYTE: &str = "\
class Grüße:
    def grüßen(self):
        return \"Grüße 🌍\"
";

/// A Rust source opening with a byte-order mark.
///
/// `syn` strips the mark before it lexes, so every position it reports counts
/// from the byte after it. A span published against the source the caller
/// handed in has to carry those three bytes back; without them every extent
/// slices three bytes early, which is a name that opens one identifier in and a
/// body that stops before its closing brace — never an error.
///
/// Rust alone, because it is the one backend that discards a prefix: a
/// tree-sitter grammar indexes the source as given.
const RUST_BOM: &str = "\u{feff}pub struct Marked {
    wert: u32,
}

pub fn marked() -> u32 {
    1
}
";

/// A source per module-stating grammar that is exactly one declaration, with no
/// terminator after it.
///
/// The file module's extent is the whole source, and with no trailing newline
/// the sole declaration's extent is the whole source too. Two structures at one
/// extent state no ownership between them, so the module has nothing to own and
/// stands down; a terminator is what usually hides the case, because it lands
/// inside the module and outside the declaration.
///
/// One row per module-stating grammar, not one per family: the module is settled
/// by the walk they share, and the declaration beside it comes from a different
/// recognizer in each. Which grammars those are is not restated here — the
/// empty-source table states it, and
/// [`assert_every_module_stating_language_is_read`] holds this list to it.
const SOLE_UNTERMINATED_DECLARATION: [(SyntaxLanguage, &str); 3] = [
    (SyntaxLanguage::Python, "def build():\n    return 1"),
    (
        SyntaxLanguage::JavaScript,
        "function build() {\n  return 1;\n}",
    ),
    (
        SyntaxLanguage::TypeScript,
        "function build(): number {\n  return 1;\n}",
    ),
];

/// Every span slices its source exactly, its lines agree with that slice, and
/// the owner links form one acyclic forest inside one file.
#[test]
fn structure_spans_and_owner_forests_are_exact_for_lf_and_crlf() {
    let mut reached: Vec<SyntaxLanguage> = Vec::new();
    for fixture in FIXTURES {
        spans_and_owners_are_exact(fixture.source, fixture.language);
        the_same_source_in_crlf_states_the_same_structures(fixture.source, fixture.language);
        reached.push(fixture.language);
    }
    assert_every_fixture_ran(&reached);

    multibyte_text_does_not_shift_a_byte_offset();
    nested_equal_names_stay_distinct_structures();
    a_stripped_byte_order_mark_does_not_shift_a_span();
    a_sole_unterminated_declaration_is_owned_by_nothing_of_its_own_extent();
}

/// Every span slices, every line pair agrees with that slice, and every owner
/// strictly contains what it owns without any nearer owner existing.
fn spans_and_owners_are_exact(source: &str, language: SyntaxLanguage) {
    let inventory = inventory_of(source, language);
    let structures = inventory.structures();
    // The loop below asserts once per structure, so a source stating none
    // asserts nothing at all and reports a pass — the guard `table.rs` already
    // carries over its own rows.
    assert!(
        !structures.is_empty(),
        "{language:?} states at least one structure to check the extents of"
    );
    for (position, fact) in structures.iter().enumerate() {
        let span = fact.span();
        let sliced = source
            .get(span.byte_range())
            .unwrap_or_else(|| panic!("{language:?} structure {position} slices its source"));
        assert!(
            !sliced.is_empty(),
            "{language:?} structure {position} covers at least one byte"
        );
        if let Some(name) = fact.name() {
            assert!(
                sliced.contains(name),
                "{language:?} structure {position} contains the name it declares"
            );
        }

        let last = span.end_byte().saturating_sub(1).max(span.start_byte());
        assert_eq!(
            span.start_line(),
            line_at(source, span.start_byte() as usize),
            "{language:?} structure {position} opens on the line its first byte sits on"
        );
        assert_eq!(
            span.end_line(),
            line_at(source, last as usize),
            "{language:?} structure {position} closes on the line its last byte sits on"
        );
        assert_eq!(
            span.line_count(),
            span.end_line() - span.start_line() + 1,
            "{language:?} structure {position} counts its inclusive lines"
        );

        assert_nearest_owner(structures, position, language);
    }
}

/// One structure's owner is the nearest structure that strictly contains it.
fn assert_nearest_owner(
    structures: &[StructureFact<'_>],
    position: usize,
    language: SyntaxLanguage,
) {
    let span = structures[position].span();
    let nearest = structures
        .iter()
        .enumerate()
        .filter(|(candidate, fact)| *candidate != position && fact.span().strictly_contains(span))
        .min_by_key(|(_, fact)| fact.span().end_byte() - fact.span().start_byte())
        .map(|(candidate, _)| candidate as u32);
    assert_eq!(
        structures[position].owner(),
        nearest,
        "{language:?} structure {position} names the nearest structure containing it"
    );
}

/// The same source written with CRLF endings states the same structures on the
/// same lines.
///
/// Byte offsets legitimately move, because the source is longer. Kinds, names,
/// owners, and lines are claims about the declaration rather than about the
/// terminator, so all four must be identical.
fn the_same_source_in_crlf_states_the_same_structures(source: &str, language: SyntaxLanguage) {
    // Rewritten once and only ever borrowed as text, so the buffer is owned as
    // the immutable string it is rather than as one still open for appending.
    let crlf: Box<str> = source.replace('\n', "\r\n").into();
    let expected = rows(&inventory_of(source, language));
    let observed = rows(&inventory_of(&crlf, language));
    assert_eq!(
        observed, expected,
        "{language:?} states the same structures on the same lines under CRLF"
    );
}

/// One structure's kind, name, owner, and inclusive line range.
///
/// Everything a line terminator must not change, and nothing it may: byte
/// offsets are absent because CRLF legitimately moves them.
///
/// The name is owned rather than borrowed, because the two inventories compared
/// here read two different strings — this is the one row type that cannot carry
/// the shared borrowed identity as it stands.
type LineBoundRow = (StructureKind, Option<Box<str>>, Option<u32>, u32, u32);

/// The comparable half of one inventory.
///
/// The head is [`identity_of`], the one this tree shares; the line columns are
/// this case's own.
fn rows(inventory: &StructureInventory<'_>) -> Box<[LineBoundRow]> {
    inventory
        .structures()
        .iter()
        .map(|fact| {
            let (kind, name, owner) = identity_of(fact);
            (
                kind,
                name.map(Box::from),
                owner,
                fact.span().start_line(),
                fact.span().end_line(),
            )
        })
        .collect()
}

/// A span is a byte offset, not a character offset.
fn multibyte_text_does_not_shift_a_byte_offset() {
    for (language, source, opener) in [
        (SyntaxLanguage::Rust, RUST_MULTIBYTE, "pub struct Grüße {"),
        (SyntaxLanguage::Python, PYTHON_MULTIBYTE, "class Grüße:"),
    ] {
        let inventory = inventory_of(source, language);
        let declared = inventory
            .structures()
            .iter()
            .find(|fact| fact.name() == Some("Grüße"))
            .unwrap_or_else(|| panic!("{language:?} declares the multibyte name"));
        let sliced = &source[declared.span().byte_range()];
        assert!(
            sliced.starts_with(opener),
            "{language:?} slices the declaration exactly, not {sliced:?}"
        );

        let member = inventory
            .structures()
            .iter()
            .find(|fact| fact.name() == Some("grüßen"))
            .unwrap_or_else(|| panic!("{language:?} declares the multibyte member"));
        assert!(
            source[member.span().byte_range()].contains("Grüße 🌍"),
            "{language:?} keeps a four-byte code point inside the member it belongs to"
        );
        assert_eq!(
            member.span().start_line(),
            line_at(source, member.span().start_byte() as usize),
            "{language:?} counts lines rather than characters"
        );
    }
}

/// Two declarations sharing a name at two sites stay two structures.
///
/// The Rust fixture declares `Output` and `run` once in a trait and once in the
/// impl that satisfies it. Merging equal names would report one site's
/// declaration as the other's.
fn nested_equal_names_stay_distinct_structures() {
    let inventory = inventory_of(super::fixtures::STRUCTURE_RUST_SOURCE, SyntaxLanguage::Rust);
    for name in ["Output", "run"] {
        let sites: Box<[_]> = inventory
            .structures()
            .iter()
            .filter(|fact| fact.name() == Some(name))
            .collect();
        assert_eq!(sites.len(), 2, "{name} is declared at two sites");
        assert_ne!(
            sites[0].span(),
            sites[1].span(),
            "{name}'s two declarations keep their own extents"
        );
        assert_ne!(
            sites[0].owner(),
            sites[1].owner(),
            "{name}'s two declarations keep their own owners"
        );
    }
}

/// A span indexes the source the caller handed in, not the one its parser saw.
///
/// The Rust backend hands `syn` a source with the byte-order mark removed,
/// because `syn` counts its own positions from there. Everything published then
/// has to be counted back against the caller's bytes: an inventory that borrows
/// the stripped text instead states extents that slice three bytes early, and
/// three bytes early is still a valid slice, so nothing refuses.
///
/// The whole extent claim is re-asked over this source rather than a name or two
/// spot-checked, because the shift is uniform: it moves every span by the same
/// three bytes, and only the byte-to-line agreement and the owner geometry
/// notice a whole inventory sliding at once.
fn a_stripped_byte_order_mark_does_not_shift_a_span() {
    let inventory = inventory_of(RUST_BOM, SyntaxLanguage::Rust);
    assert_eq!(
        inventory.source(),
        RUST_BOM,
        "the inventory publishes the source it was given, mark and all"
    );
    spans_and_owners_are_exact(RUST_BOM, SyntaxLanguage::Rust);

    for (name, opener) in [
        ("Marked", "pub struct Marked {"),
        ("marked", "pub fn marked() -> u32 {"),
    ] {
        let declared = inventory
            .structures()
            .iter()
            .find(|fact| fact.name() == Some(name))
            .unwrap_or_else(|| panic!("the marked source declares {name}"));
        let sliced = &RUST_BOM[declared.span().byte_range()];
        assert!(
            sliced.starts_with(opener),
            "{name} slices the original bytes rather than the stripped ones, not {sliced:?}"
        );
    }
}

/// A file module does not stand beside a declaration holding its own extent.
///
/// Every other source hides this behind its terminator: the trailing newline
/// belongs to the file module and to no declaration, so the module strictly
/// contains whatever it holds. Strip the terminator from a source that is one
/// declaration and the two extents become identical, at which point the module
/// owns nothing — an owner equal to its child is one structure recognized twice,
/// which is exactly what an owner forest must not admit. So the module stands
/// down, and the declaration is the whole inventory.
///
/// The same source with its terminator restored is asserted beside it, so this
/// is a claim about the extent rather than about the language: both rows state a
/// module the moment there is one byte for it to hold and the declaration not
/// to.
fn a_sole_unterminated_declaration_is_owned_by_nothing_of_its_own_extent() {
    assert_every_module_stating_language_is_read();
    for (language, source) in SOLE_UNTERMINATED_DECLARATION {
        let inventory = inventory_of(source, language);
        let structures = inventory.structures();
        assert_eq!(
            structures.len(),
            1,
            "{language:?} states the declaration alone, with no module at its own extent: {:?}",
            kinds_and_names(&inventory)
        );
        assert_eq!(
            structures[0].kind(),
            StructureKind::Function,
            "{language:?} recognizes the one declaration its source writes"
        );
        assert_eq!(
            structures[0].span().byte_range(),
            0..source.len(),
            "{language:?} writes a declaration reaching the source's last byte, \
             which is what leaves the module nothing to own"
        );
        spans_and_owners_are_exact(source, language);

        let terminated: Box<str> = format!("{source}\n").into();
        let restored = inventory_of(&terminated, language);
        assert_eq!(
            restored.structures().first().map(|fact| fact.kind()),
            Some(StructureKind::Module),
            "{language:?} states its file module again once one byte sits outside \
             the declaration"
        );
        spans_and_owners_are_exact(&terminated, language);
    }
}

/// [`SOLE_UNTERMINATED_DECLARATION`] names every language whose walk states a
/// file module, and no other.
///
/// A fixed list of two rows was the shape this claim shipped in, and it left
/// TypeScript — a language whose walk states the module the claim is about —
/// unread, with nothing to notice. The set is not restated here either: a walk
/// states a file module exactly when its inventory of an empty source is not
/// empty, and `completeness::EMPTY` writes that number down per language. So the
/// requirement is read from there, and an equality rather than a containment, so
/// a language named twice fails too.
fn assert_every_module_stating_language_is_read() {
    for (language, empty) in super::completeness::EMPTY {
        let read = SOLE_UNTERMINATED_DECLARATION
            .iter()
            .filter(|(it, _)| *it == language)
            .count();
        assert_eq!(
            read,
            usize::from(empty > 0),
            "{language:?} is read once by this claim exactly when its walk states \
             a file module"
        );
    }
}
