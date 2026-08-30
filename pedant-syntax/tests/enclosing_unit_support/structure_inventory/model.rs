//! The public structure model, and the ceilings it is taken beneath.

use pedant_syntax::{StructureInventoryLimits, StructureKind, SyntaxLanguage};
use serde_json::json;

use crate::fixtures::declare_variants;

use super::asserts::{AMPLE_DEPTH, AMPLE_STRUCTURES, inventory_of};
use super::fixtures::{FIXTURES, STRUCTURE_RUST_SOURCE};

// Every kind the closed vocabulary states, beside its serialized spelling.
//
// One list declares both. A hand-written array beside a separate exhaustive
// match keeps compiling when the vocabulary gains a variant: the match forces a
// spelling arm, the array stays one short, and the variant is never serialized
// here at all.
declare_variants!(
    StructureKind,
    ALL_KINDS,
    kind_name,
    Module => "module",
    Function => "function",
    Method => "method",
    Struct => "struct",
    Enum => "enum",
    Union => "union",
    Trait => "trait",
    TypeAlias => "type_alias",
    Impl => "impl",
    Class => "class",
    Interface => "interface",
    DefinedType => "defined_type",
    Constant => "constant",
    Static => "static",
    Variable => "variable",
    Field => "field",
    Package => "package",
);

/// The closed kinds, the checked ceilings and their defaults, and the exact
/// accessors one structure and one inventory publish.
#[test]
fn structure_inventory_public_model_and_limits_are_exact() {
    closed_kinds_serialize_in_snake_case();
    every_kind_is_stated_by_some_fixture();
    limits_reject_a_zero_ceiling_and_default_to_the_bounded_pair();
    an_inventory_states_its_source_identity();
    a_structure_states_its_kind_name_owner_and_exact_extent();
}

/// Every kind the vocabulary declares is one some language's fixture states.
///
/// The spelling table above proves a kind can be written down and read back. It
/// cannot prove any recognizer emits one: a variant added to [`StructureKind`]
/// is forced into `declare_variants!` and into the serialization arm below, and
/// into no fixture by anything, so it would ship as vocabulary a client may send
/// and no source produces. The union of the fixture rows is what closes that,
/// the same way `enclosing_unit_support::kind_coverage` closes it for the
/// declaration model.
fn every_kind_is_stated_by_some_fixture() {
    let stated: Box<[StructureKind]> = FIXTURES
        .iter()
        .flat_map(|fixture| fixture.expected.iter().map(|row| row.kind))
        .collect();
    for kind in ALL_KINDS {
        assert!(
            stated.contains(&kind),
            "{kind:?} is a structure kind no fixture's language states"
        );
    }
}

/// The vocabulary is closed, and every variant has one lower-snake-case wire
/// spelling that decodes back to itself.
fn closed_kinds_serialize_in_snake_case() {
    let mut seen: Vec<&str> = Vec::new();
    for kind in ALL_KINDS {
        let name = kind_name(kind);
        assert!(!seen.contains(&name), "{name} is spelled once");
        seen.push(name);
        let encoded = serde_json::to_value(kind).expect("kind serializes");
        assert_eq!(encoded, json!(name), "{kind:?} serializes as {name}");
        let decoded: StructureKind = serde_json::from_value(encoded).expect("kind decodes");
        assert_eq!(decoded, kind);
    }
}

/// Both ceilings are private, checked, and default to the bounded pair.
fn limits_reject_a_zero_ceiling_and_default_to_the_bounded_pair() {
    assert_eq!(
        StructureInventoryLimits::new(0, AMPLE_STRUCTURES),
        None,
        "a zero depth admits no source"
    );
    assert_eq!(
        StructureInventoryLimits::new(AMPLE_DEPTH, 0),
        None,
        "a zero structure ceiling admits no declaration"
    );

    let limits = StructureInventoryLimits::new(7, 11).expect("nonzero ceilings");
    assert_eq!(limits.max_syntax_depth(), 7);
    assert_eq!(limits.max_structures_per_source(), 11);

    let default = StructureInventoryLimits::default();
    assert_eq!(default.max_syntax_depth(), 256);
    assert_eq!(default.max_structures_per_source(), 262_144);
    assert_eq!(
        StructureInventoryLimits::new(256, 262_144),
        Some(default),
        "the default is the checked constructor's answer for the same pair"
    );
}

/// An inventory names the grammar it was read through and the exact source its
/// spans index.
fn an_inventory_states_its_source_identity() {
    let inventory = inventory_of(STRUCTURE_RUST_SOURCE, SyntaxLanguage::Rust);
    assert_eq!(inventory.language(), SyntaxLanguage::Rust);
    assert_eq!(inventory.source(), STRUCTURE_RUST_SOURCE);
    assert!(
        std::ptr::eq(inventory.source().as_ptr(), STRUCTURE_RUST_SOURCE.as_ptr()),
        "the inventory borrows the caller's source rather than copying it"
    );
}

/// One structure publishes its kind, its optional name, its owner position, and
/// a full byte-and-line extent that slices its own source.
fn a_structure_states_its_kind_name_owner_and_exact_extent() {
    let inventory = inventory_of(STRUCTURE_RUST_SOURCE, SyntaxLanguage::Rust);
    let structures = inventory.structures();

    let module = structures.first().expect("the module opens the inventory");
    assert_eq!(module.kind(), StructureKind::Module);
    assert_eq!(module.name(), Some("inner"));
    assert_eq!(
        module.owner(),
        None,
        "no structure owns the outermost module"
    );

    let block = structures
        .iter()
        .position(|fact| fact.kind() == StructureKind::Impl)
        .expect("the fixture states an impl block");
    assert_eq!(
        structures[block].name(),
        None,
        "an impl block declares no name"
    );

    let span = structures[block].span();
    assert_eq!(
        span.byte_range(),
        span.start_byte() as usize..span.end_byte() as usize,
        "the range is exactly the pair of offsets"
    );
    assert_eq!(
        &STRUCTURE_RUST_SOURCE[span.byte_range()],
        inventory.text_of(block as u32).expect("retained text"),
        "the retained text is the span's own slice"
    );
    assert!(
        STRUCTURE_RUST_SOURCE[span.byte_range()].starts_with("impl Job {"),
        "the extent opens at the declaration"
    );
    assert_eq!(
        span.line_count(),
        span.end_line() - span.start_line() + 1,
        "the line count is the inclusive range"
    );
    assert!(
        span.strictly_contains(structures[block + 1].span()),
        "the block strictly contains the first item it owns"
    );
    assert!(
        !span.strictly_contains(span),
        "an extent does not strictly contain itself"
    );
    assert_eq!(
        inventory.text_of(structures.len() as u32),
        None,
        "a position this inventory does not hold retains no text"
    );
}
