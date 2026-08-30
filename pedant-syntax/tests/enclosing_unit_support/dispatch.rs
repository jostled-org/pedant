//! Backend selection: which languages this build answers for, and which it
//! does not.
//!
//! Declared by `tests/enclosing_unit.rs` with `#[path]`, for the reason stated
//! there: cargo builds one test executable per `tests/*.rs`, so a support
//! module must not become a root. This is where `rust`'s disabled contract
//! lives, because the `rust` support module only exists when the feature is on.

use pedant_syntax::{
    Location, StructureError, StructureInventoryLimits, SyntaxLanguage, enclosing_unit,
    structure_inventory,
};

use crate::fixture_support::{
    Minimal, assert_matches_row, extraction_enabled, minimal_declaration,
};
use crate::fixtures::ALL_LANGUAGES;
use crate::positions::point_of;

/// Every language answers its minimal declaration, or answers nothing, and
/// which one it does is the feature list this build was compiled with.
///
/// Both halves run in every configuration, so neither is a branch only some
/// build reaches. The enabled half also states the property
/// [`minimal_declaration`] claims for this test: line 2 sits inside the
/// declaration, so a disabled backend's `None` is absence rather than a
/// probe that missed.
#[test]
fn a_backend_answers_exactly_where_this_build_links_it() {
    for language in ALL_LANGUAGES {
        assert_minimal_declaration(language);
    }
}

/// A structure inventory refuses exactly where this build links no backend.
///
/// The same selector answers both surfaces, and the difference between their
/// answers is why the structure error exists. Extraction reports an absent
/// backend as `None`, which reads as "no declaration contains this point". An
/// inventory cannot borrow that spelling: its own empty value already means
/// "this source declares nothing", so an absent backend has to refuse by name.
///
/// Runs in every configuration, so neither half is a branch only some build
/// reaches.
#[test]
fn a_structure_inventory_refuses_by_name_where_no_backend_is_linked() {
    for language in ALL_LANGUAGES {
        let minimal = minimal_declaration(language);
        let answer = structure_inventory(
            minimal.source,
            language,
            StructureInventoryLimits::default(),
        );
        match extraction_enabled(language) {
            // Inspected rather than accepted as any `Ok`: the linked half of
            // this claim is that *this* language's backend answered. A selector
            // that dispatched to a neighbour's grammar, or one that answered a
            // source holding a declaration with an empty inventory, states
            // nothing about a backend being linked and passes an `is_ok`.
            true => {
                let inventory = answer.unwrap_or_else(|refusal| {
                    panic!(
                        "{language:?} has a backend in this configuration, so it \
                         states an inventory: {refusal}"
                    )
                });
                assert_eq!(
                    inventory.language(),
                    language,
                    "the inventory names the grammar it was read through"
                );
                assert!(
                    !inventory.structures().is_empty(),
                    "{language:?} states the declaration its minimal source writes"
                );
            }
            false => assert_eq!(
                answer.err(),
                Some(StructureError::BackendUnavailable { language }),
                "{language:?} has no backend in this configuration, so it refuses by name"
            ),
        }
    }
}

/// Assert one language's minimal declaration against this build's features.
fn assert_minimal_declaration(language: SyntaxLanguage) {
    let minimal = minimal_declaration(language);
    assert_eq!(
        enclosing_unit(
            minimal.source,
            language,
            Location {
                line: 0,
                column: None
            }
        ),
        None,
        "{language:?} rejects a zero line in every configuration"
    );

    let inside = point_of(minimal.source, minimal.target.needle);
    for at in [
        Location {
            line: 2,
            column: None,
        },
        Location {
            line: 2,
            column: Some(1),
        },
        inside.into(),
        inside.line_only(),
    ] {
        match extraction_enabled(language) {
            true => assert_target(&minimal, language, at),
            false => assert_eq!(
                enclosing_unit(minimal.source, language, at),
                None,
                "{language:?} has no backend in this configuration, so {at:?} answers nothing"
            ),
        }
    }
}

/// Assert `at` resolves the declaration the snippet writes down.
fn assert_target(minimal: &Minimal, language: SyntaxLanguage, at: Location) {
    let unit = enclosing_unit(minimal.source, language, at)
        .unwrap_or_else(|| panic!("{language:?} resolves its declaration at {at:?}"));
    assert_matches_row(&unit, &minimal.target, format_args!("{language:?} {at:?}"));
}
