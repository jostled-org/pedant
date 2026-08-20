//! Backend selection: which languages this build answers for, and which it
//! does not.
//!
//! Declared by `tests/enclosing_unit.rs` with `#[path]`, for the reason stated
//! there: cargo builds one test executable per `tests/*.rs`, so a support
//! module must not become a root. This is where `rust`'s disabled contract
//! lives, because the `rust` support module only exists when the feature is on.

use pedant_syntax::{Location, SyntaxLanguage, enclosing_unit};

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
