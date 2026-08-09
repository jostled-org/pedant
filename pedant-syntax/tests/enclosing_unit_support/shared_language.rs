//! The shared `Language` enum's Rust variant, at this crate's boundary.
//!
//! `rust-symbol-resolution` adds `Language::Rust`, which reaches this crate as
//! one conversion arm. The claim here is only that arm: the converted token is
//! the Rust grammar, and it extracts what the Rust grammar already extracts.
//! Everything else the variant must not disturb is stated where it already
//! lives — path classification and detection exemption in `rust_is_syntax_only`,
//! and the declaration itself in the fixtures' Rust row.

/// Rust converts to the Rust grammar, and extraction through the converted
/// token answers the Rust fixture row.
pub fn rust_conversion_preserves_extraction() {
    use pedant_syntax::{Language, Location, SyntaxLanguage, enclosing_unit};

    use crate::fixture_support::{assert_matches_row, minimal_declaration};
    use crate::positions::point_of;

    let converted = SyntaxLanguage::from(Language::Rust);
    assert_eq!(
        converted,
        SyntaxLanguage::Rust,
        "the shared Rust language maps to the Rust grammar"
    );

    let minimal = minimal_declaration(converted);
    let at = Location::from(point_of(minimal.source, minimal.target.needle));
    let unit = enclosing_unit(minimal.source, converted, at)
        .expect("the converted token reaches the Rust backend");
    assert_matches_row(
        &unit,
        &minimal.target,
        format_args!("Rust via Language::Rust at {at:?}"),
    );
}
