//! The written-down session claim, and the one probe that asserts it.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. Every case parses one source once and then asks that same session
//! every question, so a second parse would have to appear in production code
//! rather than in the probe.
//!
//! `session_cases` states the sources and their expectations; this module
//! states what asserting one of them means.

use pedant_syntax::tree_sitter::{ParsedSyntax, parse_bound};
use pedant_syntax::{Location, SourceUnitKind, SyntaxLanguage};

use crate::fixture_support::{extraction_enabled, minimal_declaration, tree_sitter_languages};
use crate::positions::point_of;

/// One declaration an anchor must name, written down field by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anchored {
    pub(crate) kind: SourceUnitKind,
    pub(crate) name: &'static str,
    /// One-based line of the declaration's first byte.
    pub(crate) line: usize,
    /// One-based UTF-8 byte column of the declaration's first byte.
    pub(crate) column: usize,
}

/// One probe: a unique needle, and the declaration that must own it.
pub(crate) struct Probe {
    pub(crate) needle: &'static str,
    /// `None` states that no recognized declaration holds the needle.
    pub(crate) owner: Option<Anchored>,
}

/// One language's session case.
pub(crate) struct SessionCase {
    pub(crate) language: SyntaxLanguage,
    pub(crate) source: &'static str,
    /// The declaration owning the source's single multi-byte code point.
    pub(crate) code_point_owner: Anchored,
    /// Every other written-down probe.
    pub(crate) probes: &'static [Probe],
    /// A source this grammar recovers from, leaving error nodes in the tree.
    pub(crate) broken: &'static str,
    /// A needle inside `broken` whose anchor must still be absent.
    pub(crate) broken_needle: &'static str,
}

/// Every written-down claim one language's session makes.
///
/// One `parse_bound` call answers every question below. A helper that needed
/// its own session would have to parse a second time, which is the thing this
/// case exists to rule out.
pub(crate) fn assert_session_case(case: &SessionCase) {
    let language = case.language;
    let parsed = parse_bound(case.source, language)
        .unwrap_or_else(|| panic!("{language:?} links a grammar and parses its case source"));

    assert!(
        !parsed.has_errors(),
        "{language:?} case source parses without recovery"
    );
    assert_eq!(
        parsed.root().end_byte(),
        case.source.len(),
        "{language:?} binds the tree to the whole case source"
    );

    for probe in case.probes {
        let at = point_of(case.source, probe.needle);
        assert_anchor(&parsed, language, at.into(), probe.owner, probe.needle);
    }

    assert_code_point_boundary(&parsed, case);
    assert_unaddressable_locations_are_absent(&parsed, case);
    assert_repeated_query_is_identical(&parsed, case);
    assert_error_tree_is_absent(case);
}

/// The multi-byte code point fixes both the byte column and its interior.
fn assert_code_point_boundary(parsed: &ParsedSyntax<'_>, case: &SessionCase) {
    let at = point_of(case.source, "é");
    assert_anchor(
        parsed,
        case.language,
        at.into(),
        Some(case.code_point_owner),
        "é",
    );

    let inside = Location {
        line: at.line,
        column: Some(at.column + 1),
    };
    assert_anchor(parsed, case.language, inside, None, "inside é");
}

/// A location the source cannot address answers nothing, whatever holds it.
fn assert_unaddressable_locations_are_absent(parsed: &ParsedSyntax<'_>, case: &SessionCase) {
    let past_end = case.source.lines().count() + 10;
    for (at, label) in [
        (
            Location {
                line: 0,
                column: None,
            },
            "zero line",
        ),
        (
            Location {
                line: 0,
                column: Some(1),
            },
            "zero line with a column",
        ),
        (
            Location {
                line: 1,
                column: Some(0),
            },
            "zero column",
        ),
        (
            Location {
                line: past_end,
                column: None,
            },
            "line past the source",
        ),
        (
            Location {
                line: 1,
                column: Some(10_000),
            },
            "column past its line",
        ),
    ] {
        assert_anchor(parsed, case.language, at, None, label);
    }
}

/// One session answers the same question the same way every time.
fn assert_repeated_query_is_identical(parsed: &ParsedSyntax<'_>, case: &SessionCase) {
    let at: Location = point_of(case.source, "é").into();
    let first = parsed.enclosing_unit_anchor(at);
    assert!(
        first.is_some(),
        "{:?} resolves an anchor to repeat",
        case.language
    );
    for pass in 2..=3 {
        assert_eq!(
            parsed.enclosing_unit_anchor(at),
            first,
            "{:?} pass {pass} repeats the first anchor",
            case.language
        );
    }
}

/// A recovery tree binds, reports its errors, and anchors nothing.
fn assert_error_tree_is_absent(case: &SessionCase) {
    let language = case.language;
    let parsed = parse_bound(case.broken, language)
        .unwrap_or_else(|| panic!("{language:?} recovers a tree from its broken source"));
    assert!(
        parsed.has_errors(),
        "{language:?} broken source must leave error nodes in the tree"
    );
    let at: Location = point_of(case.broken, case.broken_needle).into();
    assert_eq!(
        parsed.enclosing_unit_anchor(at),
        None,
        "{language:?} anchors nothing in an error-bearing tree"
    );
}

/// Assert one location's anchor against a written-down expectation.
fn assert_anchor(
    parsed: &ParsedSyntax<'_>,
    language: SyntaxLanguage,
    at: Location,
    owner: Option<Anchored>,
    label: &str,
) {
    let anchor = parsed.enclosing_unit_anchor(at);
    let actual = anchor.as_ref().map(|anchor| {
        (
            anchor.kind,
            anchor.name.as_deref(),
            anchor.start.line,
            anchor.start.column,
        )
    });
    let expected =
        owner.map(|owner| (owner.kind, Some(owner.name), owner.line, Some(owner.column)));
    assert_eq!(
        actual, expected,
        "{language:?} anchor at {label:?} ({at:?})"
    );
}

/// Rust selects no tree-sitter grammar in any build, so it binds no session.
pub(crate) fn assert_rust_binds_no_session() {
    let minimal = minimal_declaration(SyntaxLanguage::Rust);
    assert_eq!(
        parse_bound(minimal.source, SyntaxLanguage::Rust).map(|_| ()),
        None,
        "Rust parses through syn and binds no tree-sitter session"
    );
}

/// A grammar this build omits binds nothing rather than falling back.
pub(crate) fn assert_disabled_grammars_bind_nothing() {
    for language in tree_sitter_languages().filter(|language| !extraction_enabled(*language)) {
        let minimal = minimal_declaration(language);
        assert_eq!(
            parse_bound(minimal.source, language).map(|_| ()),
            None,
            "{language:?} has no grammar in this build and binds no session"
        );
    }
}
