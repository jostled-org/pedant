//! The location rules every backend shares.
//!
//! One byte column, one line-only probe, and one rejection table, run
//! against every fixture this build enables, so a backend cannot answer a
//! position question its siblings answer differently.

use pedant_syntax::{Location, SourceUnit, enclosing_unit};

use crate::fixture_support;
use crate::fixtures;
use crate::fixtures::ALL_LANGUAGES;
use crate::positions::point_of;
use crate::table::assert_rows;

/// The byte length of the multi-byte character every fixture carries.
const MULTIBYTE: usize = "é".len();

#[test]
fn all_backends_share_line_and_byte_column_rules() {
    let mut reached = 0_usize;
    for fixture in fixtures::ENABLED {
        let expected = Some(fixture_support::unit_of_row(&fixture.target));
        let at = point_of(fixture.source, fixture.target.needle);
        let multibyte = point_of(fixture.source, "é");
        let after = Location {
            line: multibyte.line,
            column: Some(multibyte.column + MULTIBYTE),
        };

        for (label, point) in [
            ("ascii", Location::from(at)),
            ("multibyte", Location::from(multibyte)),
            ("after", after),
        ] {
            assert_eq!(
                enclosing_unit(fixture.source, fixture.language, point),
                expected,
                "{:?} resolves the {label} byte column",
                fixture.language
            );
            let line_only = Location {
                line: point.line,
                column: None,
            };
            assert_eq!(
                enclosing_unit(fixture.source, fixture.language, line_only),
                expected,
                "{:?} resolves the {label} line by containment",
                fixture.language
            );
        }

        reached += 1;
    }
    fixture_support::assert_covered(reached, ALL_LANGUAGES, "extraction backend");
}

/// Neither line terminator changes the declaration, and the last line resolves
/// without one.
///
/// Every fixture source ends with a newline, so `SourceIndex`'s trailing-newline
/// branch and its `\r` strip are otherwise never exercised. Each snippet from
/// [`fixture_support::minimal_declaration`] puts the declaration's own last line last,
/// so removing the final newline leaves an unterminated line that must still
/// resolve rather than dropping off the index.
///
/// The baseline is the snippet's written-down target, not a first extraction of
/// the same source. A backend that resolves the wrong extent under every
/// terminator would satisfy a self-derived expectation; it fails this one.
#[test]
fn line_terminators_do_not_change_the_declaration() {
    let mut reached = 0_usize;
    for language in fixture_support::enabled_languages() {
        let minimal = fixture_support::minimal_declaration(language);
        let target = std::slice::from_ref(&minimal.target);
        assert_rows(minimal.source, language, target);

        let unterminated = minimal
            .source
            .strip_suffix('\n')
            .expect("every minimal declaration ends with a newline");
        assert_rows(unterminated, language, target);

        let crlf = minimal.source.replace('\n', "\r\n");
        let at = point_of(&crlf, minimal.target.needle);
        let carried = enclosing_unit(&crlf, language, at.into())
            .unwrap_or_else(|| panic!("{language:?} resolves a CRLF source"));
        // The terminators are folded before the comparison, so the text field
        // states the same declaration the other two probes state.
        let folded = SourceUnit {
            text: carried.text.replace("\r\n", "\n").into(),
            ..carried
        };
        fixture_support::assert_matches_row(
            &folded,
            &minimal.target,
            format_args!("{language:?} CRLF"),
        );
        reached += 1;
    }
    fixture_support::assert_covered(reached, ALL_LANGUAGES, "extraction backend");
}

#[test]
fn invalid_locations_return_none() {
    let mut reached = 0_usize;
    for fixture in fixtures::ENABLED {
        let at = point_of(fixture.source, fixture.target.needle);
        let multibyte = point_of(fixture.source, "é");
        let lines = fixture.source.lines().count();
        let width = fixture
            .source
            .lines()
            .nth(at.line - 1)
            .expect("the marked line exists")
            .len();

        let cases = [
            Location {
                line: 0,
                column: None,
            },
            Location {
                line: 0,
                column: Some(1),
            },
            Location {
                line: at.line,
                column: Some(0),
            },
            Location {
                line: lines + 1,
                column: None,
            },
            Location {
                line: lines + 1,
                column: Some(1),
            },
            Location {
                line: at.line,
                column: Some(width + 1),
            },
            Location {
                line: multibyte.line,
                column: Some(multibyte.column + 1),
            },
        ];

        for case in cases {
            assert_eq!(
                enclosing_unit(fixture.source, fixture.language, case),
                None,
                "{:?} rejects {case:?}",
                fixture.language
            );
        }
        reached += 1;
    }
    fixture_support::assert_covered(reached, ALL_LANGUAGES, "extraction backend");
}
