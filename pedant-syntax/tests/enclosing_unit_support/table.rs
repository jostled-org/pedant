//! The recognized-declaration table driver, shared by the backend modules.
//!
//! The rows themselves are [`crate::fixtures::Row`], because a fixture's target
//! and a table's rows are the same written-down statement. This module only
//! drives them.

use pedant_syntax::{SyntaxLanguage, enclosing_unit};

use crate::fixture_support::{assert_absent, assert_matches_row};
use crate::fixtures::{Fixture, Row};
use crate::positions::point_of;

/// Assert a fixture's whole declaration table: every row resolves, and the
/// line the fixture names outside every declaration resolves to nothing.
///
/// The fixture owns the source, the language, and the absent line, so a
/// backend module states none of them a second time.
pub fn assert_table(fixture: &Fixture, rows: &[Row]) {
    assert_rows(fixture.source, fixture.language, rows);
    assert_absent(fixture.source, fixture.language, fixture.outside);
}

/// Assert every row resolves by exact point and by line containment.
///
/// An empty table is a defect, not a pass: the caller's rows describe the
/// declarations its backend must recognize.
///
/// Public because a backend case that names its own source rather than its
/// fixture's asks exactly this. Every message names the language, because one
/// test may run two tables whose rows share a needle.
pub fn assert_rows(source: &str, language: SyntaxLanguage, rows: &[Row]) {
    assert!(
        !rows.is_empty(),
        "{language:?} names at least one recognized declaration"
    );
    for row in rows {
        let at = point_of(source, row.needle);
        let unit = enclosing_unit(source, language, at.into())
            .unwrap_or_else(|| panic!("{language:?} resolves a declaration at {:?}", row.needle));
        assert_matches_row(&unit, row, format_args!("{language:?} {}", row.needle));

        assert_eq!(
            enclosing_unit(source, language, at.line_only()).as_ref(),
            Some(&unit),
            "{language:?} {} resolves the same declaration by line",
            row.needle
        );
    }
}
