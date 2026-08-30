//! Go backend: recognized declarations, grouped type specifications, and
//! method precedence over a receiver type.

use pedant_syntax::go::{GoFactError, GoFactLimits};
use pedant_syntax::{LineSpan, SourceUnitKind, SyntaxLanguage};

use crate::fixture_support::assert_absent;
use crate::fixtures::{GO, GO_SOURCE, Row};
use crate::go_fact_source::facts;
use crate::table::{assert_rows, assert_table};

const LANGUAGE: SyntaxLanguage = SyntaxLanguage::Go;

pub(crate) const ROWS: [Row; 5] = [
    // A sole ungrouped specification returns its whole declaration, so the
    // `type` keyword opens the text.
    Row {
        needle: "Retries int",
        kind: SourceUnitKind::Struct,
        name: Some("Config"),
        span: LineSpan { start: 5, end: 7 },
        text: "type Config struct {\n    Retries int\n}",
    },
    Row {
        needle: "return count + 1",
        kind: SourceUnitKind::Function,
        name: Some("build"),
        span: LineSpan { start: 13, end: 15 },
        text: "func build(count int) int {\n    return count + 1\n}",
    },
    // A receiver method is its own unit, never attributed to its receiver type.
    // The cross-cutting rules resolve this same declaration, so the fixture
    // states it once and the table names it.
    GO.target,
    // A specification inside `type (...)` returns only its own range, not the
    // whole group.
    Row {
        needle: "Name string",
        kind: SourceUnitKind::Struct,
        name: Some("Group"),
        span: LineSpan { start: 24, end: 26 },
        text: "Group struct {\n        Name string\n    }",
    },
    // An alias returns its own declaration, matching the Rust and TypeScript
    // `TypeAlias` row.
    Row {
        needle: "type Alias = int",
        kind: SourceUnitKind::TypeAlias,
        name: Some("Alias"),
        span: LineSpan { start: 33, end: 33 },
        text: "type Alias = int",
    },
];

/// The table, plus the rule that an interface's method is no unit: a signature
/// with no body would return one line in place of the declaring type.
#[test]
fn recognized_declaration_table() {
    assert_table(&GO, &ROWS);
    assert_absent(GO_SOURCE, LANGUAGE, "    Run() int");
}

/// Neither zero ceiling is a request for the crate default: both refuse the
/// first fact walk they govern.
#[test]
fn zero_go_syntax_and_fact_ceilings_refuse() {
    assert_eq!(
        facts(GO_SOURCE, GoFactLimits::new(0, u32::MAX)),
        Err(GoFactError::SyntaxDepthExceeded { limit: 0 })
    );
    assert_eq!(
        facts(GO_SOURCE, GoFactLimits::new(u32::MAX, 0)),
        Err(GoFactError::FactCapacityExceeded { limit: 0 })
    );
}

/// A non-struct specification beside a struct one stays absent, and the group
/// itself is not a unit.
#[test]
fn grouped_type_specs_are_separate_units() {
    assert_absent(GO_SOURCE, LANGUAGE, "type (");
    assert_absent(GO_SOURCE, LANGUAGE, "Mark()");
}

/// A comment before the opening parenthesis does not ungroup the specification.
///
/// The grammar admits a comment as an extra, so this declaration's children are
/// `type`, `comment`, `(`, `type_spec`, `)`. A check reading a fixed child index
/// finds the comment where it expects the parenthesis, calls the group
/// ungrouped, and widens a grouped specification's text to the whole
/// declaration — comment and parentheses included. Asking the specification for
/// a following sibling instead is what keeps this row at its own extent.
#[test]
fn a_comment_before_the_group_paren_keeps_the_spec_grouped() {
    let source = "package main\n\ntype /* note */ (\n\tA struct { x int }\n)\n";
    assert_rows(
        source,
        LANGUAGE,
        &[Row {
            needle: "x int",
            kind: SourceUnitKind::Struct,
            name: Some("A"),
            span: LineSpan { start: 4, end: 4 },
            text: "A struct { x int }",
        }],
    );
}
