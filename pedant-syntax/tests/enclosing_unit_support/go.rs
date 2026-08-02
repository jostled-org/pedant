//! Go backend: recognized declarations, grouped type specifications, and
//! method precedence over a receiver type.

use pedant_syntax::{LineSpan, SourceUnitKind, SyntaxLanguage};

use crate::fixture_support::assert_absent;
use crate::fixtures::{GO, GO_SOURCE, Row};
use crate::table::{assert_rows, assert_table};

const LANGUAGE: SyntaxLanguage = SyntaxLanguage::Go;

pub(crate) const ROWS: [Row; 4] = [
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
];

/// The table, plus both halves of the rule that a type specification is a unit
/// only when it declares a struct: an interface is not one, and neither is an
/// alias.
#[test]
fn recognized_declaration_table() {
    assert_table(&GO, &ROWS);
    assert_absent(GO_SOURCE, LANGUAGE, "    Run() int");
    assert_absent(GO_SOURCE, LANGUAGE, "type Alias = int");
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
