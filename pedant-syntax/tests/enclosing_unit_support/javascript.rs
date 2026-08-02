//! JavaScript backend: recognized declarations and method precedence.

use std::path::Path;

use pedant_syntax::{LineSpan, SourceUnitKind, SyntaxLanguage};

use crate::fixtures::{JAVASCRIPT, Row};
use crate::table::{assert_rows, assert_table};

const LANGUAGE: SyntaxLanguage = SyntaxLanguage::JavaScript;

pub(crate) const ROWS: [Row; 4] = [
    Row {
        needle: "return count + 1;",
        kind: SourceUnitKind::Function,
        name: Some("build"),
        span: LineSpan { start: 3, end: 5 },
        text: "function build(count) {\n  return count + 1;\n}",
    },
    Row {
        needle: "yield limit;",
        kind: SourceUnitKind::Function,
        name: Some("stream"),
        span: LineSpan { start: 7, end: 9 },
        text: "function* stream(limit) {\n  yield limit;\n}",
    },
    // The class wins on its own header line, where no method covers it.
    Row {
        needle: "class Service {",
        kind: SourceUnitKind::Class,
        name: Some("Service"),
        span: LineSpan { start: 11, end: 16 },
        text: "class Service {\n  run(label) {\n    const greeting = `héllo ${label}`;\n    return greeting;\n  }\n}",
    },
    // The method beats the class wherever the class body holds the location.
    // The cross-cutting rules resolve this same declaration, so the fixture
    // states it once and the table names it.
    JAVASCRIPT.target,
];

#[test]
fn recognized_declaration_table() {
    assert_table(&JAVASCRIPT, &ROWS);
}

/// An `export` statement opens the declaration's text, and a method still wins.
///
/// Python widens to `decorated_definition`, Go widens to `type_declaration`,
/// and a Rust span already covers its attributes, so an exported JavaScript
/// declaration returns the statement that introduces it rather than the bare
/// node. Selection compares byte length, so the wider outer range still loses
/// to the `method_definition` inside it.
#[test]
fn an_export_statement_opens_the_returned_text() {
    let source = "export function build(count) {\n  return count + 1;\n}\n\nexport default class Service {\n  run(label) {\n    return label;\n  }\n}\n";
    assert_rows(
        source,
        LANGUAGE,
        &[
            Row {
                needle: "return count + 1;",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 3 },
                text: "export function build(count) {\n  return count + 1;\n}",
            },
            Row {
                needle: "class Service {",
                kind: SourceUnitKind::Class,
                name: Some("Service"),
                span: LineSpan { start: 5, end: 9 },
                text: "export default class Service {\n  run(label) {\n    return label;\n  }\n}",
            },
            Row {
                needle: "return label;",
                kind: SourceUnitKind::Method,
                name: Some("run"),
                span: LineSpan { start: 6, end: 8 },
                text: "run(label) {\n    return label;\n  }",
            },
        ],
    );
}

/// A `.jsx` file extracts, through the grammar its own extension names.
///
/// `.jsx` classified as unsupported until the extension arm named it, so every
/// such file answered nothing. Routing is half the claim and the grammar is the
/// other half: `.jsx` resolves to plain JavaScript rather than to a JSX dialect
/// of its own, and the plain JavaScript grammar parses a JSX-bodied function.
/// Starting from the path rather than from [`LANGUAGE`] is what joins them —
/// the row runs against whatever the path resolves to.
#[test]
fn a_jsx_path_extracts_through_the_javascript_grammar() {
    let source = "function Badge(label) {\n  return <span className=\"badge\">{label}</span>;\n}\n";
    let language = pedant_syntax::syntax_language(Path::new("web/App.jsx"), source)
        .expect("a .jsx path names a syntax language");
    assert_eq!(
        language, LANGUAGE,
        ".jsx names the plain JavaScript grammar"
    );
    assert_rows(
        source,
        language,
        &[Row {
            needle: "className",
            kind: SourceUnitKind::Function,
            name: Some("Badge"),
            span: LineSpan { start: 1, end: 3 },
            text: "function Badge(label) {\n  return <span className=\"badge\">{label}</span>;\n}",
        }],
    );
}

/// A method an object literal declares is a method, as `SourceUnitKind` states.
///
/// The grammar spells it `method_definition` wherever it appears, and the model
/// names an owning object as well as a class, so this answers rather than
/// falling through to the `const` the object initializes.
#[test]
fn an_object_literal_method_is_a_method() {
    let source = "const routes = {\n  resolve(key) {\n    return key;\n  },\n};\n";
    assert_rows(
        source,
        LANGUAGE,
        &[Row {
            needle: "return key;",
            kind: SourceUnitKind::Method,
            name: Some("resolve"),
            span: LineSpan { start: 2, end: 4 },
            text: "resolve(key) {\n    return key;\n  }",
        }],
    );
}
