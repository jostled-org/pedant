//! TypeScript and TSX backends: the shared declaration set, the abstract
//! class, and the one-way dialect boundary between the two grammars.

use pedant_syntax::{LineSpan, SourceUnitKind, SyntaxLanguage, enclosing_unit};

use crate::fixture_support::unit_of_row;
use crate::fixtures::{Row, TSX, TSX_SOURCE, TYPESCRIPT, TYPESCRIPT_SOURCE};
use crate::positions::point_of;
use crate::table::{assert_rows, assert_table};

pub(crate) const ROWS: [Row; 6] = [
    Row {
        needle: "return count + 1;",
        kind: SourceUnitKind::Function,
        name: Some("build"),
        span: LineSpan { start: 3, end: 5 },
        text: "function build(count: number): number {\n  return count + 1;\n}",
    },
    Row {
        needle: "yield limit;",
        kind: SourceUnitKind::Function,
        name: Some("stream"),
        span: LineSpan { start: 7, end: 9 },
        text: "function* stream(limit: number) {\n  yield limit;\n}",
    },
    // `abstract_class_declaration`, the one node kind TypeScript adds to the
    // JavaScript set. The needle sits on the abstract member, which is a
    // structure the shared table names and a unit this model does not — see
    // `an_abstract_member_reads_as_the_class_that_declares_it`.
    Row {
        needle: "abstract name(): string;",
        kind: SourceUnitKind::Class,
        name: Some("Service"),
        span: LineSpan { start: 11, end: 18 },
        text: "abstract class Service {\n  abstract name(): string;\n\n  run(label: string): string {\n    const greeting = `héllo ${label}`;\n    return greeting;\n  }\n}",
    },
    // The method beats the abstract class wherever its body holds the location.
    // The cross-cutting rules resolve this same declaration, so the fixture
    // states it once and the table names it.
    TYPESCRIPT.target,
    Row {
        needle: "class Plain {",
        kind: SourceUnitKind::Class,
        name: Some("Plain"),
        span: LineSpan { start: 20, end: 24 },
        text: "class Plain {\n  ping(): number {\n    return 1;\n  }\n}",
    },
    Row {
        needle: "return 1;",
        kind: SourceUnitKind::Method,
        name: Some("ping"),
        span: LineSpan { start: 21, end: 23 },
        text: "ping(): number {\n    return 1;\n  }",
    },
];

/// The same six declarations as [`ROWS`], under the JSX dialect.
pub(crate) const TSX_ROWS: [Row; 6] = [
    Row {
        needle: "return <span",
        kind: SourceUnitKind::Function,
        name: Some("Badge"),
        span: LineSpan { start: 3, end: 5 },
        text: "function Badge(label: string) {\n  return <span className=\"badge\">{label}</span>;\n}",
    },
    Row {
        needle: "yield <hr",
        kind: SourceUnitKind::Function,
        name: Some("frames"),
        span: LineSpan { start: 7, end: 9 },
        text: "function* frames(limit: number) {\n  yield <hr key={limit} />;\n}",
    },
    Row {
        needle: "abstract title(): string;",
        kind: SourceUnitKind::Class,
        name: Some("Panel"),
        span: LineSpan { start: 11, end: 18 },
        text: "abstract class Panel {\n  abstract title(): string;\n\n  render(label: string) {\n    const greeting = `héllo ${label}`;\n    return <div title={greeting} />;\n  }\n}",
    },
    // As above, stated once on the TSX fixture.
    TSX.target,
    Row {
        needle: "class Plain {",
        kind: SourceUnitKind::Class,
        name: Some("Plain"),
        span: LineSpan { start: 20, end: 24 },
        text: "class Plain {\n  icon() {\n    return <i />;\n  }\n}",
    },
    Row {
        needle: "return <i />;",
        kind: SourceUnitKind::Method,
        name: Some("icon"),
        span: LineSpan { start: 21, end: 23 },
        text: "icon() {\n    return <i />;\n  }",
    },
];

#[test]
fn recognized_declaration_table() {
    assert_table(&TYPESCRIPT, &ROWS);
    assert_table(&TSX, &TSX_ROWS);
}

/// An abstract member is a structure, and it is not a source unit.
///
/// One grammar table serves both readers, and the unit model is the narrower
/// of the two: `abstract run(): number;` is recognized as a method, the
/// structure inventory states it as one, and a unit carries the declaration's
/// own text. A signature with no body would return a single line in place of
/// the type that declares it, so the reader gets the abstract class instead —
/// the answer a Go interface method already gives.
///
/// Written down rather than left to the table above, because the table's row
/// resolves the abstract class for its own reason and would keep passing if
/// the narrowing were dropped and the class simply won on extent.
#[test]
fn an_abstract_member_reads_as_the_class_that_declares_it() {
    let source = "abstract class Service {\n  abstract name(): string;\n}\n";
    for language in [SyntaxLanguage::TypeScript, SyntaxLanguage::Tsx] {
        assert_rows(
            source,
            language,
            &[Row {
                needle: "abstract name(): string;",
                kind: SourceUnitKind::Class,
                name: Some("Service"),
                span: LineSpan { start: 1, end: 3 },
                text: "abstract class Service {\n  abstract name(): string;\n}",
            }],
        );
    }
}

/// A decorator opens the declaration it decorates, in both dialects.
///
/// The grammar states a class decorator two ways: as a child of the
/// `class_declaration` when the class is bare, and as a sibling under the
/// `export_statement` when it is exported. A member decorator is a sibling
/// inside the `class_body`. All three open the text, as a Python decorator and
/// a Rust attribute already do.
///
/// A member states more than one decorator as a run of siblings, and the text
/// opens at the first of the run, not the nearest. One decorator makes the
/// walk's every step look alike, so the stacked source states the recursion.
#[test]
fn decorators_and_exports_open_the_returned_text() {
    let single = "@Component({ selector: \"panel\" })\nexport class Panel {\n  @Input()\n  run(label: string): string {\n    return label;\n  }\n}\n";
    let single_rows = [
        Row {
            needle: "selector",
            kind: SourceUnitKind::Class,
            name: Some("Panel"),
            span: LineSpan { start: 1, end: 7 },
            text: "@Component({ selector: \"panel\" })\nexport class Panel {\n  @Input()\n  run(label: string): string {\n    return label;\n  }\n}",
        },
        Row {
            needle: "return label;",
            kind: SourceUnitKind::Method,
            name: Some("run"),
            span: LineSpan { start: 3, end: 6 },
            text: "@Input()\n  run(label: string): string {\n    return label;\n  }",
        },
    ];

    let stacked = "export class Panel {\n  @Input()\n  @Memo()\n  run(label: string): string {\n    return label;\n  }\n}\n";
    let stacked_rows = [Row {
        needle: "return label;",
        kind: SourceUnitKind::Method,
        name: Some("run"),
        span: LineSpan { start: 2, end: 6 },
        text: "@Input()\n  @Memo()\n  run(label: string): string {\n    return label;\n  }",
    }];

    for language in [SyntaxLanguage::TypeScript, SyntaxLanguage::Tsx] {
        assert_rows(single, language, &single_rows);
        assert_rows(stacked, language, &stacked_rows);
    }
}

/// A `type` alias is a declaration, and `SourceUnitKind::TypeAlias` names it.
///
/// The kind is in the shared model and the TypeScript grammar spells the node
/// `type_alias_declaration`. An interface stays unrecognized — the model has no
/// variant for it — which the tree-sitter unsupported table already states.
#[test]
fn type_aliases_are_recognized() {
    let source = "export type Handle = number;\n\ntype Bare = string;\n";
    assert_rows(
        source,
        SyntaxLanguage::TypeScript,
        &[
            Row {
                needle: "Handle",
                kind: SourceUnitKind::TypeAlias,
                name: Some("Handle"),
                span: LineSpan { start: 1, end: 1 },
                text: "export type Handle = number;",
            },
            Row {
                needle: "Bare",
                kind: SourceUnitKind::TypeAlias,
                name: Some("Bare"),
                span: LineSpan { start: 3, end: 3 },
                text: "type Bare = string;",
            },
        ],
    );
}

/// An `enum` is a declaration, and `export` opens its text in either dialect.
///
/// `SourceUnitKind::Enum` reached only the Rust backend until the TypeScript
/// recognizer named `enum_declaration`, so the model carried a kind this
/// grammar returned nothing for. The exported form is a child of an
/// `export_statement`, which is the shape `js_declared_range` widens, and a
/// `const enum` takes the same node — so the returned text opens at `export`
/// rather than at `enum`.
#[test]
fn enums_are_recognized() {
    assert_rows(
        "enum Color { Red }\n",
        SyntaxLanguage::TypeScript,
        &[Row {
            needle: "Red",
            kind: SourceUnitKind::Enum,
            name: Some("Color"),
            span: LineSpan { start: 1, end: 1 },
            text: "enum Color { Red }",
        }],
    );

    assert_rows(
        "export const enum Color { Red }\n",
        SyntaxLanguage::Tsx,
        &[Row {
            needle: "Red",
            kind: SourceUnitKind::Enum,
            name: Some("Color"),
            span: LineSpan { start: 1, end: 1 },
            text: "export const enum Color { Red }",
        }],
    );
}

/// The dialect boundary runs one way, and that is why routing `.tsx` matters.
///
/// The TypeScript grammar has no JSX element, so JSX source resolves nothing
/// under it. The TSX grammar is TypeScript plus JSX, so plain TypeScript
/// resolves the same declaration under either. A file misrouted to TSX still
/// answers; a file misrouted to TypeScript goes silent.
#[test]
fn tsx_accepts_typescript_but_typescript_rejects_jsx() {
    let jsx = point_of(TSX_SOURCE, "return <div");
    assert_eq!(
        enclosing_unit(TSX_SOURCE, SyntaxLanguage::TypeScript, jsx.into()),
        None,
        "the TypeScript grammar rejects JSX source"
    );

    let typed = point_of(TYPESCRIPT_SOURCE, "return greeting;");
    assert_eq!(
        enclosing_unit(TYPESCRIPT_SOURCE, SyntaxLanguage::Tsx, typed.into()),
        Some(unit_of_row(&TYPESCRIPT.target)),
        "the Tsx grammar accepts plain TypeScript source"
    );
}
