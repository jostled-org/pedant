//! Rust backend: every recognized `syn` item, nested method precedence,
//! attribute-opened text, and parser failure.

use pedant_syntax::{
    LineSpan, Location, SourceUnitKind, SyntaxLanguage, enclosing_unit, invalidate_parser_cache,
};

use crate::fixture_support::unit_of_row;
use crate::fixtures::{RUST, RUST_SOURCE, Row};
use crate::positions::point_of;
use crate::table::{assert_rows, assert_table};

const LANGUAGE: SyntaxLanguage = SyntaxLanguage::Rust;

/// Every recognized `syn` item, keyed by a substring it contains.
pub(crate) const ROWS: [Row; 12] = [
    Row {
        needle: "pub retries: usize,",
        kind: SourceUnitKind::Struct,
        name: Some("Config"),
        span: LineSpan { start: 3, end: 5 },
        text: "pub struct Config {\n    pub retries: usize,\n}",
    },
    Row {
        needle: "Fast,",
        kind: SourceUnitKind::Enum,
        name: Some("Mode"),
        span: LineSpan { start: 7, end: 10 },
        text: "pub enum Mode {\n    Fast,\n    Slow,\n}",
    },
    Row {
        needle: "bits: u32,",
        kind: SourceUnitKind::Union,
        name: Some("Word"),
        span: LineSpan { start: 12, end: 15 },
        text: "pub union Word {\n    bits: u32,\n    bytes: [u8; 4],\n}",
    },
    Row {
        needle: "pub trait Runner {",
        kind: SourceUnitKind::Trait,
        name: Some("Runner"),
        span: LineSpan { start: 17, end: 21 },
        text: "pub trait Runner {\n    fn describe(&self) -> usize {\n        11\n    }\n}",
    },
    // A trait method beats the trait wherever the trait's body holds the
    // location.
    Row {
        needle: "        11",
        kind: SourceUnitKind::Method,
        name: Some("describe"),
        span: LineSpan { start: 18, end: 20 },
        text: "fn describe(&self) -> usize {\n        11\n    }",
    },
    Row {
        needle: "pub type Handle",
        kind: SourceUnitKind::TypeAlias,
        name: Some("Handle"),
        span: LineSpan { start: 23, end: 23 },
        text: "pub type Handle = usize;",
    },
    // An impl block with a body: the header line resolves the impl, the body
    // lines resolve its method.
    Row {
        needle: "impl fmt::Debug for Config {",
        kind: SourceUnitKind::Impl,
        name: None,
        span: LineSpan { start: 25, end: 32 },
        text: "impl fmt::Debug for Config {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        fn tag() -> usize {\n            7\n        }\n        f.write_str(\"héllo\")\n    }\n}",
    },
    // The declaration the cross-cutting rules resolve, stated once on the
    // fixture and named here rather than restated.
    RUST.target,
    // An `fn` a method body declares: an impl is an ancestor but not the
    // owner, so the kind is `Function`, as a `def` inside a Python method is.
    Row {
        needle: "            7",
        kind: SourceUnitKind::Function,
        name: Some("tag"),
        span: LineSpan { start: 27, end: 29 },
        text: "fn tag() -> usize {\n            7\n        }",
    },
    Row {
        needle: "impl Runner for Mode {}",
        kind: SourceUnitKind::Impl,
        name: None,
        span: LineSpan { start: 34, end: 34 },
        text: "impl Runner for Mode {}",
    },
    Row {
        needle: "Config { retries }",
        kind: SourceUnitKind::Function,
        name: Some("build"),
        span: LineSpan { start: 36, end: 38 },
        text: "pub fn build(retries: usize) -> Config {\n    Config { retries }\n}",
    },
    // A receiverless associated `fn`, beside the `&self` method above that
    // answers `Method`. The receiver is the whole rule, and this route reads it
    // through the shared item table's `callable` rows — so without this row the
    // rule was stated by the structure walk alone and the boundary that
    // published the change had nothing red.
    Row {
        needle: "Config { retries: 0 }",
        kind: SourceUnitKind::Function,
        name: Some("new"),
        span: LineSpan { start: 41, end: 43 },
        text: "pub fn new() -> Config {\n        Config { retries: 0 }\n    }",
    },
];

#[test]
fn recognized_item_table() {
    assert_table(&RUST, &ROWS);
}

/// An attribute opens the declaration, as a Python decorator does.
#[test]
fn attributes_open_the_returned_text() {
    let source = "#[derive(Debug)]\npub struct Config {\n    retries: usize,\n}\n";
    assert_rows(
        source,
        LANGUAGE,
        &[Row {
            needle: "retries: usize,",
            kind: SourceUnitKind::Struct,
            name: Some("Config"),
            span: LineSpan { start: 1, end: 4 },
            text: "#[derive(Debug)]\npub struct Config {\n    retries: usize,\n}",
        }],
    );
}

/// An associated type is a type alias, wherever it is declared.
///
/// `SourceUnitKind::TypeAlias` would otherwise be reachable only for a free
/// `type` item: a trait's associated type would answer `Trait` for the whole
/// block and an impl's would answer `Impl`. Methods already have this shape
/// through `visit_trait_item_fn` and `visit_impl_item_fn`.
#[test]
fn associated_types_are_type_aliases() {
    let source = "pub trait Runner {\n    type Handle;\n}\n\nimpl Runner for u8 {\n    type Handle = u16;\n}\n";
    assert_rows(
        source,
        LANGUAGE,
        &[
            Row {
                needle: "type Handle;",
                kind: SourceUnitKind::TypeAlias,
                name: Some("Handle"),
                span: LineSpan { start: 2, end: 2 },
                text: "type Handle;",
            },
            Row {
                needle: "type Handle = u16;",
                kind: SourceUnitKind::TypeAlias,
                name: Some("Handle"),
                span: LineSpan { start: 6, end: 6 },
                text: "type Handle = u16;",
            },
        ],
    );
}

/// Releasing the parser's source map does not disturb the next extraction.
///
/// `proc-macro2` keeps every parsed file on a thread-local map that nothing
/// frees, so a long-lived host releases it between calls. That is only usable if
/// the parser rebuilds what it needs afterwards. Each pass here parses a
/// different source, so a stale entry would answer with the previous file's
/// positions rather than fail outright.
///
/// The expectation comes from the fixture, not from a first call, so a pass
/// that answers consistently wrong fails here.
#[test]
fn extraction_survives_an_invalidated_parser_cache() {
    let other = "pub fn ready() -> usize {\n    1\n}\n";
    let expected = unit_of_row(&RUST.target);

    for pass in 0..4 {
        invalidate_parser_cache();
        let ready = enclosing_unit(other, LANGUAGE, point_of(other, "    1").into())
            .unwrap_or_else(|| panic!("pass {pass}: the other source resolves"));
        assert_eq!(ready.name.as_deref(), Some("ready"), "pass {pass}");

        invalidate_parser_cache();
        assert_eq!(
            enclosing_unit(
                RUST_SOURCE,
                LANGUAGE,
                point_of(RUST_SOURCE, "f.write_str").into()
            )
            .as_ref(),
            Some(&expected),
            "pass {pass}: the same question answers the same after invalidation"
        );
    }
}

/// A byte-order mark does not shift the declaration `syn` reports.
///
/// `syn` strips the mark before lexing and reports every position against what
/// is left. An index built over the unstripped source is then three bytes short
/// on line 1, which returns a shifted name and a truncated body rather than an
/// error — the failure a Windows editor's default encoding produces.
#[test]
fn a_byte_order_mark_does_not_shift_positions() {
    let plain = "fn main() {\n    ready();\n}\n";
    let marked = "\u{feff}fn main() {\n    ready();\n}\n";
    let expected = enclosing_unit(plain, LANGUAGE, point_of(plain, "ready();").into())
        .expect("the unmarked source resolves");
    assert_eq!(&*expected.text, "fn main() {\n    ready();\n}");
    assert_eq!(expected.name.as_deref(), Some("main"));

    for at in [
        Location {
            line: 1,
            column: Some(4),
        },
        point_of(marked, "ready();").into(),
    ] {
        assert_eq!(
            enclosing_unit(marked, LANGUAGE, at).as_ref(),
            Some(&expected),
            "a marked source answers what the same unmarked source answers"
        );
    }
}

/// A shebang does not shift the declaration `syn` reports either.
///
/// `syn` drops a leading shebang but keeps that line's newline, so the text it
/// lexes holds the same number of lines as the source and the index over the
/// source needs no adjustment. Were the newline consumed with the line, every
/// declaration after line 1 would come back one line early — a shift no
/// assertion catches unless a shebang'd `.rs` file is stated, and
/// `#!/usr/bin/env cargo` is one people write.
///
/// The span is written down rather than taken from the same source without its
/// shebang, so a backend that shifts both sources alike fails here.
#[test]
fn a_shebang_does_not_shift_positions() {
    assert_rows(
        "#!/usr/bin/env cargo\nfn main() {\n    ready();\n}\n",
        LANGUAGE,
        &[Row {
            needle: "ready();",
            kind: SourceUnitKind::Function,
            name: Some("main"),
            span: LineSpan { start: 2, end: 4 },
            text: "fn main() {\n    ready();\n}",
        }],
    );
}

#[test]
fn parser_failure_returns_none() {
    let broken = "pub fn ready() -> usize {\n    1\n}\n\npub fn broken( {\n";
    for column in [None, Some(5)] {
        assert_eq!(
            enclosing_unit(broken, LANGUAGE, Location { line: 2, column }),
            None,
            "a syn parse failure is absence, not partial recovery"
        );
    }
}
