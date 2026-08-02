//! Cross-cutting behavior shared by the per-language fixtures.
//!
//! Fixture source and expected declarations live in fixtures.rs; this file
//! owns backend selection, coverage guards, and shared expected-value helpers.

use std::fmt;

use pedant_syntax::{LineSpan, SourceUnit, SourceUnitKind, SyntaxLanguage};

#[cfg(any(feature = "rust", feature = "_ts"))]
use pedant_syntax::enclosing_unit;

#[cfg(any(feature = "rust", feature = "_ts"))]
use crate::fixtures::ALL_LANGUAGES;
use crate::fixtures::Row;
#[cfg(any(feature = "rust", feature = "_ts"))]
use crate::positions::point_of;

/// Assert `reached` cases were exercised: one per enabled backend among
/// `candidates`.
///
/// Every test that loops over an enabled-backend set ends here. The expected
/// count comes from [`extraction_enabled`], so a cfg slip that empties or
/// shortens the set fails those tests instead of greening them with no
/// assertion. Zero is a defect for every candidate set: a caller reaching here
/// has a backend linked, so a build with none must not compile the caller at
/// all.
///
/// `subject` names what one case covers, because the candidate sets differ.
/// [`ALL_LANGUAGES`] counts extraction backends; [`tree_sitter_languages`]
/// excludes Rust, which never selects a grammar, so its tables hold no Rust
/// row.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub fn assert_covered(
    reached: usize,
    candidates: impl IntoIterator<Item = SyntaxLanguage>,
    subject: &str,
) {
    assert!(
        reached > 0,
        "a caller of this guard links at least one {subject}"
    );
    assert_eq!(
        reached,
        enabled_count(candidates),
        "every {subject} this build enables contributes one case"
    );
}

/// Assert `skipped` cases were passed over: one per disabled tree-sitter
/// backend.
///
/// A loop whose body runs only for a disabled backend asserts nothing in the
/// all-features configuration. Ending it here makes the run state which
/// configuration it proved: zero skips names a build that disables none, and a
/// case table that lost a row fails rather than shrinking in silence.
#[cfg(feature = "_ts")]
pub fn assert_every_disabled_tree_sitter_backend_skipped(skipped: usize) {
    assert_eq!(
        skipped,
        tree_sitter_languages().count() - enabled_count(tree_sitter_languages()),
        "every tree-sitter backend this build disables contributes one skip"
    );
}

/// Every language a tree-sitter grammar can serve: all of them but Rust, which
/// parses through `syn` and selects no grammar in any build.
#[cfg(feature = "_ts")]
pub fn tree_sitter_languages() -> impl Iterator<Item = SyntaxLanguage> {
    ALL_LANGUAGES
        .into_iter()
        .filter(|language| !matches!(language, SyntaxLanguage::Rust))
}

/// Every language whose extraction backend this build enables.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub fn enabled_languages() -> impl Iterator<Item = SyntaxLanguage> {
    ALL_LANGUAGES
        .into_iter()
        .filter(|language| extraction_enabled(*language))
}

/// How many of `candidates` this build links an extraction backend for.
#[cfg(any(feature = "rust", feature = "_ts"))]
fn enabled_count(candidates: impl IntoIterator<Item = SyntaxLanguage>) -> usize {
    candidates
        .into_iter()
        .filter(|language| extraction_enabled(*language))
        .count()
}

/// Whether this build enables the extraction backend for `language`.
pub fn extraction_enabled(language: SyntaxLanguage) -> bool {
    match language {
        SyntaxLanguage::Rust => cfg!(feature = "rust"),
        SyntaxLanguage::Python => cfg!(feature = "ts-python"),
        SyntaxLanguage::JavaScript => cfg!(feature = "ts-javascript"),
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => cfg!(feature = "ts-typescript"),
        SyntaxLanguage::Go => cfg!(feature = "ts-go"),
        SyntaxLanguage::Bash => cfg!(feature = "ts-bash"),
    }
}

/// One minimal declaration for `language` and the unit it resolves to.
///
/// The target is written down rather than taken from a first extraction, so a
/// backend that resolves the wrong extent fails here instead of agreeing with
/// itself across the terminator variants.
pub struct Minimal {
    /// Source holding exactly one declaration, valid under its own grammar.
    pub source: &'static str,
    /// The declaration that source resolves.
    pub target: Row,
}

/// One minimal declaration for `language`, valid under its own grammar.
///
/// Two properties every snippet holds, one per caller. `dispatch` needs line 2
/// to sit inside the declaration, so a probe on a disabled backend fails on a
/// backend that answers rather than passing on a line no declaration covers.
/// `location` needs the last line before the trailing newline to be the
/// declaration's own last line, so stripping that newline leaves a source whose
/// final, unterminated line still resolves.
///
/// An exhaustive match, so a new variant fails to compile until it has a
/// snippet, and both callers then cover it without further edits.
pub fn minimal_declaration(language: SyntaxLanguage) -> Minimal {
    match language {
        SyntaxLanguage::Rust => Minimal {
            source: "fn build() -> usize {\n    1\n}\n",
            target: Row {
                needle: "    1",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 3 },
                text: "fn build() -> usize {\n    1\n}",
            },
        },
        SyntaxLanguage::Python => Minimal {
            source: "def build():\n    return 1\n",
            target: Row {
                needle: "return 1",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 2 },
                text: "def build():\n    return 1",
            },
        },
        SyntaxLanguage::JavaScript => Minimal {
            source: "function build() {\n  return 1;\n}\n",
            target: Row {
                needle: "return 1;",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 3 },
                text: "function build() {\n  return 1;\n}",
            },
        },
        SyntaxLanguage::TypeScript => Minimal {
            source: "function build(): number {\n  return 1;\n}\n",
            target: Row {
                needle: "return 1;",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 3 },
                text: "function build(): number {\n  return 1;\n}",
            },
        },
        SyntaxLanguage::Tsx => Minimal {
            source: "function Build() {\n  return <b />;\n}\n",
            target: Row {
                needle: "return <b />;",
                kind: SourceUnitKind::Function,
                name: Some("Build"),
                span: LineSpan { start: 1, end: 3 },
                text: "function Build() {\n  return <b />;\n}",
            },
        },
        SyntaxLanguage::Go => Minimal {
            source: "package main\nfunc build() int {\n    return 1\n}\n",
            target: Row {
                needle: "return 1",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 2, end: 4 },
                text: "func build() int {\n    return 1\n}",
            },
        },
        SyntaxLanguage::Bash => Minimal {
            source: "build() {\n  echo hi\n}\n",
            target: Row {
                needle: "echo hi",
                kind: SourceUnitKind::Function,
                name: Some("build"),
                span: LineSpan { start: 1, end: 3 },
                text: "build() {\n  echo hi\n}",
            },
        },
    }
}

/// Assert no recognized declaration holds `needle`, by point and by line.
///
/// This lives with the fixtures rather than with the table driver because both
/// the table driver and the per-backend modules ask it, and neither owns the
/// other. It carries the same gate as `point_of`, whose coordinates it needs.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub fn assert_absent(source: &str, language: SyntaxLanguage, needle: &str) {
    let at = point_of(source, needle);
    assert_eq!(
        enclosing_unit(source, language, at.into()),
        None,
        "{language:?} has no declaration at {needle:?}"
    );
    assert_eq!(
        enclosing_unit(source, language, at.line_only()),
        None,
        "{language:?} has no declaration on line {}",
        at.line
    );
}

/// The unit a written-down row must return.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub fn unit_of_row(row: &Row) -> SourceUnit {
    SourceUnit {
        kind: row.kind,
        name: row.name.map(Into::into),
        span: row.span,
        text: row.text.into(),
    }
}

/// Assert `unit` is the declaration `row` writes down, field by field.
///
/// One definition of "matches" for every caller holding a [`Row`]: the table
/// driver, the dispatch probes, and the CRLF probe. A field the model gains is
/// compared in one place rather than three that would each keep compiling
/// without it.
///
/// `context` names the probe — a language and a needle, a language and a
/// location — and each assertion appends the field it compared, so a failure
/// still says which field differed.
///
/// Ungated, because `dispatch` states its enabled and disabled halves in one
/// function that every configuration compiles.
pub fn assert_matches_row(unit: &SourceUnit, row: &Row, context: fmt::Arguments<'_>) {
    assert_eq!(unit.kind, row.kind, "{context} kind");
    assert_eq!(unit.name.as_deref(), row.name, "{context} name");
    assert_eq!(unit.span, row.span, "{context} span");
    assert_eq!(&*unit.text, row.text, "{context} text");
}
