//! What this crate reports when no complete structural parse stands behind an
//! analysis.
//!
//! Three ways that happens: this build links no grammar for the requested
//! language, this build links none at all, and the parser recovered a tree that
//! carries errors. All three keep every flat finding they produce today and
//! report `Unavailable`, rather than a successful analysis with an empty symbol
//! list.

#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
use std::collections::BTreeSet;

use pedant_types::{
    Capability, CapabilityAnalysis, FindingOrigin, Language, SymbolAttributionStatus,
};

use crate::language_probe::{FlatRow, analysis_for, assert_flat_sequence};

/// One written-down flat occurrence, as a case states it.
///
/// The language is stated once per case rather than once per row, so a case
/// cannot write a row against a language it did not analyze.
type Occurrence = (Capability, &'static str, usize, usize, FindingOrigin);

/// The occurrences a case states, in the projection the comparison reads.
fn stated(language: Language, occurrences: &[Occurrence]) -> Box<[FlatRow<'static>]> {
    occurrences
        .iter()
        .map(|&(capability, evidence, line, column, origin)| {
            (
                capability,
                evidence,
                line,
                column,
                Some(origin),
                Some(language),
            )
        })
        .collect()
}

/// Assert an analysis reports unavailable attribution beside exact findings.
fn assert_unavailable(
    analysis: &CapabilityAnalysis,
    path: &str,
    language: Language,
    occurrences: &[Occurrence],
) {
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Unavailable,
        "{path} has no complete structural parse behind it"
    );
    assert!(
        analysis.symbols.is_empty(),
        "{path} claims no symbol, got {:?}",
        analysis.symbols
    );
    assert_flat_sequence(analysis, path, &stated(language, occurrences));
}

// ---------------------------------------------------------------------------
// 4.T6: a disabled grammar
// ---------------------------------------------------------------------------

/// One text-tier fixture: a source, where it lives, and what it must report.
#[cfg(not(feature = "ts-python"))]
struct Fallback {
    language: Language,
    path: &'static str,
    source: &'static str,
    occurrences: &'static [Occurrence],
}

/// Analyze one text-tier fixture and judge the whole answer.
#[cfg(not(feature = "ts-python"))]
fn assert_fallback(fixture: &Fallback) {
    let analysis = analysis_for(fixture.source, fixture.path, fixture.language);
    assert_unavailable(
        &analysis,
        fixture.path,
        fixture.language,
        fixture.occurrences,
    );
}

/// The Python fixture both no-grammar cases scan at the text tier.
///
/// The disabled-grammar case and the no-default corpus put this one source
/// through this one assertion, so it is written once under the wider of the two
/// gates rather than twice with two chances to drift.
#[cfg(not(feature = "ts-python"))]
const PYTHON_FALLBACK: Fallback = Fallback {
    language: Language::Python,
    path: "fallback.py",
    source: concat!(
        "import socket\n",        // 1
        "\n",                     // 2
        "def fetch(url):\n",      // 3
        "    return open(url)\n", // 4
    ),
    occurrences: &[
        (Capability::Network, "socket", 1, 1, FindingOrigin::Import),
        (
            Capability::FileRead,
            "open()",
            4,
            12,
            FindingOrigin::CodeSite,
        ),
    ],
};

/// 4.T6 (Invariant 10): a build whose requested grammar is disabled keeps its
/// text-tier findings and reports attribution as unavailable.
///
/// Compiled where the Python grammar is absent, which covers both the
/// no-default configuration and the JavaScript-only split configuration the
/// plan names.
#[cfg(not(feature = "ts-python"))]
#[test]
fn disabled_grammar_keeps_flat_findings_and_marks_attribution_unavailable() {
    assert_fallback(&PYTHON_FALLBACK);
}

// ---------------------------------------------------------------------------
// 4.T8: an error-bearing recovery tree
// ---------------------------------------------------------------------------

/// Python the grammar recovers from: the parameter list never closes.
///
/// The alias carries the claim. `s` resolves to `socket` only through the import
/// alias map the structured tier builds while walking the tree, so the second
/// row below is one no text-tier scan can produce. A source whose rows the text
/// tier could also emit would pass this case even if the parse had been
/// abandoned and the fallback had run.
#[cfg(feature = "ts-python")]
const RECOVERY_SOURCE: &str = concat!(
    "import socket as s\n",               // 1
    "conn = s.create_connection(addr)\n", // 2
    "\n",                                 // 3
    "def fetch(:\n",                      // 4
    "    return conn\n",                  // 5
);

/// 4.T8 (Invariant 19): a recovery tree keeps every flat finding the structured
/// and text paths produce today, and reports attribution as unavailable.
#[cfg(feature = "ts-python")]
#[test]
fn recovery_tree_keeps_flat_findings_and_marks_attribution_unavailable() {
    let analysis = analysis_for(RECOVERY_SOURCE, "recovery.py", Language::Python);
    assert_unavailable(
        &analysis,
        "recovery.py",
        Language::Python,
        &[
            (Capability::Network, "socket", 1, 1, FindingOrigin::Import),
            (
                Capability::Network,
                "s.create_connection",
                2,
                8,
                FindingOrigin::CodeSite,
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// 4.T11: the no-default fallback corpus
// ---------------------------------------------------------------------------

/// Every language this crate analyzes, at the text tier.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
const FALLBACK_CORPUS: &[Fallback] = &[
    PYTHON_FALLBACK,
    Fallback {
        language: Language::JavaScript,
        path: "fallback.js",
        source: "const cp = require('child_process');\n",
        occurrences: &[(
            Capability::ProcessExec,
            "child_process",
            1,
            1,
            FindingOrigin::Import,
        )],
    },
    Fallback {
        language: Language::TypeScript,
        path: "fallback.ts",
        source: "const fs = require('fs');\n",
        occurrences: &[(Capability::FileRead, "fs", 1, 1, FindingOrigin::Import)],
    },
    Fallback {
        language: Language::Go,
        path: "fallback.go",
        source: "package main\n\nimport \"net/http\"\n",
        occurrences: &[(Capability::Network, "net/http", 3, 1, FindingOrigin::Import)],
    },
    Fallback {
        language: Language::Bash,
        path: "fallback.sh",
        source: "curl https://example.test/root\n",
        occurrences: &[(Capability::Network, "curl", 1, 1, FindingOrigin::CodeSite)],
    },
];

/// Whether this crate's own scanners answer for `language`.
///
/// Exhaustive by variant on purpose: a seventh `Language` fails to compile here
/// rather than quietly leaving the corpus one row short.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
fn analyzed_here(language: Language) -> bool {
    match language {
        // Rust capability analysis belongs to `pedant-core`, so this crate
        // scans no Rust and the corpus states no Rust row.
        Language::Rust => false,
        Language::Python
        | Language::JavaScript
        | Language::TypeScript
        | Language::Go
        | Language::Bash => true,
    }
}

/// Every language the corpus must carry a row for.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
fn analyzed_languages() -> BTreeSet<Language> {
    [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Go,
        Language::Bash,
    ]
    .into_iter()
    .filter(|&language| analyzed_here(language))
    .collect()
}

/// 4.T11 (Invariant 16): the no-default build emits the same text-tier findings
/// it does today and reports every source's symbol attribution as unavailable.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
#[test]
fn no_default_language_analysis_keeps_flat_findings_and_marks_symbols_unavailable() {
    for fixture in FALLBACK_CORPUS {
        assert_fallback(fixture);
    }

    let covered: BTreeSet<Language> = FALLBACK_CORPUS
        .iter()
        .map(|fixture| fixture.language)
        .collect();
    assert_eq!(
        covered,
        analyzed_languages(),
        "the corpus covers every language this crate analyzes"
    );
}
