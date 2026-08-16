//! What this crate reports when no complete structural parse stands behind an
//! analysis.
//!
//! Three ways that happens: this build links no grammar for the requested
//! language, this build links none at all, and the parser recovered a tree that
//! carries errors. All three keep every flat finding they produce today and
//! report `Unavailable`, rather than a successful analysis with an empty symbol
//! list.

use pedant_types::{
    Capability, CapabilityAnalysis, FindingOrigin, Language, SymbolAttributionStatus,
};

use crate::language_probe::analysis_for;

/// One written-down flat occurrence, in the projection every case compares.
type FlatRow = (Capability, &'static str, usize, usize, FindingOrigin);

/// Assert an analysis reports unavailable attribution beside exact findings.
fn assert_unavailable(analysis: &CapabilityAnalysis, path: &str, expected: &[FlatRow]) {
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

    let actual: Box<[Compared<'_>]> = analysis
        .profile
        .findings
        .iter()
        .map(|finding| {
            (
                finding.capability,
                &*finding.evidence,
                finding.location.line,
                finding.location.column,
                finding.origin.expect("every finding states an origin"),
            )
        })
        .collect();
    // The written-down rows carry `&'static str` evidence; borrowing them for
    // this one comparison shortens that to the analysis's own lifetime, which is
    // all the tuple equality needs.
    let expected: Box<[Compared<'_>]> = expected
        .iter()
        .map(|&(capability, evidence, line, column, origin)| {
            (capability, evidence, line, column, origin)
        })
        .collect();
    assert_eq!(
        actual, expected,
        "{path} must keep exactly its current flat findings"
    );
}

/// One flat occurrence as both sides of a comparison spell it.
type Compared<'a> = (Capability, &'a str, usize, usize, FindingOrigin);

// ---------------------------------------------------------------------------
// 4.T6: a disabled grammar
// ---------------------------------------------------------------------------

/// The Python source the disabled-grammar case scans at the text tier.
#[cfg(not(feature = "ts-python"))]
const DISABLED_SOURCE: &str = concat!(
    "import socket\n",        // 1
    "\n",                     // 2
    "def fetch(url):\n",      // 3
    "    return open(url)\n", // 4
);

/// 4.T6 (Invariant 10): a build whose requested grammar is disabled keeps its
/// text-tier findings and reports attribution as unavailable.
///
/// Compiled where the Python grammar is absent, which covers both the
/// no-default configuration and the JavaScript-only split configuration the
/// plan names.
#[cfg(not(feature = "ts-python"))]
#[test]
fn disabled_grammar_keeps_flat_findings_and_marks_attribution_unavailable() {
    let analysis = analysis_for(DISABLED_SOURCE, "disabled.py", Language::Python);
    assert_unavailable(
        &analysis,
        "disabled.py",
        &[
            (Capability::Network, "socket", 1, 1, FindingOrigin::Import),
            (
                Capability::FileRead,
                "open()",
                4,
                12,
                FindingOrigin::CodeSite,
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// 4.T8: an error-bearing recovery tree
// ---------------------------------------------------------------------------

/// Python the grammar recovers from: the parameter list never closes.
#[cfg(feature = "ts-python")]
const RECOVERY_SOURCE: &str = concat!(
    "import socket\n",                                 // 1
    "\n",                                              // 2
    "def fetch(:\n",                                   // 3
    "    return open(\"https://api.example.test\")\n", // 4
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
        &[
            (Capability::Network, "socket", 1, 1, FindingOrigin::Import),
            (
                Capability::FileRead,
                "open()",
                4,
                12,
                FindingOrigin::CodeSite,
            ),
            (
                Capability::Network,
                "https://api.example.test",
                4,
                17,
                FindingOrigin::StringLiteral,
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// 4.T11: the no-default fallback corpus
// ---------------------------------------------------------------------------

/// One fallback row: a source, where it lives, and what the text tier reports.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
struct Fallback {
    language: Language,
    path: &'static str,
    source: &'static str,
    rows: &'static [FlatRow],
}

/// Every language this crate analyzes, at the text tier.
#[cfg(not(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
)))]
const FALLBACK_CORPUS: &[Fallback] = &[
    Fallback {
        language: Language::Python,
        path: "fallback.py",
        source: "import socket\n\ndef fetch(url):\n    return open(url)\n",
        rows: &[
            (Capability::Network, "socket", 1, 1, FindingOrigin::Import),
            (
                Capability::FileRead,
                "open()",
                4,
                12,
                FindingOrigin::CodeSite,
            ),
        ],
    },
    Fallback {
        language: Language::JavaScript,
        path: "fallback.js",
        source: "const cp = require('child_process');\n",
        rows: &[(
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
        rows: &[(Capability::FileRead, "fs", 1, 1, FindingOrigin::Import)],
    },
    Fallback {
        language: Language::Go,
        path: "fallback.go",
        source: "package main\n\nimport \"net/http\"\n",
        rows: &[(Capability::Network, "net/http", 3, 1, FindingOrigin::Import)],
    },
    Fallback {
        language: Language::Bash,
        path: "fallback.sh",
        source: "curl https://example.test/root\n",
        rows: &[(Capability::Network, "curl", 1, 1, FindingOrigin::CodeSite)],
    },
];

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
    let mut reached = 0_usize;
    for row in FALLBACK_CORPUS {
        let analysis = analysis_for(row.source, row.path, row.language);
        assert_unavailable(&analysis, row.path, row.rows);
        reached += 1;
    }
    assert_eq!(
        reached,
        FALLBACK_CORPUS.len(),
        "every corpus row must be exercised"
    );
    assert_eq!(
        reached, 5,
        "the corpus covers every language this crate analyzes"
    );
}
