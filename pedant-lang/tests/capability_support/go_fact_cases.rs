//! What Go capability analysis publishes once one fact inventory owns the
//! grammar.
//!
//! The flat findings, their order, their attribution status, and the symbols
//! beneath them are published security evidence, so every row here is written
//! down rather than derived. Moving structured ownership out of this crate must
//! not change one byte of them.

use pedant_types::{Capability, FindingOrigin, Language, SymbolAttributionStatus};

use crate::language_probe::{FlatRow, analysis_for, assert_flat_sequence};

/// One Go source whose structured findings the text tier cannot produce.
///
/// The alias carries that claim: `osx.ReadFile` resolves to `os.ReadFile` only
/// through the import map the structured tier builds, and no scan for the
/// literal text `os.ReadFile(` finds it. A source the text tier could also
/// answer for would pass this case even if the structured path had been
/// abandoned.
#[cfg(feature = "ts-go")]
const STRUCTURED_SOURCE: &str = concat!(
    "package main\n",                                  // 1
    "\n",                                              // 2
    "import (\n",                                      // 3
    "\t\"net/http\"\n",                                // 4
    "\tosx \"os\"\n",                                  // 5
    ")\n",                                             // 6
    "\n",                                              // 7
    "const endpoint = \"https://example.test/api\"\n", // 8
    "\n",                                              // 9
    "func load(path string) string {\n",               // 10
    "\tdata, _ := osx.ReadFile(path)\n",               // 11
    "\treturn string(data)\n",                         // 12
    "}\n",                                             // 13
    "\n",                                              // 14
    "func run() {\n",                                  // 15
    "\t_ = osx.Getenv(\"TOKEN\")\n",                   // 16
    "}\n",                                             // 17
);

/// Go the parser recovers from, whose structured findings still stand.
///
/// The import above the break resolves the alias, so the call below it is
/// again a row only the structured tier produces.
#[cfg(feature = "ts-go")]
const RECOVERY_SOURCE: &str = concat!(
    "package main\n",            // 1
    "\n",                        // 2
    "import osx \"os\"\n",       // 3
    "\n",                        // 4
    "func load( {\n",            // 5
    "\t_ = osx.Getenv(\"K\")\n", // 6
    "}\n",                       // 7
);

/// One written-down occurrence, as a row states it.
type Occurrence = (Capability, &'static str, usize, usize, FindingOrigin);

/// The occurrences a case states, in the projection the comparison reads.
fn stated(occurrences: &[Occurrence]) -> Box<[FlatRow<'static>]> {
    occurrences
        .iter()
        .map(|&(capability, evidence, line, column, origin)| {
            (
                capability,
                evidence,
                line,
                column,
                Some(origin),
                Some(Language::Go),
            )
        })
        .collect()
}

/// 2.T4 (Invariant 3): the published Go capability answer is byte-exact after
/// the grammar moved into one fact inventory.
#[cfg(feature = "ts-go")]
#[test]
fn go_capability_output_and_recovery_are_byte_exact_after_fact_migration() {
    let analysis = analysis_for(STRUCTURED_SOURCE, "widget.go", Language::Go);
    assert_flat_sequence(
        &analysis,
        "widget.go",
        &stated(&[
            (Capability::Network, "net/http", 4, 2, FindingOrigin::Import),
            (
                Capability::FileRead,
                "os.ReadFile",
                11,
                13,
                FindingOrigin::CodeSite,
            ),
            (
                Capability::EnvAccess,
                "os.Getenv",
                16,
                6,
                FindingOrigin::CodeSite,
            ),
            (
                Capability::Network,
                "https://example.test/api",
                8,
                18,
                FindingOrigin::StringLiteral,
            ),
        ]),
    );
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "a complete parse attributes every finding it can"
    );
    let owners: Box<[(&str, usize, usize)]> = analysis
        .symbols
        .iter()
        .map(|held| {
            (
                &*held.symbol.name,
                held.symbol.declaration.line,
                held.profile.findings.len(),
            )
        })
        .collect();
    assert_eq!(
        &*owners,
        &[("load", 10, 1), ("run", 15, 1)],
        "each call site is attributed to the function that holds it"
    );

    let recovered = analysis_for(RECOVERY_SOURCE, "broken.go", Language::Go);
    assert_flat_sequence(
        &recovered,
        "broken.go",
        &stated(&[(
            Capability::EnvAccess,
            "os.Getenv",
            6,
            6,
            FindingOrigin::CodeSite,
        )]),
    );
    assert_eq!(
        recovered.symbol_attribution,
        SymbolAttributionStatus::Unavailable,
        "a recovery tree states no complete callable inventory"
    );
    assert!(
        recovered.symbols.is_empty(),
        "a recovery tree claims no symbol, got {:?}",
        recovered.symbols
    );
}

/// The text-tier source, whose findings need no grammar at all.
#[cfg(not(feature = "ts-go"))]
const TEXT_SOURCE: &str = concat!(
    "package main\n",             // 1
    "\n",                         // 2
    "import \"net/http\"\n",      // 3
    "\n",                         // 4
    "func load(path string) {\n", // 5
    "\tf, _ := os.Open(path)\n",  // 6
    "\t_ = f\n",                  // 7
    "}\n",                        // 8
);

/// 2.T5 (Invariant 3): a build with no Go grammar keeps its text findings and
/// reports attribution as unavailable, claiming no structured symbol.
#[cfg(not(feature = "ts-go"))]
#[test]
fn go_capability_without_grammar_retains_text_findings_and_unavailable_attribution() {
    let analysis = analysis_for(TEXT_SOURCE, "text.go", Language::Go);
    assert_flat_sequence(
        &analysis,
        "text.go",
        &stated(&[
            (Capability::Network, "net/http", 3, 1, FindingOrigin::Import),
            (
                Capability::FileRead,
                "os.Open",
                6,
                10,
                FindingOrigin::CodeSite,
            ),
        ]),
    );
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Unavailable,
        "no grammar means no callable inventory to be complete about"
    );
    assert!(
        analysis.symbols.is_empty(),
        "a grammar-absent build claims no symbol, got {:?}",
        analysis.symbols
    );
}

/// How many callables the compatibility-limit corpus states.
#[cfg(feature = "ts-go")]
const CORPUS_CALLABLES: usize = 120;

/// A Go source far above any ceiling a snapshot would lower.
///
/// Every callable is named to a fixed width, so every call site opens at the
/// same column and the expectation is one row repeated rather than a table
/// that restates the generator.
#[cfg(feature = "ts-go")]
fn corpus() -> String {
    let mut source = String::from("package main\n\nimport osx \"os\"\n\n");
    for index in 0..CORPUS_CALLABLES {
        source.push_str(&format!(
            "func f{index:03}() {{ _ = osx.Getenv(\"K{index:03}\") }}\n"
        ));
    }
    source
}

/// 2.T6 (Invariants 3 and 5): capability analysis runs beneath the unbounded
/// compatibility limit, so a corpus above every lowered ceiling still answers.
#[cfg(feature = "ts-go")]
#[test]
fn go_capability_uses_unbounded_compatibility_fact_limits() {
    use pedant_syntax::go::GoFactLimits;
    use pedant_syntax::{SyntaxLanguage, tree_sitter::parse_bound};

    assert_eq!(
        (
            GoFactLimits::UNBOUNDED.max_syntax_depth(),
            GoFactLimits::UNBOUNDED.max_facts()
        ),
        (u32::MAX, u32::MAX),
        "the compatibility limit spends every ceiling"
    );

    let source = corpus();
    let parsed = parse_bound(&source, SyntaxLanguage::Go).expect("the corpus parses");
    assert!(
        parsed.go_file_facts(GoFactLimits::new(8, 64)).is_err(),
        "the corpus must sit above the lowered ceilings this case names"
    );
    assert!(
        parsed.go_file_facts(GoFactLimits::UNBOUNDED).is_ok(),
        "the compatibility limit admits the same corpus"
    );

    let analysis = analysis_for(&source, "corpus.go", Language::Go);
    let expected: Box<[Occurrence]> = (0..CORPUS_CALLABLES)
        .map(|index| {
            (
                Capability::EnvAccess,
                "os.Getenv",
                5 + index,
                19,
                FindingOrigin::CodeSite,
            )
        })
        .collect();
    assert_flat_sequence(&analysis, "corpus.go", &stated(&expected));
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "the corpus parses completely, so every finding is attributed"
    );
    assert_eq!(
        analysis.symbols.len(),
        CORPUS_CALLABLES,
        "every callable in the corpus owns its own call site"
    );
}
