//! Contract tests for the `pedant-syntax` public substrate.
//!
//! This root owns the boundary model, syntax-language dispatch, and the shared
//! location rules. It stays the crate's only integration executable: the
//! fixtures, the table driver, the tree-sitter support cases, and one module
//! per extraction backend reach it through `#[path]` support modules, which
//! Cargo links into this same binary instead of a second one.

#[path = "enclosing_unit_support/fixtures.rs"]
mod fixtures;

#[path = "enclosing_unit_support/fixture_support.rs"]
mod fixture_support;

#[path = "enclosing_unit_support/positions.rs"]
mod positions;

#[cfg(any(feature = "rust", feature = "_ts"))]
#[path = "enclosing_unit_support/table.rs"]
mod table;

#[cfg(feature = "_ts")]
#[path = "enclosing_unit_support/tree_sitter_support.rs"]
mod tree_sitter_support;

/// The session claim every case is written in, and the probe that asserts it.
#[cfg(feature = "_ts")]
#[path = "enclosing_unit_support/session_probe.rs"]
mod session_probe;

/// What one bound parse session answers about the source it was built from.
#[cfg(feature = "_ts")]
#[path = "enclosing_unit_support/session_cases.rs"]
mod session_cases;

/// Who may build a parser, and what a bound session may do. Needs `syn` to
/// scan this crate's own source, so it carries the `rust` gate as well.
#[cfg(all(feature = "rust", feature = "_ts"))]
#[path = "enclosing_unit_support/ownership/mod.rs"]
mod ownership;

#[cfg(any(feature = "rust", feature = "_ts"))]
#[path = "enclosing_unit_support/location.rs"]
mod location;

#[cfg(feature = "rust")]
#[path = "enclosing_unit_support/shared_language.rs"]
mod shared_language;

mod model {
    use pedant_syntax::{LineSpan, Location, SourceUnit, SourceUnitKind, SyntaxLanguage};
    use serde_json::json;

    #[cfg(any(feature = "rust", feature = "_ts"))]
    use pedant_syntax::enclosing_unit;

    use crate::fixtures;
    // The serialized spelling of every variant. Generated beside the variant
    // arrays themselves, so a variant the model gains fails to compile until
    // both this table and the array it feeds name it.
    use crate::fixtures::{kind_name, language_name};
    #[cfg(any(feature = "rust", feature = "_ts"))]
    use crate::positions::point_of;

    #[test]
    fn serde_contract_uses_snake_case_and_public_fields() {
        for language in fixtures::ALL_LANGUAGES {
            let name = language_name(language);
            let encoded = serde_json::to_value(language).expect("language serializes");
            assert_eq!(encoded, json!(name), "{language:?} serializes as {name}");
            let decoded: SyntaxLanguage =
                serde_json::from_value(encoded).expect("language deserializes");
            assert_eq!(decoded, language);
        }

        for kind in fixtures::ALL_KINDS {
            let name = kind_name(kind);
            let encoded = serde_json::to_value(kind).expect("kind serializes");
            assert_eq!(encoded, json!(name), "{kind:?} serializes as {name}");
            let decoded: SourceUnitKind = serde_json::from_value(encoded).expect("kind decodes");
            assert_eq!(decoded, kind);
        }

        let located = Location {
            line: 4,
            column: Some(7),
        };
        assert_eq!(
            serde_json::to_value(located).expect("location serializes"),
            json!({ "line": 4, "column": 7 })
        );
        let line_only = Location {
            line: 4,
            column: None,
        };
        assert_eq!(
            serde_json::to_value(line_only).expect("location serializes"),
            json!({ "line": 4, "column": null })
        );
        let decoded: Location =
            serde_json::from_value(json!({ "line": 4, "column": null })).expect("location decodes");
        assert_eq!(decoded, line_only);

        let unit = SourceUnit {
            kind: SourceUnitKind::Method,
            name: Some("run".into()),
            span: LineSpan { start: 3, end: 5 },
            text: "fn run(&self) {}".into(),
        };
        let encoded = serde_json::to_value(&unit).expect("unit serializes");
        assert_eq!(
            encoded,
            json!({
                "kind": "method",
                "name": "run",
                "span": { "start": 3, "end": 5 },
                "text": "fn run(&self) {}",
            })
        );
        let decoded: SourceUnit = serde_json::from_value(encoded).expect("unit decodes");
        assert_eq!(decoded, unit);

        let anonymous = SourceUnit {
            kind: SourceUnitKind::Impl,
            name: None,
            span: LineSpan { start: 1, end: 9 },
            text: "impl Run for Job {}".into(),
        };
        let encoded = serde_json::to_value(&anonymous).expect("unit serializes");
        assert_eq!(encoded["name"], json!(null));
        let decoded: SourceUnit = serde_json::from_value(encoded).expect("unit decodes");
        assert_eq!(decoded, anonymous);
    }

    /// Extraction keeps no state that changes its answer.
    ///
    /// What that answer is belongs to the location rules, and absence belongs
    /// to the fixtures' own absence helper. Only repetition is stated here: the
    /// first call fixes the expectation the rest must match. The one thing this
    /// borrows from elsewhere is that the first call answers at all, without
    /// which repeating `None` would satisfy the loop.
    ///
    /// Needs at least one linked backend: [`fixtures::ENABLED`] is empty
    /// otherwise and the loop below asserts nothing.
    #[cfg(any(feature = "rust", feature = "_ts"))]
    #[test]
    fn repeated_extraction_is_identical() {
        let mut reached = 0_usize;
        for fixture in fixtures::ENABLED {
            let at = Location::from(point_of(fixture.source, fixture.target.needle));
            let first = enclosing_unit(fixture.source, fixture.language, at);
            assert!(
                first.is_some(),
                "{:?} resolves a declaration to repeat",
                fixture.language
            );

            for pass in 2..=3 {
                assert_eq!(
                    enclosing_unit(fixture.source, fixture.language, at),
                    first,
                    "{:?} pass {pass} repeats the first extraction",
                    fixture.language
                );
            }
            reached += 1;
        }
        crate::fixture_support::assert_covered(
            reached,
            fixtures::ALL_LANGUAGES,
            "extraction backend",
        );
    }
}

mod syntax_language {
    use std::path::Path;

    use pedant_syntax::{FileClassification, SyntaxLanguage, classify_path, detect_language};
    use pedant_types::Language;

    use crate::fixtures::ALL_LANGUAGES;

    #[test]
    fn rust_is_syntax_only() {
        let path = Path::new("pedant-syntax/src/lib.rs");
        let source = "fn main() {}\n";

        assert_eq!(
            pedant_syntax::syntax_language(path, source),
            Some(SyntaxLanguage::Rust)
        );
        assert_eq!(classify_path(path), FileClassification::Rust);
        assert_eq!(classify_path(path).language(), None);
        assert_eq!(detect_language(path, source), None);
    }

    #[test]
    fn tsx_precedes_typescript_classification() {
        let tsx = Path::new("web/App.tsx");
        assert_eq!(
            pedant_syntax::syntax_language(tsx, ""),
            Some(SyntaxLanguage::Tsx)
        );
        assert_eq!(
            classify_path(tsx),
            FileClassification::Source(Language::TypeScript),
            "capability classification of .tsx is unchanged"
        );

        for path in ["web/app.ts", "web/app.mts"] {
            assert_eq!(
                pedant_syntax::syntax_language(Path::new(path), ""),
                Some(SyntaxLanguage::TypeScript),
                "{path} keeps the TypeScript grammar"
            );
        }
        assert_eq!(
            SyntaxLanguage::from(Language::TypeScript),
            SyntaxLanguage::TypeScript,
            "capability TypeScript never converts to Tsx"
        );
    }

    /// `(path, source, expected)` over manifest, shebang, and unsupported rules.
    ///
    /// `setup.py` states its rule in a named test instead: it is the one path
    /// where syntax dispatch and capability classification disagree, the same
    /// way Rust and `.tsx` are the two languages they disagree about.
    ///
    /// `.jsx` and `.cts` are here because they were `Unsupported` until the
    /// extension arms named them: every such file answered nothing, so a row
    /// that only asserts the language would have passed before the arms
    /// existed too. `.jsx` names the plain JavaScript grammar rather than a JSX
    /// dialect of its own, which the JavaScript backend's own case extracts
    /// through.
    const DETECTION_CASES: [(&str, &str, Option<SyntaxLanguage>); 15] = [
        ("pkg/package.json", "", None),
        ("pkg/pyproject.toml", "", None),
        ("pkg/Makefile", "", None),
        ("pkg/notes.txt", "", None),
        ("pkg/hook", "", None),
        (
            "pkg/hook",
            "#!/usr/bin/env python3\nimport os\n",
            Some(SyntaxLanguage::Python),
        ),
        (
            "pkg/hook",
            "#!/bin/bash\necho hi\n",
            Some(SyntaxLanguage::Bash),
        ),
        (
            "pkg/hook",
            "#!/usr/bin/env node\n",
            Some(SyntaxLanguage::JavaScript),
        ),
        ("pkg/app.py", "", Some(SyntaxLanguage::Python)),
        ("pkg/app.js", "", Some(SyntaxLanguage::JavaScript)),
        ("web/App.jsx", "", Some(SyntaxLanguage::JavaScript)),
        ("pkg/app.ts", "", Some(SyntaxLanguage::TypeScript)),
        ("web/mod.cts", "", Some(SyntaxLanguage::TypeScript)),
        ("pkg/main.go", "", Some(SyntaxLanguage::Go)),
        ("pkg/run.sh", "", Some(SyntaxLanguage::Bash)),
    ];

    /// The two languages `DETECTION_CASES` states no row for, named rather than
    /// left to a weaker check.
    ///
    /// Both fail this table's parity assertion by design, because capability
    /// detection disagrees with syntax dispatch about them: it answers `None`
    /// for Rust and `TypeScript` for `.tsx`. `rust_is_syntax_only` and
    /// `tsx_precedes_typescript_classification` state their rules instead.
    const DETECTION_EXEMPT: [SyntaxLanguage; 2] = [SyntaxLanguage::Rust, SyntaxLanguage::Tsx];

    /// Assert every syntax language reaches [`DETECTION_CASES`], or is exempt.
    ///
    /// The table is a fixed list, so a seventh language could otherwise arrive
    /// with a detection rule and no row. Exemption is exact in both directions:
    /// an exempt language that gains a row fails here too, so the list cannot
    /// go stale.
    ///
    /// Its own case rather than a call from the table test below. The guard
    /// reads nothing from that test, and as a case the harness names it: a
    /// deleted or reordered call site can no longer retire it in silence.
    #[test]
    fn every_language_states_a_detection_rule() {
        for language in ALL_LANGUAGES {
            let listed = DETECTION_CASES
                .iter()
                .any(|(.., expected)| *expected == Some(language));
            assert_eq!(
                listed,
                !DETECTION_EXEMPT.contains(&language),
                "{language:?} states a detection rule here unless a named test states it"
            );
        }
    }

    /// Whether a file is extractable never depends on its shebang.
    ///
    /// A manifest filename claims a path before any extension does, so
    /// `setup.py` classifies as `Manifest` and names no language. Falling
    /// through to the shebang rule would then make the same file Python for one
    /// author and nothing for the next. The extension answers instead: source
    /// that is also a manifest resolves, and a manifest that is not source does
    /// not.
    #[test]
    fn a_manifest_answers_the_same_with_and_without_a_shebang() {
        for (path, expected) in [
            ("pkg/setup.py", Some(SyntaxLanguage::Python)),
            ("pkg/package.json", None),
            ("pkg/pyproject.toml", None),
            ("pkg/Makefile", None),
            ("pkg/justfile", None),
        ] {
            let path = Path::new(path);
            for source in ["", "#!/usr/bin/env node\nconsole.log(1)\n"] {
                assert_eq!(
                    pedant_syntax::syntax_language(path, source),
                    expected,
                    "{} with source {source:?}",
                    path.display()
                );
            }
        }
    }

    /// `env` takes its own options before the interpreter it runs.
    ///
    /// `#!/usr/bin/env -S python3` resolved to `-S`, which names no language,
    /// so a script written the portable way went undetected.
    #[test]
    fn env_options_precede_the_interpreter_name() {
        let path = Path::new("pkg/hook");
        for source in [
            "#!/usr/bin/env -S python3\nimport os\n",
            "#!/usr/bin/env -S python3 -u\nimport os\n",
        ] {
            assert_eq!(
                pedant_syntax::syntax_language(path, source),
                Some(SyntaxLanguage::Python),
                "{source:?} names python3"
            );
            assert_eq!(
                detect_language(path, source),
                Some(Language::Python),
                "{source:?} names python3 for capability routing too"
            );
        }
    }

    #[test]
    fn manifest_shebang_and_unsupported_paths_follow_existing_rules() {
        for (path, source, expected) in DETECTION_CASES {
            let path = Path::new(path);
            assert_eq!(
                pedant_syntax::syntax_language(path, source),
                expected,
                "{} with source {source:?}",
                path.display()
            );
            assert_eq!(
                pedant_syntax::syntax_language(path, source),
                detect_language(path, source).map(SyntaxLanguage::from),
                "non-Rust syntax detection tracks the existing capability rules"
            );
        }
    }
}

#[path = "enclosing_unit_support/dispatch.rs"]
mod dispatch;

#[cfg(feature = "rust")]
#[path = "enclosing_unit_support/rust.rs"]
mod rust;

#[cfg(feature = "ts-python")]
#[path = "enclosing_unit_support/python.rs"]
mod python;

#[cfg(feature = "ts-javascript")]
#[path = "enclosing_unit_support/javascript.rs"]
mod javascript;

#[cfg(feature = "ts-typescript")]
#[path = "enclosing_unit_support/typescript.rs"]
mod typescript;

#[cfg(feature = "ts-go")]
#[path = "enclosing_unit_support/go.rs"]
mod go;

/// The one Go source every fact claim is read from.
#[cfg(feature = "ts-go")]
#[path = "enclosing_unit_support/go_fact_source.rs"]
mod go_fact_source;

/// What the bounded Go fact inventory states.
#[cfg(feature = "ts-go")]
#[path = "enclosing_unit_support/go_facts.rs"]
mod go_facts;

/// What that inventory states as the type of every name the source binds.
#[cfg(feature = "ts-go")]
#[path = "enclosing_unit_support/go_type_facts.rs"]
mod go_type_facts;

/// What a lowered Go fact ceiling refuses, and when.
#[cfg(feature = "ts-go")]
#[path = "enclosing_unit_support/go_fact_limits.rs"]
mod go_fact_limits;

#[cfg(feature = "ts-bash")]
#[path = "enclosing_unit_support/bash.rs"]
mod bash;

/// Needs every backend linked, so it runs in the all-features configuration the
/// plan proof names.
#[cfg(all(
    feature = "rust",
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
#[path = "enclosing_unit_support/kind_coverage.rs"]
mod kind_coverage;

/// The shared `Language` enum gains Rust, and the exhaustive conversion sends
/// it to the Rust backend, which extracts what the fixtures' Rust row already
/// writes down. Path classification and detection exemption stay with
/// `rust_is_syntax_only`, which states them for `.rs` itself.
#[cfg(feature = "rust")]
#[test]
fn rust_language_conversion_preserves_existing_rust_extraction() {
    shared_language::rust_conversion_preserves_extraction();
}
