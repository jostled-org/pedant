//! Tests for the substrate surface — the part of `pedant-core` that answers
//! factual questions about source text and is present in every configuration.
//!
//! This root carries no `checks` gate, so it runs under `--no-default-features`,
//! under `--no-default-features --features semantic`, and under the default set.

/// Shared readers over this crate's manifest, `lib.rs`, and test roots. Every
/// test module below derives its substrate-versus-judgment boundary from this
/// one classification, so no module reimplements it.
///
/// The `#[path]` is required. Default resolution would place the file in
/// `tests/substrate/`, which pedant's `conflicting-module-root` rule rejects
/// beside `substrate.rs`, and its advice — fold the root into
/// `substrate/mod.rs` — does not apply to a cargo test root, since cargo builds
/// a test executable per `tests/*.rs` and would stop building this one. A
/// sibling directory satisfies both: cargo declares no target for it, because
/// it holds no `main.rs`.
#[path = "substrate_support/declaration_scan.rs"]
mod declaration_scan;

mod substrate_behavior {
    use pedant_core::capabilities::detect_capabilities;
    use pedant_core::ir::extract;
    use pedant_types::Capability;

    const SOURCE: &str = "use std::fs;\n\nfn read_manifest(path: &str) -> String {\n    fs::read_to_string(path).unwrap_or_default()\n}\n";

    /// `extract` and `detect_capabilities` produce facts with no policy input:
    /// neither takes a `CheckConfig`, and neither returns a violation.
    #[test]
    fn substrate_entry_points_produce_facts_without_judgment() {
        let syntax = syn::parse_file(SOURCE).expect("the fixture source should parse");
        let ir = extract("substrate_fixture.rs", &syntax, None);

        let functions: Vec<&str> = ir.functions.iter().map(|fact| &*fact.name).collect();
        assert_eq!(
            functions,
            ["read_manifest"],
            "one free function is expected"
        );

        let use_paths: Vec<&str> = ir.use_paths.iter().map(|fact| &*fact.path).collect();
        assert_eq!(
            use_paths,
            ["std::fs", "fs::read_to_string"],
            "the import and the call path are both flattened into use-path facts"
        );

        let profile = detect_capabilities(&ir, None);
        let found: Vec<Capability> = profile.findings.iter().map(|it| it.capability).collect();
        assert_eq!(
            found,
            [Capability::FileRead],
            "`std::fs` should resolve to one file-read capability"
        );
    }
}

mod declared_surface {
    use std::collections::BTreeSet;

    use crate::declaration_scan::{
        CHECKS_FEATURE, LibSurface, PathIdents, SUBSTRATE_ROOTS, file_name, has_checks_gate,
        manifest_table, parse_rust_file, test_root_paths,
    };

    /// Non-optional dependencies of the substrate, asserted as a closed set.
    const CLOSED_DEPENDENCY_SET: &[&str] = &[
        "pedant-types",
        "proc-macro2",
        "quote",
        "sha2",
        "syn",
        "thiserror",
    ];

    #[test]
    fn judgment_test_roots_carry_the_checks_gate() {
        let surface = LibSurface::classify();
        assert!(
            !surface.judgment_names.is_empty(),
            "lib.rs should declare a judgment surface behind `{CHECKS_FEATURE}`"
        );

        let roots = test_root_paths();
        let names: Box<[Box<str>]> = roots.iter().map(|path| file_name(path)).collect();
        let mut missing_gate: Vec<Box<str>> = Vec::new();
        let mut needless_gate: Vec<&str> = Vec::new();
        for (path, name) in roots.iter().zip(&names) {
            let file = parse_rust_file(path);
            let gated = has_checks_gate(&file.attrs);
            let references = surface.judgment_references(&PathIdents::scan(&file));
            if !gated && !references.is_empty() {
                missing_gate.push(format!("{name} references {references:?}").into_boxed_str());
            }
            if gated && SUBSTRATE_ROOTS.contains(&&**name) {
                needless_gate.push(name);
            }
        }

        assert!(
            missing_gate.is_empty(),
            "test roots reach the judgment surface without a file-level checks gate: {missing_gate:?}"
        );
        assert!(
            needless_gate.is_empty(),
            "substrate test roots must carry no checks gate: {needless_gate:?}"
        );

        let present: BTreeSet<&str> = names.iter().map(|name| &**name).collect();
        for expected in SUBSTRATE_ROOTS {
            assert!(
                present.contains(*expected),
                "{expected} is asserted ungated but is not a test root"
            );
        }
    }

    #[test]
    fn checks_feature_declares_no_rust_analyzer_dependency() {
        let manifest = manifest_table();
        let features = manifest
            .get("features")
            .and_then(toml::Value::as_table)
            .expect("[features] should be declared");

        let entries = features
            .get(CHECKS_FEATURE)
            .and_then(toml::Value::as_array)
            .expect("the checks feature should be declared as a list");
        for entry in entries {
            let name = entry.as_str().expect("a feature entry should be a string");
            assert!(
                !name.contains("ra_ap_") && !name.contains("line-index"),
                "the checks feature must not enable rust-analyzer: {name}"
            );
        }

        let default = features
            .get("default")
            .and_then(toml::Value::as_array)
            .expect("the default feature should be declared as a list");
        let names: Vec<&str> = default.iter().filter_map(toml::Value::as_str).collect();
        assert_eq!(
            names,
            [CHECKS_FEATURE],
            "default should select exactly the judgment surface"
        );
    }

    #[test]
    fn non_optional_dependencies_are_the_declared_closed_set() {
        let manifest = manifest_table();
        let dependencies = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .expect("[dependencies] should be declared");
        let required: BTreeSet<&str> = dependencies
            .iter()
            .filter(|(_, spec)| !is_optional(spec))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(
            required,
            CLOSED_DEPENDENCY_SET
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            "the substrate's non-optional dependency closure changed"
        );
    }

    fn is_optional(spec: &toml::Value) -> bool {
        spec.as_table()
            .and_then(|table| table.get("optional"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }
}

mod parse_only {
    use std::path::{Path, PathBuf};

    use pedant_core::capabilities::detect_capabilities;
    use pedant_core::ir::extract;
    use pedant_types::Capability;

    use crate::declaration_scan::{LibSurface, crate_path, module_files, parse_rust_file};

    /// The sole exclusion from the scanned substrate source set, named by path
    /// rather than derived. `ir/semantic` compiles in every configuration so
    /// `extract` can accept `Option<&SemanticContext>` unconditionally, and
    /// `ir/semantic/context.rs` names rust-analyzer's workspace loader, which
    /// invokes the toolchain. Those items are `semantic`-gated, but this scanner
    /// reads source text and evaluates no `cfg`, so it cannot tell a gated item
    /// from a live one. That is also why `semantic` sits outside the claim.
    const SEMANTIC_EXCLUSION: &str = "ir/semantic";

    #[test]
    fn scanned_substrate_source_set_names_no_process_api() {
        let sources = scanned_sources();
        let excluded = excluded_root();
        assert!(
            !sources.is_empty(),
            "the scanned substrate source set should not be empty"
        );
        assert!(
            sources
                .iter()
                .any(|path| path.ends_with("ir/extract/visitor.rs")),
            "directory-module subtrees should be expanded: ir/extract/visitor.rs is missing"
        );
        assert!(
            !sources.iter().any(|path| path.starts_with(&excluded)),
            "the semantic adapter subtree should stay out of the scanned set"
        );
        assert!(
            module_files("ir")
                .iter()
                .any(|path| path.ends_with("ir/semantic/context.rs")),
            "the exclusion is not vacuous: context.rs is in the unfiltered expansion"
        );

        let offenders: Box<[Box<str>]> = sources
            .iter()
            .filter_map(|path| process_evidence(path))
            .collect();
        assert!(
            offenders.is_empty(),
            "substrate sources name a process-capability API: {offenders:?}"
        );
    }

    /// `lib.rs` plus every file of every ungated `lib.rs` module declaration,
    /// less [`SEMANTIC_EXCLUSION`].
    fn scanned_sources() -> Box<[PathBuf]> {
        let surface = LibSurface::classify();
        let excluded = excluded_root();
        let mut files = vec![crate_path("src").join("lib.rs")];
        for module in &surface.ungated_modules {
            files.extend(module_files(module));
        }
        files.retain(|path| !path.starts_with(&excluded));
        files.sort();
        files.dedup();
        files.into_boxed_slice()
    }

    /// Absolute form of [`SEMANTIC_EXCLUSION`].
    fn excluded_root() -> PathBuf {
        crate_path("src").join(SEMANTIC_EXCLUSION)
    }

    fn process_evidence(path: &Path) -> Option<Box<str>> {
        let syntax = parse_rust_file(path);
        let ir = extract(&path.to_string_lossy(), &syntax, None);
        detect_capabilities(&ir, None)
            .findings
            .iter()
            .find(|finding| finding.capability == Capability::ProcessExec)
            .map(|finding| format!("{}: {}", path.display(), finding.evidence).into_boxed_str())
    }
}

#[cfg(feature = "semantic")]
mod semantic_loader {
    use pedant_core::SemanticContext;

    use crate::declaration_scan::crate_path;

    /// The substrate-plus-semantic configuration loads a real workspace.
    /// `tests/semantic.rs` carries the checks gate, so this is that
    /// configuration's only executed loader coverage.
    #[test]
    fn semantic_context_loads_without_the_checks_feature() {
        let workspace = crate_path("tests/fixtures/semantic_workspace");
        assert!(
            SemanticContext::load(&workspace).is_some(),
            "SemanticContext::load should succeed for the committed fixture workspace"
        );
    }
}
