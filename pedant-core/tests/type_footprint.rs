//! Whole-crate inherent-impl aggregation: `high-method-count` across files and
//! `scattered-inherent-impl`.

use std::path::{Path, PathBuf};

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::analyze_with_shape;
use pedant_core::project::{FileShape, ProjectContext, check_project};
use pedant_core::violation::{Severity, Violation, ViolationType};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn config() -> CheckConfig {
    CheckConfig {
        check_high_method_count: true,
        check_scattered_inherent_impl: true,
        max_methods: 15,
        ..CheckConfig::default()
    }
}

/// Run the full per-file + project pipeline over a fixture crate's `src/`.
fn run(crate_dir: &str, config: &CheckConfig) -> Vec<Violation> {
    let root = fixture(crate_dir);
    let mut files: Vec<String> = std::fs::read_dir(root.join("src"))
        .unwrap()
        .map(|e| e.unwrap().path().to_string_lossy().into_owned())
        .collect();
    files.sort();

    let mut violations = Vec::new();
    let mut shapes: Vec<FileShape> = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        let (result, shape) = analyze_with_shape(file, &source, config, None).unwrap();
        violations.extend(result.violations.into_vec());
        shapes.push(shape);
    }

    let ctx = ProjectContext {
        rust_files: &files,
        workspace_root: &root,
        metadata: None,
        file_shapes: &shapes,
    };
    check_project(&ctx, config, &mut violations);
    violations
}

fn method_counts(violations: &[Violation]) -> Vec<String> {
    violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::HighMethodCount { .. }))
        .map(|v| v.message.to_string())
        .collect()
}

fn scattered(violations: &[Violation]) -> Vec<&Violation> {
    violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::ScatteredInherentImpl))
        .collect()
}

/// The regression this check exists for: moving half an `impl` into a second
/// file must not change the god-object verdict.
#[test]
fn test_split_impl_reports_same_method_count_as_single_file() {
    let single = method_counts(&run("single_impl", &config()));
    let split = method_counts(&run("split_impl", &config()));

    assert_eq!(single.len(), 1, "single-file layout: {single:?}");
    assert_eq!(split.len(), 1, "split layout: {split:?}");
    assert!(
        single[0].contains("`God` has 20 inherent methods"),
        "single-file layout: {single:?}"
    );
    assert!(
        split[0].contains("`God` has 20 inherent methods"),
        "split layout must count the same 20 methods: {split:?}"
    );
}

#[test]
fn test_split_impl_reports_scattered_inherent_impl() {
    let violations = run("split_impl", &config());
    let hits = scattered(&violations);
    assert_eq!(hits.len(), 1, "{:?}", method_counts(&violations));
    assert_eq!(hits[0].severity, Severity::Warn);
    assert!(hits[0].message.contains("`God`"), "{}", hits[0].message);
    assert!(hits[0].message.contains("2 files"), "{}", hits[0].message);
    // Reported at the type's definition site, the one place that is not scattered.
    assert!(
        hits[0].file_path.ends_with("lib.rs"),
        "{}",
        hits[0].file_path
    );
}

/// A single-file god-object is not scattered; only `high-method-count` fires.
#[test]
fn test_single_file_impl_is_not_scattered() {
    assert!(scattered(&run("single_impl", &config())).is_empty());
}

/// One file is all the evidence there is: aggregation must degrade to today's
/// per-file behavior rather than report a partial total.
#[test]
fn test_single_file_invocation_degrades_to_per_file() {
    let file = fixture("split_impl/src/god_a.rs");
    let path = file.to_string_lossy().into_owned();
    let source = std::fs::read_to_string(&file).unwrap();
    let config = config();
    let (result, shape) = analyze_with_shape(&path, &source, &config, None).unwrap();

    let mut violations = result.violations.into_vec();
    let files = [path];
    let ctx = ProjectContext {
        rust_files: &files,
        workspace_root: &fixture("split_impl"),
        metadata: None,
        file_shapes: std::slice::from_ref(&shape),
    };
    check_project(&ctx, &config, &mut violations);

    // 10 methods, and no definition site in view: nothing to report either way.
    assert!(method_counts(&violations).is_empty());
    assert!(scattered(&violations).is_empty());
}

/// Mutually exclusive `#[cfg]` impls never coexist in one build, so their
/// methods must not be summed and they must not read as scattering — whether
/// the gate sits on the `mod` declaration or on the `impl` block itself.
///
/// `Handle` and `Direct` each hold 10 methods per platform. Summing would give
/// 20 and invent a god-object; the max gives 10.
#[test]
fn test_mutually_exclusive_cfg_impls_are_not_summed() {
    let violations = run("cfg_split_impl", &config());
    assert!(
        method_counts(&violations).is_empty(),
        "platform impls must not sum: {:?}",
        method_counts(&violations)
    );
    assert!(scattered(&violations).is_empty());
}

/// The default-on-feature evasion: `#[cfg(feature = "extra")]` where `extra` is
/// in `default` compiles in every ordinary build, so all 20 methods ship. A
/// cfg must never buy an exemption — that would reinstate the very evasion this
/// check exists to close, one layer up.
///
/// Shape A gates the `mod` declaration; Shape B gates the `impl` block. Both
/// must be caught.
#[test]
fn test_default_on_feature_gate_does_not_hide_god_object() {
    for fixture in ["default_feature_mod", "default_feature_impl"] {
        let violations = run(fixture, &config());
        let hits = method_counts(&violations);
        assert_eq!(
            hits.len(),
            1,
            "{fixture} evaded high-method-count: {hits:?}"
        );
        assert!(
            hits[0].contains("`God` has 20 inherent methods"),
            "{fixture}: the 8 unconditional methods plus the 12 gated ones all \
             ship on default features: {hits:?}"
        );
        assert_eq!(scattered(&violations).len(), 1, "{fixture}");
    }
}

/// The unconditional core is counted on top of the richest alternative, not
/// instead of it: a shared base plus mutually exclusive platform halves is
/// measured as base + one half.
#[test]
fn test_unconditional_core_adds_to_the_richest_alternative() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        format!(
            "#[cfg(unix)]\nmod unix;\n#[cfg(windows)]\nmod windows;\npub struct Handle;\n{}",
            impl_block_no_import("Handle", 0, 10)
        ),
    )
    .unwrap();
    std::fs::write(root.join("src/unix.rs"), impl_block("Handle", 10, 18)).unwrap();
    std::fs::write(root.join("src/windows.rs"), impl_block("Handle", 18, 26)).unwrap();

    // 10 unconditional + max(8 unix, 8 windows) = 18 > 15. Summing both
    // platforms would say 26; neither build has that.
    let hits = method_counts(&run_dir(root, &config()));
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].contains("18 inherent methods"), "{hits:?}");
}

/// Impls under the *same* predicate do compile together, so they sum.
#[test]
fn test_same_predicate_impls_sum() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "#[cfg(unix)]\nmod a;\n#[cfg(unix)]\nmod b;\npub struct God;",
    )
    .unwrap();
    std::fs::write(root.join("src/a.rs"), impl_block("God", 0, 10)).unwrap();
    std::fs::write(root.join("src/b.rs"), impl_block("God", 10, 20)).unwrap();

    let hits = method_counts(&run_dir(root, &config()));
    assert_eq!(
        hits.len(),
        1,
        "both are `cfg(unix)`, so a unix build has all 20: {hits:?}"
    );
    assert!(hits[0].contains("20 inherent methods"), "{hits:?}");
}

/// A gated `mod` carries its predicate down to ungated submodules, which are
/// just as conditional as the module declaring them.
#[test]
fn test_gate_propagates_into_submodules() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src/unix")).unwrap();
    std::fs::create_dir_all(root.join("src/windows")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "#[cfg(unix)]\nmod unix;\n#[cfg(windows)]\nmod windows;\npub struct Handle;",
    )
    .unwrap();
    // Each platform's impls live in an ungated submodule of a gated module.
    std::fs::write(root.join("src/unix/mod.rs"), "mod inner;").unwrap();
    std::fs::write(root.join("src/unix/inner.rs"), impl_block("Handle", 0, 20)).unwrap();
    std::fs::write(root.join("src/windows/mod.rs"), "mod inner;").unwrap();
    std::fs::write(
        root.join("src/windows/inner.rs"),
        impl_block("Handle", 20, 40),
    )
    .unwrap();

    // Each platform has 20 in one file: the per-file check owns those. The
    // crate-wide view must not sum them into 40 across 2 files.
    let violations = run_dir(root, &config());
    assert!(
        scattered(&violations).is_empty(),
        "platform halves never coexist: {:?}",
        scattered(&violations)
            .iter()
            .map(|v| v.message.to_string())
            .collect::<Vec<_>>()
    );
    let hits = method_counts(&violations);
    assert!(
        hits.iter().all(|m| !m.contains("40 inherent")),
        "must not sum mutually exclusive platforms: {hits:?}"
    );
}

#[test]
fn test_scattered_inherent_impl_disabled_by_default() {
    let config = CheckConfig {
        check_high_method_count: true,
        max_methods: 15,
        ..CheckConfig::default()
    };
    assert!(scattered(&run("split_impl", &config)).is_empty());
    // The high-method-count amendment is not gated on the new check.
    assert_eq!(method_counts(&run("split_impl", &config)).len(), 1);
}

#[test]
fn test_high_method_count_disabled_leaves_only_scattered() {
    let config = CheckConfig {
        check_scattered_inherent_impl: true,
        max_methods: 15,
        ..CheckConfig::default()
    };
    let violations = run("split_impl", &config);
    assert!(method_counts(&violations).is_empty());
    assert_eq!(scattered(&violations).len(), 1);
}

/// When one file's slice already trips the ceiling, the crate-wide count must
/// replace it rather than be reported alongside it.
#[test]
fn test_aggregate_supersedes_the_per_file_finding() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(root.join("src/lib.rs"), "mod a;\nmod b;\npub struct God;").unwrap();
    // a.rs alone exceeds the ceiling; b.rs pushes the true total to 25.
    std::fs::write(root.join("src/a.rs"), impl_block("God", 0, 20)).unwrap();
    std::fs::write(root.join("src/b.rs"), impl_block("God", 20, 25)).unwrap();

    let hits = method_counts(&run_dir(root, &config()));
    assert_eq!(
        hits.len(),
        1,
        "expected one finding, not a per-file duplicate: {hits:?}"
    );
    assert!(hits[0].contains("25 inherent methods"), "{hits:?}");
}

/// Supersession is scoped: a same-named type in another crate keeps its own
/// per-file finding.
#[test]
fn test_supersession_does_not_reach_across_crates() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Crate `far`: a single-file God of 20 — the per-file check owns it.
    std::fs::create_dir_all(root.join("far/src")).unwrap();
    std::fs::write(root.join("far/Cargo.toml"), "[package]\nname = \"far\"\n").unwrap();
    std::fs::write(root.join("far/src/lib.rs"), "mod a;\npub struct God;").unwrap();
    std::fs::write(root.join("far/src/a.rs"), impl_block("God", 0, 20)).unwrap();

    // Crate `near`: the same name, scattered — the project pass supersedes here.
    std::fs::create_dir_all(root.join("near/src")).unwrap();
    std::fs::write(root.join("near/Cargo.toml"), "[package]\nname = \"near\"\n").unwrap();
    std::fs::write(
        root.join("near/src/lib.rs"),
        "mod a;\nmod b;\npub struct God;",
    )
    .unwrap();
    std::fs::write(root.join("near/src/a.rs"), impl_block("God", 0, 20)).unwrap();
    std::fs::write(root.join("near/src/b.rs"), impl_block("God", 20, 25)).unwrap();

    let hits = method_counts(&run_dir(root, &config()));
    assert_eq!(hits.len(), 2, "{hits:?}");
    assert!(
        hits.iter()
            .any(|m| m.contains("`God` has 20 inherent methods (limit")),
        "far's per-file finding must survive: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|m| m.contains("25 inherent methods across 2 files")),
        "near's aggregate must replace its per-file slice: {hits:?}"
    );
}

/// Ambiguous names are skipped: pedant sees `Foo`, not a resolved path, so two
/// definition sites in one crate make the aggregate unattributable.
#[test]
fn test_ambiguous_type_name_produces_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    write_two_impls(root, "pub struct Dup;", "pub struct Dup;");

    let violations = run_dir(root, &config());
    assert!(method_counts(&violations).is_empty());
    assert!(scattered(&violations).is_empty());
}

/// Files in different crates are separate aggregation groups even when they
/// share a type name.
#[test]
fn test_separate_crates_do_not_merge() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for name in ["one", "two"] {
        std::fs::create_dir_all(root.join(name).join("src")).unwrap();
        std::fs::write(
            root.join(name).join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\n"),
        )
        .unwrap();
        std::fs::write(root.join(name).join("src/lib.rs"), "pub struct Split;").unwrap();
        std::fs::write(root.join(name).join("src/a.rs"), impl_block("Split", 0, 10)).unwrap();
    }
    let violations = run_dir(root, &config());
    // Each crate has one impl file: not scattered, and 10 < 15 either way.
    assert!(scattered(&violations).is_empty());
    assert!(method_counts(&violations).is_empty());
}

/// Forwarder exclusion applies to the aggregate, as it does per file.
#[test]
fn test_forwarders_excluded_from_aggregate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "mod a;\nmod b;\npub struct Facade { inner: usize }",
    )
    .unwrap();
    std::fs::write(root.join("src/a.rs"), forwarder_block("Facade", 0, 10)).unwrap();
    std::fs::write(root.join("src/b.rs"), forwarder_block("Facade", 10, 20)).unwrap();

    assert!(method_counts(&run_dir(root, &config())).is_empty());

    let counting = CheckConfig {
        count_forwarders: true,
        ..config()
    };
    let hits = method_counts(&run_dir(root, &counting));
    assert_eq!(hits.len(), 1);
    assert!(hits[0].contains("20 inherent methods"), "{hits:?}");
}

fn impl_block(ty: &str, from: usize, to: usize) -> String {
    format!("use super::{ty};\n\n{}", impl_block_no_import(ty, from, to))
}

/// An `impl` block for a type declared in the same file.
fn impl_block_no_import(ty: &str, from: usize, to: usize) -> String {
    let body: String = (from..to)
        .map(|i| format!("    pub fn m{i}(&self) -> usize {{\n        {i}\n    }}\n"))
        .collect();
    format!("impl {ty} {{\n{body}}}\n")
}

fn forwarder_block(ty: &str, from: usize, to: usize) -> String {
    let body: String = (from..to)
        .map(|i| format!("    pub fn m{i}(&self) -> usize {{\n        self.inner.m{i}()\n    }}\n"))
        .collect();
    format!("use super::{ty};\n\nimpl {ty} {{\n{body}}}\n")
}

fn write_two_impls(root: &Path, lib_a: &str, lib_b: &str) {
    std::fs::write(root.join("src/lib.rs"), "mod a;\nmod b;\n").unwrap();
    std::fs::write(
        root.join("src/a.rs"),
        format!("{lib_a}\n{}", impl_block("Dup", 0, 10)),
    )
    .unwrap();
    std::fs::write(
        root.join("src/b.rs"),
        format!("{lib_b}\n{}", impl_block("Dup", 10, 20)),
    )
    .unwrap();
}

/// Like [`run`], but over an arbitrary directory tree of `.rs` files.
fn run_dir(root: &Path, config: &CheckConfig) -> Vec<Violation> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files.sort();

    let mut violations = Vec::new();
    let mut shapes: Vec<FileShape> = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        let (result, shape) = analyze_with_shape(file, &source, config, None).unwrap();
        violations.extend(result.violations.into_vec());
        shapes.push(shape);
    }
    let ctx = ProjectContext {
        rust_files: &files,
        workspace_root: root,
        metadata: None,
        file_shapes: &shapes,
    };
    check_project(&ctx, config, &mut violations);
    violations
}

fn collect_rust_files(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match path.is_dir() {
            true => collect_rust_files(&path, out),
            false => push_rust_file(&path, out),
        }
    }
}

fn push_rust_file(path: &Path, out: &mut Vec<String>) {
    if path.extension().is_some_and(|e| e == "rs") {
        out.push(path.to_string_lossy().into_owned());
    }
}
