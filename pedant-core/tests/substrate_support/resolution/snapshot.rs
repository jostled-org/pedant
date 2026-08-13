//! Bounded snapshots: target authority, root-only module closure, and
//! target-scoped dependency library unit selection.
//!
//! Each predicate below states one contract and delegates its claims to the
//! assertion modules beside it, so the fixtures, the readers, and the contracts
//! stay in separate files.

use pedant_core::capabilities::detect_capabilities;
use pedant_core::resolution::rust::{CargoTargetKind, SourceClosureFailureKind};
#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::rust::{
    PackageId, ResolutionProbe, RustProject, RustSnapshotError, unknown_target_id,
};
use pedant_types::Capability;

#[cfg(feature = "resolution-test-support")]
use crate::resolution::authority_asserts::{
    Refusal, assert_both_snapshots_refuse, assert_indices_collide,
    assert_manifest_revision_is_reread, assert_reads_only_follow_acceptance,
    indexed_manifest_reads,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::authority_invalidation::invalidated;
use crate::resolution::closure_asserts::{
    assert_cfg_attr_path_loaded_sources_use_sibling_directories, assert_closure_failure_families,
    assert_invalid_utf8_is_partial_evidence, assert_library_closure,
    assert_module_repetition_is_bounded, assert_path_loaded_source_uses_sibling_directory,
    assert_root_confinement_never_reads_outside, assert_source_evidence,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::closure_fixtures::MINIMAL_PACKAGE;
use crate::resolution::closure_fixtures::{
    EXPECTED_LIBRARY_CLOSURE, EXPECTED_LIBRARY_MODULES, LEGACY_CALLABLE_NEAR_MATCH,
    LEGACY_CALLABLE_THEN_MALFORMED, LEGACY_CALLABLES_2021, LEGACY_CALLABLES_EXPLICIT_2015,
    LEGACY_CALLABLES_INHERITED_2018, LEGACY_CALLABLES_OMITTED_EDITION, MODULE_CLOSURE,
    PRIMARY_TARGET_OVERLAP, SHARED_CALLABLE_ACROSS_EDITIONS,
};
use crate::resolution::fixture;
use crate::resolution::unit_asserts::{
    assert_activation_composition, assert_library_units, assert_same_package_library_unit,
    assert_unit_rejections,
};
use crate::resolution::unit_fixtures::{
    DEPENDENCY_UNITS, EXPECTED_BENCHMARK_UNITS, EXPECTED_BUILD_UNITS, EXPECTED_EXAMPLE_UNITS,
    EXPECTED_TEST_UNITS,
};
use crate::resolution::views::closure_kinds;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::views::observed_paths;
use crate::resolution::views::{app_library, render_units, root_modules, source_paths, target_id};

#[test]
fn snapshots_accept_bare_callable_traits_only_for_legacy_editions() {
    for (label, files, source_path) in [
        (
            "an omitted edition defaults to Rust 2015",
            LEGACY_CALLABLES_OMITTED_EDITION,
            "src/lib.rs",
        ),
        (
            "an explicit Rust 2015 edition",
            LEGACY_CALLABLES_EXPLICIT_2015,
            "src/lib.rs",
        ),
        (
            "a workspace-inherited Rust 2018 edition",
            LEGACY_CALLABLES_INHERITED_2018,
            "app/src/lib.rs",
        ),
    ] {
        let tmp = fixture::build_repository(files, false);
        let project = fixture::load_default(&tmp);
        let snapshot = project
            .snapshot_target(app_library(&project))
            .unwrap_or_else(|error| panic!("{label} should parse: {error}"));
        let source = snapshot.source(source_path).expect("the library source");
        let finding = detect_capabilities(source.ir(), None)
            .findings
            .into_iter()
            .find(|finding| finding.capability == Capability::Network)
            .expect("the later network import remains detectable");
        assert_eq!(
            (finding.location.line, finding.location.column),
            (4, 1),
            "{label}: compatibility parsing must retain original source spans"
        );
    }

    for (label, files) in [
        ("Rust 2021", LEGACY_CALLABLES_2021),
        ("a callable near-match", LEGACY_CALLABLE_NEAR_MATCH),
        (
            "malformed Rust after a callable",
            LEGACY_CALLABLE_THEN_MALFORMED,
        ),
    ] {
        let tmp = fixture::build_repository(files, false);
        let project = fixture::load_default(&tmp);
        let error = project.snapshot_target(app_library(&project)).unwrap_err();
        assert_eq!(
            closure_kinds(&error),
            [SourceClosureFailureKind::SourceParse],
            "{label} must remain a parse refusal"
        );
    }
}

#[test]
fn a_legacy_cached_tree_cannot_satisfy_a_modern_resolution_unit() {
    let tmp = fixture::build_repository(SHARED_CALLABLE_ACROSS_EDITIONS, false);
    let project = fixture::load_default(&tmp);
    let error = project
        .snapshot_resolution(app_library(&project))
        .expect_err("Rust 2021 must refuse a cached legacy-only syntax tree");
    assert_eq!(
        closure_kinds(&error),
        [SourceClosureFailureKind::SourceParse],
        "source-store reuse preserves each selected unit's edition contract"
    );
}

#[test]
fn target_snapshot_contains_only_root_target_module_closure() {
    let tmp = fixture::build_repository(MODULE_CLOSURE, false);
    let project = fixture::load_default(&tmp);
    let library = app_library(&project);
    let snapshot = project.snapshot_target(library).unwrap();
    assert_library_closure(&snapshot, library);
    assert_source_evidence(&snapshot);
    assert_eq!(
        root_modules(&project, library),
        EXPECTED_LIBRARY_MODULES,
        "every supported module form takes its own instance, and an inline \
         owner keeps its parent's source"
    );

    let binary = target_id(&project, "app", CargoTargetKind::Binary, "app");
    let binary_snapshot = project.snapshot_target(binary).unwrap();
    assert_eq!(
        source_paths(&binary_snapshot),
        ["src/main.rs"],
        "a second target in the same package sees only its own closure"
    );

    let perturbed = fixture::build_repository(MODULE_CLOSURE, true);
    let reordered = fixture::load_default(&perturbed);
    let reordered_snapshot = reordered.snapshot_target(app_library(&reordered)).unwrap();
    assert_eq!(
        source_paths(&reordered_snapshot),
        EXPECTED_LIBRARY_CLOSURE,
        "creation order cannot change the closure"
    );

    assert_module_repetition_is_bounded();
    assert_closure_failure_families();
    assert_invalid_utf8_is_partial_evidence();
    assert_root_confinement_never_reads_outside();
}

#[test]
fn path_loaded_source_resolves_ordinary_children_beside_its_file() {
    assert_path_loaded_source_uses_sibling_directory();
}

#[test]
fn path_loaded_cfg_attr_alternatives_retain_each_sibling_child() {
    assert_cfg_attr_path_loaded_sources_use_sibling_directories();
}

#[test]
fn resolution_snapshot_selects_only_target_scoped_dependency_library_units() {
    let tmp = fixture::build_repository(DEPENDENCY_UNITS, false);
    let project = fixture::load_default(&tmp);

    let library = app_library(&project);
    let snapshot = project.snapshot_resolution(library).unwrap();
    assert_library_units(&project, &snapshot);

    let root = snapshot.unit(snapshot.root_unit()).expect("the root unit");
    assert_eq!(
        root.target(),
        library,
        "the root unit is the requested target"
    );

    let test_target = target_id(&project, "app", CargoTargetKind::Test, "it");
    let test_snapshot = project.snapshot_resolution(test_target).unwrap();
    assert_eq!(
        render_units(&project, &test_snapshot),
        EXPECTED_TEST_UNITS,
        "a test root takes its library plus normal and development edges unconditionally"
    );

    let example = target_id(&project, "app", CargoTargetKind::Example, "demo");
    let example_snapshot = project.snapshot_resolution(example).unwrap();
    assert_eq!(
        render_units(&project, &example_snapshot),
        EXPECTED_EXAMPLE_UNITS,
        "an example root takes its library plus normal and development edges"
    );

    let benchmark = target_id(&project, "app", CargoTargetKind::Benchmark, "perf");
    let benchmark_snapshot = project.snapshot_resolution(benchmark).unwrap();
    assert_eq!(
        render_units(&project, &benchmark_snapshot),
        EXPECTED_BENCHMARK_UNITS,
        "a benchmark root takes its library plus normal and development edges"
    );

    let build_script = target_id(
        &project,
        "app",
        CargoTargetKind::BuildScript,
        "build-script-build",
    );
    let build_snapshot = project.snapshot_resolution(build_script).unwrap();
    assert_eq!(
        render_units(&project, &build_snapshot),
        EXPECTED_BUILD_UNITS,
        "a build-script root takes only build edges"
    );

    assert_activation_composition();
    assert_same_package_library_unit();
    assert_unit_rejections();
}

#[test]
fn package_primary_snapshot_refuses_a_later_incomplete_target() {
    let tmp = fixture::build_repository(PRIMARY_TARGET_OVERLAP, false);
    let project = fixture::load_default(&tmp);
    let package = project
        .workspace_members()
        .next()
        .expect("the fixture package");
    let binary = target_id(&project, "app", CargoTargetKind::Binary, "app");
    fixture::write_file(tmp.path(), "repo/src/main.rs", b"fn ( {\n");

    let error = project
        .snapshot_package_primary_targets(package.id())
        .expect_err("an incomplete binary refuses the whole package snapshot");

    assert_eq!(
        error.target(),
        Some(binary),
        "the refusal retains the later target that failed"
    );
    assert_eq!(
        closure_kinds(&error.into_source()),
        [pedant_core::resolution::rust::SourceClosureFailureKind::SourceParse],
        "the library completed first, but no partial package snapshot escaped"
    );
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn package_primary_snapshot_reuses_one_store_across_target_views() {
    let tmp = fixture::build_repository(PRIMARY_TARGET_OVERLAP, false);
    let project = fixture::load_default(&tmp);
    let package = project
        .workspace_members()
        .next()
        .expect("the fixture package");
    let probe = ResolutionProbe::install();

    let snapshot = project
        .snapshot_package_primary_targets(package.id())
        .expect("every primary target closes");

    let paths = snapshot
        .sources()
        .iter()
        .map(|source| source.path())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "build.rs",
            "helper.rs",
            "src/lib.rs",
            "src/main.rs",
            "src/shared.rs"
        ],
        "the package snapshot stores the root-only union"
    );
    let target_views = snapshot
        .targets()
        .iter()
        .map(|target| (target.kind(), target.sources().collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    assert_eq!(
        target_views,
        [
            (
                CargoTargetKind::Library,
                vec!["src/lib.rs", "src/shared.rs"]
            ),
            (
                CargoTargetKind::Binary,
                vec!["src/main.rs", "src/shared.rs"]
            ),
            (CargoTargetKind::BuildScript, vec!["build.rs", "helper.rs"]),
        ],
        "each primary target retains its own closure"
    );
    let parses = probe.parses();
    let observed = observed_paths(&parses);
    assert_eq!(
        observed
            .iter()
            .filter(|path| **path == "src/shared.rs")
            .count(),
        1,
        "one source shared by lib.rs and main.rs is parsed once"
    );
    assert_eq!(
        observed.len(),
        paths.len(),
        "every stored source parses once"
    );
    let reads = probe.source_reads();
    let observed_reads = observed_paths(&reads);
    assert_eq!(
        observed_reads
            .iter()
            .filter(|path| **path == "src/shared.rs")
            .count(),
        1,
        "one source shared by lib.rs and main.rs is read once"
    );
    assert_eq!(
        observed_reads.len(),
        paths.len(),
        "every stored source is read once"
    );
}

#[cfg(feature = "resolution-test-support")]
type PackageRefusal<'a> = (
    &'a str,
    &'a RustProject,
    PackageId,
    fn(&RustSnapshotError) -> bool,
);

#[cfg(feature = "resolution-test-support")]
#[test]
fn package_primary_snapshots_reject_invalid_package_authority_before_source_reads() {
    let probe = ResolutionProbe::install();
    let local_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let foreign_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let local = fixture::load_default(&local_root);
    let foreign = fixture::load_default(&foreign_root);
    let foreign_package = fixture_package(&foreign);

    let stale_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let stale_before = fixture::load_default(&stale_root);
    let stale_package = fixture_package(&stale_before);
    rewrite_fixture_manifest(&stale_root, "0.2.0");
    let reloaded = fixture::load_default(&stale_root);

    let changed_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let changed = fixture::load_default(&changed_root);
    let changed_package = fixture_package(&changed);
    rewrite_fixture_manifest(&changed_root, "0.3.0");

    let refusals: [PackageRefusal<'_>; 3] = [
        (
            "a package identity issued by another repository root",
            &local,
            foreign_package,
            |error| matches!(error, RustSnapshotError::ForeignPackage),
        ),
        (
            "a package identity issued before the manifests changed",
            &reloaded,
            stale_package,
            |error| matches!(error, RustSnapshotError::StalePackage),
        ),
        (
            "a manifest changed after the package identity was issued",
            &changed,
            changed_package,
            |error| matches!(error, RustSnapshotError::ProjectManifestsChanged { .. }),
        ),
    ];
    for refusal in &refusals {
        assert_package_refusal(refusal);
    }
    assert!(
        probe.source_reads().is_empty(),
        "package authority refusals must precede every Rust source read: {:?}",
        probe.source_reads()
    );

    local
        .snapshot_package_primary_targets(fixture_package(&local))
        .expect("a package identity issued by this unchanged project is accepted");
    assert_eq!(
        probe.source_reads().len(),
        1,
        "an accepted package reads its one source, so the zero-read refusals are not vacuous"
    );
}

#[cfg(feature = "resolution-test-support")]
fn assert_package_refusal(refusal: &PackageRefusal<'_>) {
    let (label, project, package, expected) = refusal;
    let error = project
        .snapshot_package_primary_targets(*package)
        .expect_err(label);
    assert_eq!(
        error.target(),
        None,
        "{label}: package authority must fail before selecting a target"
    );
    let source = error.into_source();
    assert!(expected(&source), "{label}: returned {source:?}");
}

#[cfg(feature = "resolution-test-support")]
fn fixture_package(project: &RustProject) -> PackageId {
    project
        .workspace_members()
        .next()
        .expect("the minimal fixture package")
        .id()
}

#[cfg(feature = "resolution-test-support")]
fn rewrite_fixture_manifest(root: &tempfile::TempDir, version: &str) {
    let manifest =
        format!("[package]\nname = \"app\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    fixture::write_file(root.path(), "repo/Cargo.toml", manifest.as_bytes());
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn snapshots_reject_invalid_target_authority_before_source_reads() {
    let probe = ResolutionProbe::install();

    let local_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let foreign_root = fixture::build_repository(MINIMAL_PACKAGE, false);
    let local = fixture::load_default(&local_root);
    let foreign = fixture::load_default(&foreign_root);
    let local_target = app_library(&local);
    let foreign_target = app_library(&foreign);
    assert_indices_collide(local_target, foreign_target);

    let (stale_root, stale_before, stale_target) = invalidated("0.2.0");
    assert!(
        stale_before.target(stale_target).is_some(),
        "the stale identity was valid for the project that issued it"
    );
    let reloaded = fixture::load_default(&stale_root);
    let (changed_root, changed, changed_target) = invalidated("0.3.0");
    assert!(
        changed_root.path().is_dir(),
        "the changed fixture outlives the assertions that read it"
    );

    let refusals: [Refusal<'_>; 4] = [
        (
            "an identity issued by another repository root",
            &local,
            foreign_target,
            |error| matches!(error, RustSnapshotError::ForeignTarget),
        ),
        (
            "an identity issued before the manifests changed",
            &reloaded,
            stale_target,
            |error| matches!(error, RustSnapshotError::StaleTarget),
        ),
        (
            "an index no target occupies",
            &local,
            unknown_target_id(&local),
            |error| matches!(error, RustSnapshotError::UnknownTarget { .. }),
        ),
        (
            "a manifest that changed after the project loaded",
            &changed,
            changed_target,
            |error| matches!(error, RustSnapshotError::ProjectManifestsChanged { .. }),
        ),
    ];
    let indexed = indexed_manifest_reads(&probe);
    for refusal in &refusals {
        assert_both_snapshots_refuse(refusal);
    }

    assert_manifest_revision_is_reread(&probe, &indexed);
    assert_reads_only_follow_acceptance(&probe, (&local, local_target), 5);
}
