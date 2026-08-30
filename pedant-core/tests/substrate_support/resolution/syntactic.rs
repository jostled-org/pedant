//! Tier 1: the one-pass site inventory, the names it resolves, the certainty
//! it assigns, and the snapshot every result stays bound to.
//!
//! Each predicate below states one contract and delegates its claims to the
//! assertion and expectation modules beside it, so the fixtures, the readers,
//! and the contracts stay in separate files.

#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::rust::RustResolutionError;

use crate::resolution::fixture;
use crate::resolution::report_views::{
    record_for, render_bindings, render_definitions, render_records, render_references,
    render_targets, render_units, target_for,
};
use crate::resolution::syntactic_asserts::{
    assert_binding_refused, assert_coordinate_accepted, assert_coordinate_refused,
    assert_go_only_kinds_are_refused, resolution_json, resolve_library, resolve_with_snapshot,
    span_at, span_between,
};
use crate::resolution::syntactic_expectations::{
    CONDITION_CASES, CONDITION_CONTROL, CORPUS_BINDINGS, CORPUS_DEFINITIONS, CORPUS_RECORDS,
    CORPUS_UNITS, CRLF_RECORDS, IMPORT_RECORDS, IMPORT_REFERENCES, IMPORT_SCOPES,
    SAME_PACKAGE_LIBRARY_FUNCTION, SAME_PACKAGE_LIBRARY_METHOD, SAME_PACKAGE_LOCAL_METHOD,
    SHARED_DEFINITIONS, SHARED_TARGETS,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::syntactic_fixtures::RESOLUTION_CORPUS as PROBED_CORPUS;
use crate::resolution::syntactic_fixtures::{
    CONDITION_OWNERS, IMPORT_SHAPES, MISSING_SOURCE, NON_ASCII_CRLF, RENAMED_PACKAGE,
    RESOLUTION_CORPUS, SHARED_SOURCE,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::syntactic_probe::{
    CORPUS_IMPORT_WALKS, CORPUS_MANIFEST_READS, CORPUS_SOURCES, SHARED_SOURCES,
    assert_parse_route_is_single, assert_reads_stay_inside, assert_tier1_names_no_process_api,
    observed,
};
use crate::resolution::unit_fixtures::{SAME_PACKAGE_TARGETS, SEMANTIC_SHARED_SOURCE};
use crate::resolution::views::target_id;
use crate::resolution::views::{app_library, render_scopes};
use pedant_core::resolution::rust::{CargoTargetKind, RustResolver};

#[test]
fn target_resolution_rejects_mapping_file_and_coordinate_mismatch() {
    let tmp = fixture::build_repository(NON_ASCII_CRLF, false);
    let resolution = resolve_library(&tmp);
    assert_eq!(
        render_records(resolution.report()),
        CRLF_RECORDS,
        "multiline, CRLF, and non-ASCII sources resolve at exact byte columns"
    );

    let report = resolution.report();
    assert_binding_refused(
        RENAMED_PACKAGE,
        report,
        ("a foreign unit mapping", |error| {
            matches!(error, RustResolutionError::UnitMapping { .. })
        }),
    );
    assert_binding_refused(
        MISSING_SOURCE,
        report,
        ("a file the snapshot lacks", |error| {
            matches!(error, RustResolutionError::UnknownFile { .. })
        }),
    );

    let project = fixture::load_default(&tmp);
    let snapshot = project
        .snapshot_resolution(app_library(&project))
        .expect("the fixture snapshots");
    assert_coordinate_refused(
        &snapshot,
        "a line past the end of the source",
        span_at("src/lib.rs", 99, 0),
    );
    assert_coordinate_refused(
        &snapshot,
        "a column past the end of its line",
        span_at("src/lib.rs", 0, 40),
    );
    assert_coordinate_refused(
        &snapshot,
        "a column inside a multi-byte code point",
        span_at("src/lib.rs", 0, 5),
    );
    assert_coordinate_accepted(
        &snapshot,
        "a span from the start of one line to a boundary three lines below",
        span_between("src/lib.rs", (1, 0), (4, 4)),
    );
    assert_coordinate_refused(
        &snapshot,
        "a multiline span whose end column splits a code point",
        span_between("src/lib.rs", (1, 0), (4, 14)),
    );
    assert_coordinate_refused(
        &snapshot,
        "a multiline span whose end line is past the end of the source",
        span_between("src/lib.rs", (1, 0), (99, 0)),
    );
}

/// The shared report vocabulary carries every language's kinds; a Rust
/// resolution carries only the Rust subset of them.
///
/// The wrapper is the one boundary a Rust report leaves the resolver through,
/// so the subset is proved there rather than trusted of every producer. Each
/// row states a coordinate-valid report whose only unusual property is its
/// kind, and the control rows state the same shape with a Rust kind.
#[test]
fn rust_resolution_rejects_go_only_kinds() {
    let tmp = fixture::build_repository(NON_ASCII_CRLF, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project
        .snapshot_resolution(app_library(&project))
        .expect("the fixture snapshots");
    assert_go_only_kinds_are_refused(&snapshot, &span_between("src/lib.rs", (1, 0), (4, 4)));
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn tier1_probe_reads_only_the_repository_and_invokes_no_process_path() {
    let probe = ResolutionProbe::install();
    let tmp = fixture::build_repository(PROBED_CORPUS, false);
    let resolution = resolve_library(&tmp);
    assert_eq!(
        render_units(resolution.report()),
        CORPUS_UNITS,
        "the resolved report describes exactly the snapshot's units"
    );

    assert_eq!(
        &*observed(&probe.parses()),
        CORPUS_SOURCES,
        "each source is parsed once, and resolution parses none again"
    );
    assert_parse_route_is_single();
    assert_eq!(
        &*observed(&probe.site_visits()),
        CORPUS_SOURCES,
        "one site visitor runs per source"
    );
    assert_eq!(
        &*observed(&probe.source_reads()),
        CORPUS_SOURCES,
        "each source is read once"
    );
    assert_eq!(
        &*observed(&probe.import_walks()),
        CORPUS_IMPORT_WALKS,
        "each `use` item's tree is walked once, for sites and capability paths alike"
    );
    assert_eq!(probe.project_loads(), 1, "one project index is built");
    assert_eq!(
        &*observed(&probe.manifest_reads()),
        CORPUS_MANIFEST_READS,
        "indexing reads each manifest once and snapshotting re-checks each once"
    );
    assert_reads_stay_inside(&probe.source_reads());
    assert_reads_stay_inside(&probe.manifest_reads());
    assert_tier1_names_no_process_api();
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn tier1_parses_a_source_two_units_share_exactly_once() {
    let probe = ResolutionProbe::install();
    let tmp = fixture::build_repository(SHARED_SOURCE, false);
    let resolution = resolve_library(&tmp);
    assert_eq!(
        render_units(resolution.report()),
        CORPUS_UNITS,
        "both the root library and its path dependency are units"
    );

    assert_eq!(
        &*observed(&probe.parses()),
        SHARED_SOURCES,
        "a source two units instantiate is parsed once, not once per unit"
    );
    assert_eq!(
        &*observed(&probe.source_reads()),
        SHARED_SOURCES,
        "a source two units instantiate is read once, not once per unit"
    );
}

#[test]
fn syntactic_resolution_gives_a_shared_source_one_identity_per_unit() {
    let tmp = fixture::build_repository(SHARED_SOURCE, false);
    let resolution = resolve_library(&tmp);
    let report = resolution.report();
    assert_eq!(
        render_definitions(report),
        SHARED_DEFINITIONS,
        "one parsed source states its definitions once under each unit that \
         instantiates it"
    );
    assert_eq!(
        render_targets(report),
        SHARED_TARGETS,
        "every reference selects a definition of the unit it was written in, \
         never the other unit's copy of the same source"
    );
}

#[test]
fn cross_package_shared_source_warning_gives_valid_remediation() {
    let tmp = fixture::build_repository(SHARED_SOURCE, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project
        .snapshot_resolution(app_library(&project))
        .expect("the shared source snapshots completely");
    let warning = snapshot
        .warnings()
        .iter()
        .find(|warning| warning.path() == "shared/common.rs")
        .expect("the cross-package source should emit a warning");

    assert_eq!(
        warning.to_string(),
        "shared/common.rs is instantiated by multiple resolution units \
         (Cargo.toml#lib#app, crates/helper/Cargo.toml#lib#helper), but rust-analyzer cannot \
         distinguish their semantic contexts for one physical source; give each unit its own \
         physical source, or, when the units share a package library, declare the module only \
         there and reference it through the library crate",
        "the remediation must remain valid when the owners are different packages"
    );
}

#[test]
fn shared_semantic_source_warns_without_reducing_tier_one() {
    let tmp = fixture::build_repository(SEMANTIC_SHARED_SOURCE, false);
    let project = fixture::load_default(&tmp);
    let binary = target_id(&project, "app", CargoTargetKind::Binary, "tool");
    let snapshot = project
        .snapshot_resolution(binary)
        .expect("the shared-source binary snapshots completely");
    let warning = match snapshot.warnings() {
        [warning] => warning,
        warnings => panic!(
            "the one shared physical source should emit one project warning, got {warnings:?}"
        ),
    };
    assert_eq!(warning.path(), "src/common.rs");
    assert_eq!(
        warning
            .unit_keys()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>(),
        ["Cargo.toml#bin#tool", "Cargo.toml#lib#app"],
        "the warning names both stable resolution-unit identities"
    );
    assert_eq!(
        warning.to_string(),
        "src/common.rs is instantiated by multiple resolution units \
         (Cargo.toml#bin#tool, Cargo.toml#lib#app), but rust-analyzer cannot distinguish their \
         semantic contexts for one physical source; give each unit its own physical source, or, \
         when the units share a package library, declare the module only there and reference it \
         through the library crate",
        "the project warning names the layout and its remediation"
    );

    let resolution = RustResolver::resolve_syntactic(&snapshot)
        .expect("the warning does not reduce Tier 1 availability");
    let shared_calls: Vec<String> = render_targets(resolution.report())
        .into_iter()
        .filter(|record| record.contains("make@src/common.rs:7:9-7:13"))
        .collect();
    assert_eq!(
        shared_calls,
        [
            "tool|make@src/common.rs:7:9-7:13||DynamicDispatch",
            "app|make@src/common.rs:7:9-7:13||DynamicDispatch",
        ],
        "Tier 1 retains the unresolved reference in both module instances"
    );
}

#[test]
fn syntactic_inventory_preserves_import_shape_scope_and_occurrence_identity() {
    let tmp = fixture::build_repository(IMPORT_SHAPES, false);
    let (snapshot, resolution) = resolve_with_snapshot(&tmp);
    let report = resolution.report();
    assert_eq!(
        render_scopes(&snapshot, "src/lib.rs"),
        IMPORT_SCOPES,
        "an inline module opens the scope its sites are recorded in"
    );
    assert_eq!(
        render_references(report),
        IMPORT_REFERENCES,
        "alias, glob, group, and lexical scope survive, and repeated path text \
         keeps one site per occurrence"
    );
    assert_eq!(
        render_records(report),
        IMPORT_RECORDS,
        "every import shape resolves to the definition it binds"
    );
}

#[test]
fn syntactic_resolution_resolves_each_supported_unique_target_kind() {
    let tmp = fixture::build_repository(RESOLUTION_CORPUS, false);
    let resolution = resolve_library(&tmp);
    let report = resolution.report();
    assert_eq!(
        render_units(report),
        CORPUS_UNITS,
        "the root target and its always-active path dependency are both units"
    );
    assert_eq!(
        render_bindings(&resolution),
        CORPUS_BINDINGS,
        "every report unit binds back to the snapshot unit it describes"
    );
    assert_eq!(
        render_definitions(report),
        CORPUS_DEFINITIONS,
        "every module, type, trait, function, and method is a definition"
    );
    assert_eq!(
        render_records(report),
        CORPUS_RECORDS,
        "each unique module, import, call, associated function, inherent method, \
        type, trait, and path-dependency target resolves"
    );

    let shared = fixture::build_repository(SAME_PACKAGE_TARGETS, false);
    let project = fixture::load_default(&shared);
    let binary = target_id(&project, "app", CargoTargetKind::Binary, "tool");
    let snapshot = project
        .snapshot_resolution(binary)
        .expect("the binary resolves against its package library");
    let resolution =
        RustResolver::resolve_syntactic(&snapshot).expect("Tier 1 resolves the binary");
    let report = resolution.report();
    assert_eq!(target_for(report, "make", 6), SAME_PACKAGE_LOCAL_METHOD);
    assert_eq!(
        target_for(report, "app::common::shared", 7),
        SAME_PACKAGE_LIBRARY_FUNCTION
    );
    assert_eq!(target_for(report, "make", 8), SAME_PACKAGE_LIBRARY_METHOD);
}

#[test]
fn syntactic_resolution_propagates_every_cfg_owner_into_possible_candidates() {
    let tmp = fixture::build_repository(CONDITION_OWNERS, false);
    let resolution = resolve_library(&tmp);
    let report = resolution.report();
    assert_eq!(
        record_for(report, "plain", 0),
        CONDITION_CONTROL,
        "an unconditional declaration in the same fixture stays resolved"
    );
    for case in CONDITION_CASES {
        assert_eq!(
            record_for(report, case.text, case.line),
            case.expected,
            "{}: the inherited condition must make every candidate possible",
            case.owner
        );
    }
}

#[test]
fn resolution_json_is_byte_identical_after_enumeration_order_changes() {
    let forward = resolution_json(RESOLUTION_CORPUS, false);
    let reversed = resolution_json(RESOLUTION_CORPUS, true);
    assert!(
        !forward.is_empty(),
        "the corpus serializes to a non-empty document"
    );
    assert_eq!(
        String::from_utf8_lossy(&forward),
        String::from_utf8_lossy(&reversed),
        "perturbing filesystem creation order cannot change one byte"
    );
}
