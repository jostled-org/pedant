//! Every configured project and snapshot ceiling, and the typed error that owns
//! it. Candidate fan-out belongs to the resolver and is proved beside it.

use pedant_core::resolution::rust::{
    ResolutionLimit, ResolutionLimits, RustProjectError, RustResolutionError, RustResolver,
    SourceClosureFailureKind,
};

use crate::resolution::fixture::{self, FixtureFile};
use crate::resolution::report_views::record_for;
use crate::resolution::syntactic_fixtures::CONDITION_OWNERS;
use crate::resolution::views::{app_library, closure_kinds};

/// The one reference in [`CONDITION_OWNERS`] that names two definitions, and
/// the complete record it must carry when the ceiling admits both.
///
/// Read off the fixture: `src/plain.rs` states `marker` twice, under `unix` and
/// under `not(unix)`, and `src/lib.rs:46` calls it once from an unconditional
/// body. This tier evaluates no predicate, so neither definition is discarded
/// and neither is preferred — two possible candidates, `ConditionalCompilation`
/// because both are conditional, and `Ambiguous` because more than one remains.
const FANNED_OUT_REFERENCE: (&str, u32, &str) = (
    "plain::marker",
    46,
    "plain::marker@src/lib.rs:46:4-46:17|Possible:marker,Possible:marker|ConditionalCompilation,Ambiguous",
);

/// A repository deep enough in modules, sources, bytes, and dependency hops to
/// cross every snapshot ceiling once that ceiling is lowered on its own.
const BOUNDED_REPOSITORY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
one = { path = "crates/one" }
"#,
    ),
    ("repo/src/lib.rs", "pub mod alpha;\n"),
    ("repo/src/alpha.rs", "pub mod beta;\n"),
    ("repo/src/alpha/beta.rs", "pub fn beta() { { { } } }\n"),
    (
        "repo/crates/one/Cargo.toml",
        r#"[package]
name = "one"
version = "0.1.0"
edition = "2021"

[dependencies]
two = { path = "../two" }
"#,
    ),
    ("repo/crates/one/src/lib.rs", "pub fn one() {}\n"),
    (
        "repo/crates/two/Cargo.toml",
        "[package]\nname = \"two\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/two/src/lib.rs", "pub fn two() {}\n"),
];

/// A workspace whose members are stated as a glob, so loading it walks the
/// tree before it reads a manifest. `BOUNDED_REPOSITORY` states no
/// `[workspace]` at all, so the member scan never runs there.
const GLOB_WORKSPACE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[workspace]
members = ["crates/*"]
resolver = "2"
"#,
    ),
    (
        "repo/crates/one/Cargo.toml",
        "[package]\nname = \"one\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/one/src/lib.rs", "pub fn one() {}\n"),
    (
        "repo/crates/two/Cargo.toml",
        "[package]\nname = \"two\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/two/src/lib.rs", "pub fn two() {}\n"),
];

/// One lowered snapshot ceiling and the limit its failure must name.
struct SnapshotLimitCase {
    label: &'static str,
    limits: fn(ResolutionLimits) -> ResolutionLimits,
    expected: ResolutionLimit,
}

const SNAPSHOT_LIMIT_CASES: &[SnapshotLimitCase] = &[
    SnapshotLimitCase {
        label: "three resolution units under a ceiling of one",
        limits: |limits| ResolutionLimits {
            max_units: 1,
            ..limits
        },
        expected: ResolutionLimit::Units,
    },
    SnapshotLimitCase {
        label: "five distinct sources under a ceiling of two",
        limits: |limits| ResolutionLimits {
            max_source_files: 2,
            ..limits
        },
        expected: ResolutionLimit::SourceFiles,
    },
    SnapshotLimitCase {
        label: "a source larger than one byte",
        limits: |limits| ResolutionLimits {
            max_source_file_bytes: 1,
            ..limits
        },
        expected: ResolutionLimit::SourceFileBytes,
    },
    SnapshotLimitCase {
        label: "distinct source text past the total byte ceiling",
        limits: |limits| ResolutionLimits {
            max_total_source_bytes: 20,
            ..limits
        },
        expected: ResolutionLimit::TotalSourceBytes,
    },
    SnapshotLimitCase {
        label: "a module two levels below the crate root",
        limits: |limits| ResolutionLimits {
            max_module_depth: 1,
            ..limits
        },
        expected: ResolutionLimit::ModuleDepth,
    },
    SnapshotLimitCase {
        label: "a dependency two hops from the root target",
        limits: |limits| ResolutionLimits {
            max_dependency_depth: 1,
            ..limits
        },
        expected: ResolutionLimit::DependencyDepth,
    },
    SnapshotLimitCase {
        label: "a source nested deeper than the syntax ceiling",
        limits: |limits| ResolutionLimits {
            max_syntax_depth: 2,
            ..limits
        },
        expected: ResolutionLimit::SyntaxDepth,
    },
];

fn assert_documented_defaults() {
    let limits = ResolutionLimits::default();
    assert_eq!(limits.max_manifests, 4_096, "manifest ceiling");
    assert_eq!(limits.max_units, 4_096, "resolution-unit ceiling");
    assert_eq!(limits.max_source_files, 65_536, "distinct-source ceiling");
    assert_eq!(
        limits.max_source_file_bytes,
        8 * 1_024 * 1_024,
        "per-source byte ceiling"
    );
    assert_eq!(
        limits.max_total_source_bytes,
        512 * 1_024 * 1_024,
        "total source byte ceiling"
    );
    assert_eq!(limits.max_module_depth, 256, "module-depth ceiling");
    assert_eq!(limits.max_dependency_depth, 256, "dependency-depth ceiling");
    assert_eq!(limits.max_syntax_depth, 256, "syntax-depth ceiling");
    assert_eq!(
        limits.max_candidates_per_reference, 1_024,
        "candidate fan-out ceiling"
    );
    assert_eq!(
        limits.max_member_scan_entries, 65_536,
        "member-glob scan ceiling"
    );
    assert_eq!(
        limits.max_module_instances, 65_536,
        "module-instance ceiling"
    );
}

/// The member-glob scan is charged before any manifest is read, so it reports
/// its own ceiling rather than the manifest one.
fn assert_member_scan_limit_is_project_owned() {
    let tmp = fixture::build_repository(GLOB_WORKSPACE, false);
    fixture::load_project(&tmp, ResolutionLimits::default())
        .expect("the glob workspace loads under the documented defaults");
    let error = fixture::load_project(
        &tmp,
        ResolutionLimits {
            max_member_scan_entries: 1,
            ..ResolutionLimits::default()
        },
    )
    .expect_err("a glob workspace under a scan ceiling of one");
    assert!(
        matches!(
            error,
            RustProjectError::MemberScanLimitExceeded { limit: 1 }
        ),
        "walking the tree is bounded separately from reading manifests: {error:?}"
    );
}

fn assert_manifest_limit_is_project_owned() {
    let tmp = fixture::build_repository(BOUNDED_REPOSITORY, false);
    let error = fixture::load_project(
        &tmp,
        ResolutionLimits {
            max_manifests: 1,
            ..ResolutionLimits::default()
        },
    )
    .expect_err("three manifests under a ceiling of one");
    assert!(
        matches!(error, RustProjectError::LimitExceeded { limit: 1 }),
        "the manifest ceiling belongs to project loading, not to a snapshot: {error:?}"
    );
}

fn assert_snapshot_limits_report_their_owner() {
    let tmp = fixture::build_repository(BOUNDED_REPOSITORY, false);
    let baseline = fixture::load_default(&tmp);
    baseline
        .snapshot_resolution(app_library(&baseline))
        .expect("the fixture resolves under the documented defaults");

    for case in SNAPSHOT_LIMIT_CASES {
        let limits = (case.limits)(ResolutionLimits::default());
        let project =
            fixture::load_project(&tmp, limits).expect("loading stays within its own ceiling");
        let error = project
            .snapshot_resolution(app_library(&project))
            .expect_err(case.label);
        assert_eq!(
            closure_kinds(&error),
            [SourceClosureFailureKind::LimitExceeded(case.expected)],
            "{}: unexpected failures",
            case.label
        );
    }
}

fn assert_full_fan_out_is_reported() {
    let tmp = fixture::build_repository(CONDITION_OWNERS, false);
    let project = fixture::load_default(&tmp);
    let snapshot = project.snapshot_resolution(app_library(&project)).unwrap();
    let resolution = RustResolver::resolve_syntactic(&snapshot)
        .expect("the documented candidate ceiling admits both definitions");
    let (text, line, expected) = FANNED_OUT_REFERENCE;
    assert_eq!(
        record_for(resolution.report(), text, line),
        expected,
        "a reference under the ceiling reports every candidate it found"
    );
}

fn assert_candidate_overflow_is_typed() {
    let tmp = fixture::build_repository(CONDITION_OWNERS, false);
    let project = fixture::load_project(
        &tmp,
        ResolutionLimits {
            max_candidates_per_reference: 1,
            ..ResolutionLimits::default()
        },
    )
    .expect("loading stays within its own ceiling");
    let snapshot = project.snapshot_resolution(app_library(&project)).unwrap();
    let error = RustResolver::resolve_syntactic(&snapshot)
        .expect_err("two candidates under a ceiling of one");
    assert!(
        matches!(error, RustResolutionError::LimitExceeded { limit: 1 }),
        "candidate fan-out belongs to the resolver, not to a snapshot: {error:?}"
    );
}

#[test]
fn candidate_limit_is_typed_and_never_truncates() {
    assert_full_fan_out_is_reported();
    assert_candidate_overflow_is_typed();
}

#[test]
fn project_and_snapshot_limits_report_each_owner() {
    assert_documented_defaults();
    assert_manifest_limit_is_project_owned();
    assert_member_scan_limit_is_project_owned();
    assert_snapshot_limits_report_their_owner();
}
