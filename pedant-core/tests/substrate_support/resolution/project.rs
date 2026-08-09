//! Cargo project authority: completeness, uniqueness, determinism, validated
//! versions, workspace-member expansion, and the integration-root contract that
//! replaces `tests/workspace_members.rs`.

use std::collections::BTreeSet;

use pedant_core::resolution::rust::{
    ResolutionLimits, RustDependency, RustProject, RustProjectError,
};

use crate::resolution::fixture;
use crate::resolution::project_fixtures::{
    COMPLETE_PROJECT, EXPECTED_DEPENDENCIES, EXPECTED_PACKAGES, EXPECTED_TARGETS, MEMBER_PATTERNS,
    REJECTION_CASES,
};
use crate::resolution::root_inventory::assert_exact_integration_roots;
use crate::resolution::views::{activation_text, package_name};

fn render_packages(project: &RustProject) -> Vec<String> {
    project
        .packages()
        .iter()
        .map(|package| {
            format!(
                "{}|{}|{}|{}|{}",
                package.name(),
                package.version().as_str(),
                package.rust_version().unwrap_or("-"),
                package.manifest_path(),
                membership(package.is_workspace_member()),
            )
        })
        .collect()
}

fn membership(is_member: bool) -> &'static str {
    match is_member {
        true => "member",
        false => "dependency",
    }
}

fn render_targets(project: &RustProject) -> Vec<String> {
    project
        .targets()
        .iter()
        .map(|target| {
            format!(
                "{}|{:?}|{}|{}",
                package_name(project, target.package()),
                target.kind(),
                target.name(),
                target.entry_path(),
            )
        })
        .collect()
}

fn render_dependencies(project: &RustProject) -> Vec<String> {
    project
        .dependencies()
        .iter()
        .map(|dependency| {
            format!(
                "{}|{:?}|{}|{}|{}",
                package_name(project, dependency.source()),
                dependency.kind(),
                dependency.name(),
                activation_text(dependency.activation()),
                library_entry(project, dependency),
            )
        })
        .collect()
}

fn library_entry<'a>(project: &'a RustProject, dependency: &RustDependency) -> &'a str {
    dependency
        .library()
        .and_then(|id| project.target(id))
        .map(|target| target.entry_path())
        .unwrap_or("-")
}

#[test]
fn cargo_project_is_complete_unique_deterministic_and_versioned() {
    let ordered = fixture::build_repository(COMPLETE_PROJECT, false);
    let project = fixture::load_default(&ordered);

    assert_eq!(
        render_packages(&project),
        EXPECTED_PACKAGES,
        "every package, its validated version, and its membership must appear once"
    );
    assert_eq!(
        render_targets(&project),
        EXPECTED_TARGETS,
        "every declared and automatically discovered target must appear once"
    );
    assert_eq!(
        render_dependencies(&project),
        EXPECTED_DEPENDENCIES,
        "every dependency kind, activation, and in-repository library edge must appear once"
    );

    let members: Vec<&str> = project
        .workspace_members()
        .map(|package| package.name())
        .collect();
    assert_eq!(
        members,
        ["root-app", "alpha", "beta"],
        "workspace_members borrows declared members only"
    );

    let target_ids: BTreeSet<_> = project.targets().iter().map(|target| target.id()).collect();
    assert_eq!(
        target_ids.len(),
        project.targets().len(),
        "target identities must be unique"
    );

    let perturbed = fixture::build_repository(COMPLETE_PROJECT, true);
    let reordered = fixture::load_default(&perturbed);
    assert_eq!(render_packages(&reordered), render_packages(&project));
    assert_eq!(render_targets(&reordered), render_targets(&project));
    assert_eq!(
        render_dependencies(&reordered),
        render_dependencies(&project),
        "directory creation order must not change any public view"
    );
}

#[test]
fn cargo_project_rejects_missing_inherited_and_invalid_versions() {
    for case in REJECTION_CASES {
        let tmp = fixture::build_repository(case.files, false);
        let error = fixture::load_project(&tmp, ResolutionLimits::default()).expect_err(case.label);
        assert!(
            (case.expected)(&error),
            "{}: unexpected error {error:?}",
            case.label
        );
    }

    let absent = tempfile::tempdir().unwrap();
    let error = RustProject::load(&absent.path().join("missing"), ResolutionLimits::default())
        .expect_err("a root without a manifest cannot load");
    assert!(
        matches!(error, RustProjectError::InvalidRoot { .. }),
        "unexpected error {error:?}"
    );
}

#[test]
fn workspace_member_cases_run_from_substrate_root() {
    let tmp = fixture::build_repository(MEMBER_PATTERNS, false);
    let project = fixture::load_default(&tmp);

    let members: Vec<&str> = project
        .workspace_members()
        .map(|package| package.name())
        .collect();
    assert_eq!(
        members,
        ["alpha-plugin-http", "beta-plugin-fs", "http-util", "direct"],
        "glob, nested glob, literal member, exclusion, and manifest-less directory behavior"
    );

    let manifests: Vec<&str> = project
        .packages()
        .iter()
        .map(|package| package.manifest_path())
        .collect();
    assert_eq!(
        manifests,
        [
            "crates/alpha/plugin-http/Cargo.toml",
            "crates/beta/plugin-fs/Cargo.toml",
            "crates/http-util/Cargo.toml",
            "direct/Cargo.toml",
        ],
        "a virtual workspace manifest creates no package of its own"
    );
}

/// The 33-root transition, from the configuration a plain `cargo test` runs.
///
/// The indexed authority proof states the same contract, but it compiles only
/// under `resolution-test-support`, because its manifest and document tables
/// read files a published checkout does not carry. This root inventory reads
/// tracked test directories alone, so it belongs in the default set too, and
/// [`assert_exact_integration_roots`] is the one place either states it.
#[test]
fn testing_contract_tracks_exact_33_root_transition() {
    assert_exact_integration_roots();
}
