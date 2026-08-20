//! Release contracts for the published workspace.
//!
//! Cargo replaces a path dependency with a registry dependency while packaging,
//! so a first-party requirement is only publishable once the dependency's own
//! version has advanced and been released first. Those facts live in eight
//! manifests plus `release-plz.toml`, and nothing in a workspace build compares
//! them. This module is that comparison.
//!
//! The cases are structural: they read tracked files and assert a written-down
//! model. None builds, spawns, or reads outside the repository.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::resolution::authority_scan::read_text;

/// Every published package, in the order `release-plz.toml` must publish them.
///
/// The names and their order are written down rather than derived: a topological
/// sort of the manifests would agree with any order the manifests happen to have,
/// which is the fact under test.
///
/// The versions are not written down. release-plz owns every version in this
/// workspace and bumps them in a `chore: release` commit that never consults
/// this module, so a pinned version here asserts only that a copy of a manifest
/// matches the manifest, and goes stale on the release after every edit. The
/// load-bearing facts — a requirement equals the version its dependency
/// declares, and a dependency is released first — hold against the versions this
/// module reads.
const PUBLISHED: [&str; 8] = [
    "pedant-types",
    "pedant-syntax",
    "pedant-core",
    "pedant-graph",
    "pedant-snippet",
    "pedant-lang",
    "pedant-mcp",
    "pedant",
];

fn parse_toml(relative: &str) -> toml::Table {
    toml::from_str(&read_text(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

/// Every package `release-plz.toml` names, in the order it releases them.
fn release_entries(release: &toml::Table) -> Vec<&str> {
    release
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("release-plz.toml declares a package array")
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(toml::Value::as_str)
                .expect("every release-plz entry names a package")
        })
        .collect()
}

/// The version a manifest's `[package]` declares.
fn declared_version(manifest: &toml::Table, name: &str) -> String {
    manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{name} declares no package version"))
        .to_owned()
}

/// Every first-party requirement a manifest states, across dependency kinds.
fn first_party_requirements(manifest: &toml::Table, name: &str) -> Vec<(String, String)> {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|table| manifest.get(*table))
        .filter_map(toml::Value::as_table)
        .flat_map(|table| table.iter())
        .filter(|(dependency, _)| PUBLISHED.contains(&dependency.as_str()))
        .map(|(dependency, spec)| {
            let version = spec
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("{name} requires {dependency} without a version"));
            (dependency.clone(), version.to_owned())
        })
        .collect()
}

#[test]
fn published_versions_and_requirements_form_releaseable_graph() {
    let declared: BTreeMap<&str, String> = PUBLISHED
        .iter()
        .map(|package| {
            let manifest = parse_toml(&format!("{package}/Cargo.toml"));
            (*package, declared_version(&manifest, package))
        })
        .collect();

    for package in PUBLISHED {
        let manifest = parse_toml(&format!("{package}/Cargo.toml"));
        for (dependency, requirement) in first_party_requirements(&manifest, package) {
            let published = declared
                .get(dependency.as_str())
                .expect("a first-party dependency is a published package");
            assert_eq!(
                &requirement, published,
                "{package} requires {dependency} at the version {dependency} publishes"
            );
        }
    }

    let release = parse_toml("release-plz.toml");
    assert_eq!(
        release
            .get("workspace")
            .and_then(|workspace| workspace.get("release_always"))
            .and_then(toml::Value::as_bool),
        Some(true),
        "release-plz.toml states workspace release_always explicitly"
    );
    let entries = release_entries(&release);
    let unique: BTreeSet<&str> = entries.iter().copied().collect();
    assert_eq!(
        unique.len(),
        entries.len(),
        "release-plz.toml names each package once: {entries:?}"
    );
    assert_eq!(
        unique,
        PUBLISHED.into_iter().collect::<BTreeSet<_>>(),
        "release-plz.toml covers exactly the published packages"
    );

    for (position, name) in entries.iter().enumerate() {
        let manifest = parse_toml(&format!("{name}/Cargo.toml"));
        for (dependency, _) in first_party_requirements(&manifest, name) {
            let dependency_position = entries
                .iter()
                .position(|entry| *entry == dependency)
                .expect("a first-party dependency is released too");
            assert!(
                dependency_position < position,
                "{name} is released before its dependency {dependency}"
            );
        }
    }
}

#[test]
fn main_package_changelog_has_one_root_authority() {
    let release = parse_toml("release-plz.toml");
    let pedant = release
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("release-plz.toml declares packages")
        .iter()
        .find(|entry| entry.get("name").and_then(toml::Value::as_str) == Some("pedant"))
        .expect("release-plz.toml declares the main package");
    assert_eq!(
        pedant.get("changelog_path").and_then(toml::Value::as_str),
        Some("./CHANGELOG.md"),
        "release-plz updates the repository changelog for the main package"
    );

    let manifest = parse_toml("pedant/Cargo.toml");
    let version = declared_version(&manifest, "pedant");
    let changelog = read_text("CHANGELOG.md");
    let release_heading = format!("## [{version}](");
    assert!(
        changelog
            .lines()
            .any(|line| line.starts_with(&release_heading)),
        "the repository changelog includes the current main-package release"
    );
    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("pedant-core is inside the workspace root")
            .join("pedant/CHANGELOG.md")
            .exists(),
        "a second main-package changelog would drift from the root authority"
    );
}

#[test]
fn unpublished_dev_dependencies_never_become_registry_requirements() {
    let consumers: Vec<&str> = PUBLISHED
        .into_iter()
        .filter_map(|package| {
            let manifest = parse_toml(&format!("{package}/Cargo.toml"));
            let requirement = manifest
                .get("dev-dependencies")
                .and_then(|dependencies| dependencies.get("pedant-process-guard"));
            requirement.map(|requirement| {
                assert_eq!(
                    requirement.get("path").and_then(toml::Value::as_str),
                    Some("../test-support/process-guard"),
                    "{package} uses the shared local process guard"
                );
                assert!(
                    requirement.get("version").is_none(),
                    "{package} must not turn the unpublished process guard into a registry requirement"
                );
                package
            })
        })
        .collect();

    assert_eq!(
        consumers,
        ["pedant-mcp", "pedant"],
        "the two process-spawning packages share the guard"
    );
}

#[test]
fn process_guard_windows_features_cover_job_creation_types() {
    let manifest = parse_toml("test-support/process-guard/Cargo.toml");
    let features = manifest
        .get("target")
        .and_then(|targets| targets.get("cfg(windows)"))
        .and_then(|windows| windows.get("dependencies"))
        .and_then(|dependencies| dependencies.get("windows-sys"))
        .and_then(|dependency| dependency.get("features"))
        .and_then(toml::Value::as_array)
        .expect("the process guard declares Windows API features");
    assert!(
        features
            .iter()
            .any(|feature| feature.as_str() == Some("Win32_Security")),
        "CreateJobObjectW is generated only when Win32_Security is enabled"
    );
}

#[test]
fn dependency_policy_allows_only_path_wildcards() {
    let policy = parse_toml("deny.toml");
    let bans = policy
        .get("bans")
        .and_then(toml::Value::as_table)
        .expect("deny.toml declares [bans]");
    assert_eq!(
        bans.get("wildcards").and_then(toml::Value::as_str),
        Some("deny"),
        "registry wildcard dependencies remain denied"
    );
    assert_eq!(
        bans.get("allow-wildcard-paths")
            .and_then(toml::Value::as_bool),
        Some(true),
        "unpublished path-only dependencies must remain packageable"
    );
}
