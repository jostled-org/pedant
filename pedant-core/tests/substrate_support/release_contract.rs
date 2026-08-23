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
//! [`crate::release_model`] owns that model and the manifest readers.

use std::collections::{BTreeMap, BTreeSet};

use crate::packaged_workspace_claims::{
    PACKAGED_WORKSPACE_SCRIPT, repository_root, subject_declaration,
};
use crate::release_model::{
    FIRST_PARTY_EDGES, GATED_EDGE, PUBLISHED, changelog_path, declared_version, default_selection,
    edge_line, features, parse_toml, release_entries, release_entry, stated_requirements,
};
use crate::release_workflow::assert_readiness_gates_publication;
use crate::resolution::authority_scan::read_text;

/// `release-plz.toml` states the workspace release policy explicitly.
///
/// One owner, two callers: the release-graph predicate reads it beside the
/// order it governs, and the release-owner predicate reads it beside the
/// archives it decides get published at all.
fn assert_release_always(release: &toml::Table) {
    assert_eq!(
        release
            .get("workspace")
            .and_then(|workspace| workspace.get("release_always"))
            .and_then(toml::Value::as_bool),
        Some(true),
        "release-plz.toml states workspace release_always explicitly"
    );
}

#[test]
fn published_versions_and_requirements_form_releaseable_graph() {
    let declared: BTreeMap<&str, Box<str>> = PUBLISHED
        .iter()
        .map(|package| {
            let manifest = parse_toml(&format!("{package}/Cargo.toml"));
            (*package, declared_version(&manifest, package))
        })
        .collect();

    for package in PUBLISHED {
        let manifest = parse_toml(&format!("{package}/Cargo.toml"));
        for requirement in stated_requirements(&manifest, package) {
            let published = declared
                .get(&*requirement.dependency)
                .expect("a first-party dependency is a published package");
            assert_eq!(
                requirement.version, *published,
                "{package} requires {} at the version {} publishes",
                requirement.dependency, requirement.dependency
            );
        }
    }

    let release = parse_toml("release-plz.toml");
    assert_release_always(&release);
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
        for requirement in stated_requirements(&manifest, name) {
            let dependency_position = entries
                .iter()
                .position(|entry| **entry == *requirement.dependency)
                .expect("a first-party dependency is released too");
            assert!(
                dependency_position < position,
                "{name} is released before its dependency {}",
                requirement.dependency
            );
        }
    }
}

/// 14.T2 (Invariant 25): the release order, the gated edge, the changelogs, the
/// readiness gate, and the archive proof subject are the ones this release
/// needs.
///
/// The optionality and version of the gated edge are also read by the Go
/// registration proof, which states the feature-closure half — that the edge
/// asks for the Go grammar alone. That proof compiles only under
/// `go-resolution`, and this one is what a default build has: the release facts
/// hold in every configuration, because packaging does.
#[test]
fn go_release_and_archive_owners_are_exact() {
    let release = parse_toml("release-plz.toml");
    assert_eq!(
        &*release_entries(&release),
        PUBLISHED.as_slice(),
        "release-plz.toml releases the published packages in dependency-safe order"
    );
    assert_release_always(&release);
    assert_first_party_edges_are_exact();
    assert_the_gated_edge_is_optional_versioned_and_feature_selected();
    assert_every_package_has_one_existing_changelog(&release);
    assert_the_archive_proof_states_this_release();
    assert_readiness_gates_publication();
}

/// The manifests state exactly the modelled first-party edges.
fn assert_first_party_edges_are_exact() {
    let mut stated: Box<[Box<str>]> = PUBLISHED
        .iter()
        .flat_map(|package| {
            let manifest = parse_toml(&format!("{package}/Cargo.toml"));
            stated_requirements(&manifest, package)
                .into_vec()
                .into_iter()
                .map(|requirement| {
                    edge_line(
                        package,
                        &requirement.kind,
                        &requirement.dependency,
                        requirement.selection,
                    )
                })
        })
        .collect();
    stated.sort_unstable();
    let mut modelled: Box<[Box<str>]> = FIRST_PARTY_EDGES
        .iter()
        .map(|(consumer, kind, dependency, selection)| {
            edge_line(consumer, kind, dependency, *selection)
        })
        .collect();
    modelled.sort_unstable();
    assert_eq!(
        stated, modelled,
        "the published workspace's first-party requirement set changed"
    );
}

/// The gated edge is optional, carries a published version, and is selected by
/// exactly one feature, which is not on by default.
///
/// Every clause is a way the same edge could stop being releasable. Without
/// `optional` the dependency is unconditional and the feature is a lie; without
/// a version, packaging leaves a path dependency a registry consumer cannot
/// resolve; without the feature selecting it, nothing turns it on; and a second
/// feature selecting it would put the Go grammar in a build that asked for
/// something else.
fn assert_the_gated_edge_is_optional_versioned_and_feature_selected() {
    let (consumer, dependency, feature) = GATED_EDGE;
    let manifest = parse_toml(&format!("{consumer}/Cargo.toml"));
    let edge = manifest
        .get("dependencies")
        .and_then(|table| table.get(dependency))
        .unwrap_or_else(|| panic!("{consumer} requires {dependency}"));
    assert_eq!(
        edge.get("optional").and_then(toml::Value::as_bool),
        Some(true),
        "{consumer}'s {dependency} edge is optional"
    );
    assert!(
        edge.get("version").and_then(toml::Value::as_str).is_some(),
        "{consumer}'s {dependency} edge carries the version packaging turns into a requirement"
    );
    let selection: Box<str> = format!("dep:{dependency}").into();
    let selectors: Box<[&str]> = features(&manifest)
        .filter(|(_, selects)| selects.contains(&selection))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        &*selectors,
        &[feature],
        "exactly one feature of {consumer} selects {dependency}"
    );
    assert!(
        !default_selection(&manifest).contains(&feature.into()),
        "{consumer}'s {feature} feature stays default-off"
    );
}

/// Every published package has one changelog release-plz can write, and no two
/// packages share it.
///
/// A package whose changelog path does not exist is one release-plz stops at,
/// and two packages pointed at one file would overwrite each other's history.
/// The main package states its path because the repository changelog is the
/// root authority; the other seven take the per-package default.
fn assert_every_package_has_one_existing_changelog(release: &toml::Table) {
    let paths: BTreeSet<Box<str>> = PUBLISHED
        .iter()
        .map(|package| {
            let path = changelog_path(release, package);
            assert!(
                repository_root().join(&*path).is_file(),
                "{package} declares the changelog {path}, which release-plz cannot write"
            );
            path
        })
        .collect();
    assert_eq!(
        paths.len(),
        PUBLISHED.len(),
        "each published package owns its own changelog: {paths:?}"
    );
}

/// The tracked archive proof stages this release: this plan's breaking subject,
/// and every published package.
///
/// Both readings are one number and one sentence, and both decide what the
/// indexed proof actually verifies. A stale subject shows release-plz a release
/// that is not this one, so it stages versions the publication will not; a
/// package count below the release order packages a subset and reports a green
/// archive graph for a workspace no consumer receives.
fn assert_the_archive_proof_states_this_release() {
    let proof = read_text(PACKAGED_WORKSPACE_SCRIPT);
    let subject = subject_declaration();
    assert!(
        proof.contains(&*subject),
        "{PACKAGED_WORKSPACE_SCRIPT} stages this release with [{subject}]"
    );
    let count: Box<str> = format!("RELEASE_PACKAGE_COUNT={}", PUBLISHED.len()).into();
    assert!(
        proof.contains(&*count),
        "{PACKAGED_WORKSPACE_SCRIPT} packages all {} published archives [{count}]",
        PUBLISHED.len()
    );
}

#[test]
fn main_package_changelog_has_one_root_authority() {
    let release = parse_toml("release-plz.toml");
    let pedant =
        release_entry(&release, "pedant").expect("release-plz.toml declares the main package");
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
        !repository_root().join("pedant/CHANGELOG.md").exists(),
        "a second main-package changelog would drift from the root authority"
    );
}

#[test]
fn unpublished_dev_dependencies_never_become_registry_requirements() {
    let consumers: Box<[&str]> = PUBLISHED
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
        &*consumers,
        &["pedant-mcp", "pedant"],
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
