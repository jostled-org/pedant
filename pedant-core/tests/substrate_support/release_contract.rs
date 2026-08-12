//! Release contracts for the published workspace.
//!
//! Cargo replaces a path dependency with a registry dependency while packaging,
//! so a first-party requirement is only publishable once the dependency's own
//! version has advanced and been released first. Those facts live in eight
//! manifests plus `release-plz.toml`, and nothing in a workspace build compares
//! them. This module is that comparison.
//!
//! The graph crate is the eighth of those manifests and the newest verification
//! subject, so this module also owns the case that holds it to
//! [`crate::graph_owners`] and [`crate::graph_proof_model`].
//!
//! The cases are structural: they read tracked files and assert a written-down
//! model. None builds, spawns, or reads outside the repository.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "resolution-test-support")]
use crate::graph_owners::{
    GRAPH_PACKAGE, assert_graph_check_and_gate_coverage, assert_graph_ci_identities,
    assert_graph_manifest, assert_graph_release_position,
};
#[cfg(feature = "resolution-test-support")]
use crate::graph_proof_model::{assert_graph_proof_runner, assert_graph_verification_routing};
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
    "pedant-core",
    "pedant-graph",
    "pedant-syntax",
    "pedant-snippet",
    "pedant-lang",
    "pedant-mcp",
    "pedant",
];

/// The exact `[verification].step` command the plan loop must invoke.
///
/// This module is the sole owner of the manifest-command clause. The indexed
/// authority proof runs in the same executable and configuration and states the
/// `[ci]` keys instead, because two readers of one clause can only agree or
/// drift, never corroborate.
#[cfg(feature = "resolution-test-support")]
const STEP_COMMAND: &str = "docs/scripts/with_build_lease.sh docs/scripts/verify_step.sh";

/// The exact `[verification].affected` command.
#[cfg(feature = "resolution-test-support")]
const AFFECTED_COMMAND: &str = "docs/scripts/with_build_lease.sh docs/scripts/verify_affected.sh";

/// The one owner of Cargo-output classification, the 75 status, and the
/// aggregate-exit priority.
#[cfg(feature = "resolution-test-support")]
const CLASSIFIER: &str = "docs/scripts/cargo_infrastructure.sh";

/// Every runner that must source that owner rather than restate its patterns.
///
/// `check_lib.sh` is not a runner and is not listed: it calls `cargo_record`
/// and `cargo_classify` without sourcing their owner, because each of the four
/// scripts below already does, and a library that sourced it too would give the
/// boundary checks a classifier they never use.
#[cfg(feature = "resolution-test-support")]
const CLASSIFIER_RUNNERS: [&str; 4] = [
    "docs/scripts/verify_step.sh",
    "docs/scripts/verify_affected.sh",
    "docs/scripts/run_resolution_proof.sh",
    "docs/scripts/run_graph_proof.sh",
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

/// The verification identities, from the one configuration that can see them.
///
/// `.manifest.toml` and the plan-loop scripts are local tooling that a clone of
/// this repository does not receive, and [`read`] panics on an unreadable path
/// rather than let an absent file read as a satisfied clause. Gating the case
/// on `resolution-test-support` keeps that panic out of the `[ci]` matrix,
/// which selects the feature nowhere; `run_resolution_proof.sh` selects it for
/// the Tier 1 and owner-registration modes, which is where this predicate is
/// required to be registered exactly once.
#[cfg(feature = "resolution-test-support")]
#[test]
fn verification_commands_are_build_lease_wrapped_and_classifier_backed() {
    let manifest = parse_toml(".manifest.toml");
    let verification = manifest
        .get("verification")
        .and_then(toml::Value::as_table)
        .expect(".manifest.toml declares [verification]");
    for (key, expected) in [("step", STEP_COMMAND), ("affected", AFFECTED_COMMAND)] {
        let declared = verification
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("[verification].{key} is declared"));
        assert_eq!(
            declared, expected,
            "[verification].{key} must run under the outer build lease"
        );
    }

    let classifier = read_text(CLASSIFIER);
    for owned in [
        "CARGO_INFRASTRUCTURE_PATTERNS=",
        "CARGO_INFRASTRUCTURE_STATUS=75",
    ] {
        assert!(
            classifier.contains(owned),
            "{CLASSIFIER} owns {owned}, and it is missing"
        );
    }

    for runner in CLASSIFIER_RUNNERS {
        let source = read_text(runner);
        assert!(
            source.contains("cargo_infrastructure.sh"),
            "{runner} must source the shared classifier"
        );
        assert!(
            !source.contains("CARGO_INFRASTRUCTURE_PATTERNS="),
            "{runner} must not restate the classifier's pattern set"
        );
        assert!(
            !source.contains("with_build_lease.sh"),
            "{runner} runs under the manifest command's lease; an inner one deadlocks"
        );
    }
}

/// Every proof runner's tools reach the job before its first invocation.
///
/// Both runners read their captures with ripgrep, and the runner image ships
/// neither. A mode invoked before the install does not fail on the claim it
/// tests; it fails on `rg: command not found`, which the classifier reads as a
/// code failure and blames on the plan.
///
/// The two owner-registration modes are not listed, because CI does not run
/// them. Each lists and then runs a complete `resolution-test-support` target
/// whose owners read `.manifest.toml` and the untracked guides, and their reader
/// panics rather than skip on an absent path. `graph_owners::GRAPH_CI_IDENTITIES`
/// is where the graph mode's absence from the workflow is asserted.
#[cfg(feature = "resolution-test-support")]
#[test]
fn ci_installs_every_proof_runner_tool_before_execution() {
    let workflow = read_text(".github/workflows/ci.yml");
    let install = workflow
        .find("sudo apt-get install --yes ripgrep")
        .expect("CI installs ripgrep for the proof runners");
    for invocation in [
        "docs/scripts/run_resolution_proof.sh resolution-tier1-dependency-closure",
        "docs/scripts/run_graph_proof.sh graph-dependency-closure",
        "docs/scripts/run_graph_proof.sh graph-source-capabilities",
    ] {
        let proof = workflow
            .find(invocation)
            .unwrap_or_else(|| panic!("CI runs {invocation}"));
        assert!(
            install < proof,
            "CI must install the proof runners' tools before invoking {invocation}"
        );
    }
}

/// The graph crate's release and verification owners, as this plan states them.
///
/// One case, because the claim is one claim: the eighth published package is
/// registered everywhere a released, scanned, gated, and proved workspace member
/// has to be registered, and a half-registered member is exactly the failure the
/// case exists to reject. Each helper it calls answers one of those questions.
///
/// The generic release graph — every first-party requirement equals its
/// dependency's declared version, and every dependency is released first — is
/// [`published_versions_and_requirements_form_releaseable_graph`]'s, and is not
/// restated here. Nor are the pre-existing `[ci]` keys, which
/// `resolution::authority_keys` owns.
///
/// `.manifest.toml` and the plan-loop scripts are local tooling a published
/// checkout does not carry, and [`read_text`] panics rather than skip on an
/// absent one. `resolution-test-support` keeps that panic out of the `[ci]` test
/// matrix, which selects the feature nowhere; `run_graph_proof.sh` selects it
/// for the configuration this predicate is required to be registered under.
#[cfg(feature = "resolution-test-support")]
#[test]
fn graph_release_and_verification_owners_are_exact() {
    assert_graph_manifest(&parse_toml(&format!("{GRAPH_PACKAGE}/Cargo.toml")));
    assert_graph_release_position(&release_entries(&parse_toml("release-plz.toml")));

    let manifest = parse_toml(".manifest.toml");
    let ci = manifest
        .get("ci")
        .and_then(toml::Value::as_table)
        .expect(".manifest.toml declares [ci]");
    let verification = manifest
        .get("verification")
        .and_then(toml::Value::as_table)
        .expect(".manifest.toml declares [verification]");

    assert_graph_ci_identities(ci, &read_text(".github/workflows/ci.yml"));
    assert_graph_check_and_gate_coverage(ci, verification);
    assert_graph_verification_routing();
    assert_graph_proof_runner();
}
