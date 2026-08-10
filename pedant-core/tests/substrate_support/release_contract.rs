//! Release contracts for the published workspace.
//!
//! Cargo replaces a path dependency with a registry dependency while packaging,
//! so a first-party requirement is only publishable once the dependency's own
//! version has advanced and been released first. Those facts live in seven
//! manifests plus `release-plz.toml`, and nothing in a workspace build compares
//! them. This module is that comparison.
//!
//! The case is structural: it reads tracked files and asserts a written-down
//! model. It neither builds, spawns, nor reads outside the repository.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every published package, in the order `release-plz.toml` must publish them.
///
/// Written down rather than derived: a topological sort of the manifests would
/// agree with any order the manifests happen to have, which is the fact under
/// test.
const PUBLISHED: [Package; 7] = [
    Package {
        name: "pedant-types",
        version: "0.15.0",
    },
    Package {
        name: "pedant-core",
        version: "0.20.0",
    },
    Package {
        name: "pedant-syntax",
        version: "0.3.0",
    },
    Package {
        name: "pedant-snippet",
        version: "0.3.0",
    },
    Package {
        name: "pedant-lang",
        version: "0.6.0",
    },
    Package {
        name: "pedant-mcp",
        version: "0.13.0",
    },
    Package {
        name: "pedant",
        version: "0.27.0",
    },
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
#[cfg(feature = "resolution-test-support")]
const CLASSIFIER_RUNNERS: [&str; 3] = [
    "docs/scripts/verify_step.sh",
    "docs/scripts/verify_affected.sh",
    "docs/scripts/run_resolution_proof.sh",
];

/// One published package and the version its manifest must carry.
struct Package {
    name: &'static str,
    version: &'static str,
}

/// The repository root, one level above this package.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pedant-core sits one level below the repository root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn parse_toml(relative: &str) -> toml::Table {
    toml::from_str(&read(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
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
        .filter(|(dependency, _)| PUBLISHED.iter().any(|it| it.name == dependency.as_str()))
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
    let expected: Vec<(&str, String)> = PUBLISHED
        .iter()
        .map(|package| {
            let manifest = parse_toml(&format!("{}/Cargo.toml", package.name));
            (package.name, declared_version(&manifest, package.name))
        })
        .collect();
    for (package, declared) in &expected {
        let model = PUBLISHED
            .iter()
            .find(|it| it.name == *package)
            .expect("every read package is in the model");
        assert_eq!(
            declared, model.version,
            "{package} must publish {}",
            model.version
        );
    }

    for package in &PUBLISHED {
        let manifest = parse_toml(&format!("{}/Cargo.toml", package.name));
        for (dependency, requirement) in first_party_requirements(&manifest, package.name) {
            let target = PUBLISHED
                .iter()
                .find(|it| it.name == dependency)
                .expect("a first-party dependency is a published package");
            assert_eq!(
                requirement, target.version,
                "{} requires {dependency} at the version {dependency} publishes",
                package.name
            );
        }
    }

    let release = parse_toml("release-plz.toml");
    let entries: Vec<&str> = release
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
        .collect();
    let unique: BTreeSet<&str> = entries.iter().copied().collect();
    assert_eq!(
        unique.len(),
        entries.len(),
        "release-plz.toml names each package once: {entries:?}"
    );
    assert_eq!(
        unique,
        PUBLISHED
            .iter()
            .map(|package| package.name)
            .collect::<BTreeSet<_>>(),
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
        .iter()
        .filter_map(|package| {
            let manifest = parse_toml(&format!("{}/Cargo.toml", package.name));
            let requirement = manifest
                .get("dev-dependencies")
                .and_then(|dependencies| dependencies.get("pedant-process-guard"));
            requirement.map(|requirement| {
                assert_eq!(
                    requirement.get("path").and_then(toml::Value::as_str),
                    Some("../test-support/process-guard"),
                    "{} uses the shared local process guard",
                    package.name
                );
                assert!(
                    requirement.get("version").is_none(),
                    "{} must not turn the unpublished process guard into a registry requirement",
                    package.name
                );
                package.name
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

    let classifier = read(CLASSIFIER);
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
        let source = read(runner);
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

#[cfg(feature = "resolution-test-support")]
#[test]
fn ci_installs_every_resolution_runner_tool_before_execution() {
    let workflow = read(".github/workflows/ci.yml");
    let install = workflow
        .find("sudo apt-get install --yes ripgrep")
        .expect("CI installs ripgrep for the resolution proof runner");
    let proof = workflow
        .find("docs/scripts/run_resolution_proof.sh resolution-tier1-dependency-closure")
        .expect("CI runs the Tier 1 dependency-closure proof");
    assert!(
        install < proof,
        "CI must install the proof runner's tools before invoking it"
    );
}
