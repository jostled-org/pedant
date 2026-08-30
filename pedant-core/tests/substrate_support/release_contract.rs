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
//! [`crate::release_model`] owns that model, and
//! [`crate::resolution::manifest_reader`] owns how a manifest is read.

use std::collections::{BTreeMap, BTreeSet};

use crate::packaged_workspace_claims::subject_declaration;
use crate::packaged_workspace_reading::{PACKAGED_WORKSPACE_SCRIPT, packaged_workspace_script};
use crate::release_model::{
    FIRST_PARTY_EDGES, GATED_EDGES, GatedEdge, PUBLISHED, changelog_path, declared_version,
    edge_line, release_entries, release_entry, stated_requirements,
};
use crate::release_workflow::{
    READINESS_GATE, RELEASE_WORKFLOW, assert_readiness_gates_publication,
};
use crate::resolution::authority_scan::read_text;
use crate::resolution::manifest_reader::{
    default_features, dependency_edge, feature_selection, feature_table, manifest_table,
};
use crate::resolution::root_inventory::workspace_root;
use crate::resolution::tracked_index::tracked_paths;
use crate::resolution::tracked_script::{
    SHELLCHECK_INVENTORY, assert_scripts_are_executable_and_linted,
};
use crate::shell_script_reading::tracked_shell_scripts;

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

/// Every published manifest, read from disk and parsed once.
///
/// One reading, three subjects: the versions each package declares, the
/// requirements each states, and the order those requirements force. Reading per
/// subject cost three parses of all eight files and let one subject range over a
/// set another never saw. The parse now belongs to `manifest_reader`, which
/// caches by path for the process; this map is the naming of that reading, not a
/// second copy of it.
fn published_manifests() -> BTreeMap<&'static str, &'static toml::Table> {
    PUBLISHED
        .iter()
        .map(|package| (*package, manifest_table(&format!("{package}/Cargo.toml"))))
        .collect()
}

#[test]
fn published_versions_and_requirements_form_releaseable_graph() {
    let manifests = published_manifests();
    let declared: BTreeMap<&str, Box<str>> = manifests
        .iter()
        .map(|(package, manifest)| (*package, declared_version(manifest, package)))
        .collect();

    for (package, manifest) in &manifests {
        for requirement in stated_requirements(manifest, package) {
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

    // That the release order is exactly [`PUBLISHED`], in that order, is
    // asserted once by the release-owner predicate below. An ordered equality
    // states both that each package appears once and that the set is the
    // published one, so restating either here would be a second owner of a
    // strictly weaker claim. What this loop adds is the fact that ordered
    // equality cannot state: the order is dependency-safe.
    let release = manifest_table("release-plz.toml");
    assert_release_always(release);
    let entries = release_entries(release);
    for (position, name) in entries.iter().enumerate() {
        let manifest = manifests
            .get(*name)
            .unwrap_or_else(|| panic!("release-plz.toml releases the unpublished package {name}"));
        for requirement in stated_requirements(manifest, name) {
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

/// 12.T2 (Invariants 22, 23): the release order, the gated edges, the
/// changelogs, the readiness gate, the CI and release split, and the archive
/// proof subject are the ones this release needs.
///
/// The optionality and version of the Go gated edge are also read by the Go
/// registration proof, which states the feature-closure half — that the edge
/// asks for the Go grammar alone. That proof compiles only under
/// `go-resolution`, and this one is what a default build has: the release facts
/// hold in every configuration, because packaging does.
#[test]
fn code_intelligence_release_and_archive_owners_are_exact() {
    let release = manifest_table("release-plz.toml");
    assert_eq!(
        &*release_entries(release),
        PUBLISHED.as_slice(),
        "release-plz.toml releases the published packages in dependency-safe order"
    );
    assert_release_always(release);
    assert_first_party_edges_are_exact();
    assert_every_gated_edge_is_optional_versioned_and_feature_selected();
    assert_every_package_has_one_existing_changelog(release);
    assert_the_archive_proof_states_this_release();
    assert_readiness_gates_publication();
    assert_semver_authority_is_release_only();
}

/// Every workflow file this repository tracks.
const WORKFLOW_GLOB: &str = ".github/workflows/*.yml";

/// The tagged-manifest guard, which refuses an edit to a package manifest after
/// that exact version was published.
///
/// Correct at release time and wrong at every other time: between a release and
/// the release PR that versions it, every published manifest is at a tagged
/// version, so a job that ran this guard would refuse the ordinary work of the
/// repository.
const MANIFEST_GUARD: &str = ".github/scripts/check_published_manifests.sh";

/// The guards that stand between an implementation commit and an immutable
/// version, and the step that publishes once they pass.
///
/// Each is named by the exact route a workflow invokes it through, so a job that
/// mentioned one in a comment could not answer for a job that runs it.
const PUBLICATION_ROUTES: &[&str] = &[READINESS_GATE, MANIFEST_GUARD, "command: release"];

/// release-plz is the only writer of a version, and the two guards that let it
/// write one run in exactly one place.
///
/// Every route above appears in exactly one tracked workflow, and that workflow
/// is the release one. The count is what carries the claim: ordinary
/// implementation CI that ran the tagged-manifest guard would refuse every
/// commit made between a release and the release PR that versions it, and a
/// second job that published would publish from a tree the readiness gate never
/// judged. Tracked shell scripts are read for the same reason from the other
/// side — a verification route that invoked the guard would make it something
/// an implementation step could be blocked by, and it is not.
fn assert_semver_authority_is_release_only() {
    // One selection and one reading of each workflow, for every route. Asking
    // Git per route spawned a process for each and read the same half-dozen
    // files over again, and the answer is the same commit's every time.
    let workflows: Box<[(Box<str>, String)]> = tracked_paths(WORKFLOW_GLOB)
        .into_vec()
        .into_iter()
        .map(|workflow| {
            let text = read_text(&workflow);
            (workflow, text)
        })
        .collect();
    for route in PUBLICATION_ROUTES {
        let carriers: Box<[&str]> = workflows
            .iter()
            .filter(|(_, text)| text.contains(route))
            .map(|(workflow, _)| &**workflow)
            .collect();
        assert_eq!(
            &*carriers,
            &[RELEASE_WORKFLOW],
            "[{route}] belongs to the release job alone"
        );
    }

    // Nobody runs it, and the analyser still reads it. The lint half used to be
    // proved by finding the guard's path inside the wrapper; the wrapper now
    // derives its subjects from the directories that hold them, so it names no
    // path at all and the two halves are asked separately. `--list` answers the
    // lint half against the same expansion the lint run passes to the analyser.
    //
    // The ShellCheck inventory is the one tracked script allowed to name the
    // guard, and naming is all it does: its subject list is required elsewhere
    // to equal the tracked inventory, so an exemption for it costs nothing and
    // an exemption for anything else would be a second route into the refusal.
    let naming: Box<[Box<str>]> = tracked_shell_scripts()
        .iter()
        .filter(|script| script.as_ref() != SHELLCHECK_INVENTORY)
        .filter(|script| read_text(script).contains(MANIFEST_GUARD))
        .cloned()
        .collect();
    assert_eq!(
        &*naming,
        &[] as &[Box<str>],
        "the release-only manifest guard is nobody's to run"
    );
    assert_scripts_are_executable_and_linted(&[MANIFEST_GUARD]);
}

/// The manifests state exactly the modelled first-party edges.
fn assert_first_party_edges_are_exact() {
    let mut stated: Box<[Box<str>]> = PUBLISHED
        .iter()
        .flat_map(|package| {
            let manifest = manifest_table(&format!("{package}/Cargo.toml"));
            stated_requirements(manifest, package)
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

/// Every gated edge is optional, carries a published version, is selected by
/// exactly the modelled features, and is on by default only where the model
/// says so.
///
/// Every clause is a way the same edge could stop being releasable. Without
/// `optional` the dependency is unconditional and the feature is a lie; without
/// a version, packaging leaves a path dependency a registry consumer cannot
/// resolve; without a feature selecting it, nothing turns it on; and a selector
/// nobody wrote down is a second way to link a parser or a resolver into a
/// build that asked for something else.
fn assert_every_gated_edge_is_optional_versioned_and_feature_selected() {
    for gated in GATED_EDGES {
        assert_gated_edge(gated);
        let stated = FIRST_PARTY_EDGES
            .iter()
            .find(|(consumer, kind, dependency, _)| {
                *consumer == gated.consumer
                    && *kind == "dependencies"
                    && *dependency == gated.dependency
            })
            .unwrap_or_else(|| {
                panic!(
                    "{}'s {} edge is gated, so the first-party edge table must state it",
                    gated.consumer, gated.dependency
                )
            });
        // The two tables describe one manifest from two directions, and nothing
        // makes them agree by construction. A row that appeared here and as
        // `Always` there would mean the edge lost its `optional` key while the
        // feature that selects it stayed — a build that links a resolver
        // unconditionally and a model that says it does not.
        assert_eq!(
            stated.3,
            gated.selection(),
            "{}'s {} edge is gated here and stated otherwise in the first-party edge table",
            gated.consumer,
            gated.dependency
        );
    }
}

fn assert_gated_edge(gated: &GatedEdge) {
    let GatedEdge {
        consumer,
        dependency,
        selectors: modelled,
        default_on,
    } = gated;
    let manifest = manifest_table(&format!("{consumer}/Cargo.toml"));
    let edge = dependency_edge(manifest, consumer, dependency);
    assert_eq!(
        edge.get("optional").and_then(toml::Value::as_bool),
        Some(true),
        "{consumer}'s {dependency} edge is optional"
    );
    assert!(
        edge.get("version").and_then(toml::Value::as_str).is_some(),
        "{consumer}'s {dependency} edge carries the version packaging turns into a requirement"
    );
    let selection = format!("dep:{dependency}");
    let mut selectors: Box<[&str]> = feature_table(manifest, consumer)
        .iter()
        .filter(|(feature, _)| {
            feature_selection(manifest, consumer, feature).contains(&&*selection)
        })
        .map(|(feature, _)| feature.as_str())
        .collect();
    selectors.sort_unstable();
    assert_eq!(
        &*selectors, *modelled,
        "exactly the modelled features of {consumer} select {dependency}"
    );

    let default = default_features(manifest);
    let selected: Box<[&&str]> = modelled
        .iter()
        .filter(|feature| default.iter().any(|selects| *selects == **feature))
        .collect();
    assert_eq!(
        !selected.is_empty(),
        *default_on,
        "{consumer}'s default selection of {dependency} changed; it selects {selected:?}"
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
                workspace_root().join(&*path).is_file(),
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
    let proof = packaged_workspace_script().source;
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
    let release = manifest_table("release-plz.toml");
    let pedant =
        release_entry(release, "pedant").expect("release-plz.toml declares the main package");
    assert_eq!(
        pedant.get("changelog_path").and_then(toml::Value::as_str),
        Some("./CHANGELOG.md"),
        "release-plz updates the repository changelog for the main package"
    );

    let manifest = manifest_table("pedant/Cargo.toml");
    let version = declared_version(manifest, "pedant");
    let changelog = read_text("CHANGELOG.md");
    let release_heading = format!("## [{version}](");
    assert!(
        changelog
            .lines()
            .any(|line| line.starts_with(&release_heading)),
        "the repository changelog includes the current main-package release"
    );
    assert!(
        !workspace_root().join("pedant/CHANGELOG.md").exists(),
        "a second main-package changelog would drift from the root authority"
    );
}

#[test]
fn unpublished_dev_dependencies_never_become_registry_requirements() {
    let consumers: Box<[&str]> = PUBLISHED
        .into_iter()
        .filter_map(|package| {
            let manifest = manifest_table(&format!("{package}/Cargo.toml"));
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
        &["pedant-snippet", "pedant-mcp", "pedant"],
        "the three packages whose tests spawn a process share the guard"
    );
}

#[test]
fn process_guard_windows_features_cover_job_creation_types() {
    let manifest = manifest_table("test-support/process-guard/Cargo.toml");
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
    let policy = manifest_table("deny.toml");
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
