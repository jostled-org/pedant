//! The written-down release and verification owners of `pedant-graph`.
//!
//! The graph crate is the eighth published package and the thirty-fourth
//! integration executable, and nothing in a cargo build compares its manifest,
//! its acceptance identities, and the runner that proves them. This module is
//! that comparison, and every inventory below is stated rather than discovered:
//! a count taken from the repository agrees with whatever the repository holds,
//! so it could not reject a proof mode that quietly stopped running anything.
//!
//! Ownership is split with the modules that were already here. The generic
//! release graph — every published requirement equals its dependency's declared
//! version, and every dependency is released first — belongs to
//! [`super::release_contract`]'s dynamic eight-package case. The pre-existing
//! `[ci]` acceptance keys belong to `resolution::authority_keys`. What is stated
//! here is what this plan adds: the graph package's own manifest shape, its
//! release position, its five acceptance identities, and the eight-tree check
//! and gate commands.
//!
//! The runner's own model lives in [`crate::graph_proof_model`]: this file and
//! that one hold one type group each, and the split keeps the manifest subject
//! apart from the shell subject.
//!
//! `.manifest.toml` and the plan-loop scripts are local tooling a clone does not
//! receive, and [`read_text`] panics on an absent path rather than let a missing
//! file read as a satisfied clause. `resolution-test-support` is what decides
//! where this runs, never whether an absent subject passes.

use std::collections::BTreeSet;

use crate::graph_proof_model::{GITIGNORE_REINCLUSION, GRAPH_PROOF_RUNNER};
use crate::resolution::authority_model::FIRST_PARTY_SOURCES;
use crate::resolution::authority_scan::read_text;

/// The published graph package.
pub const GRAPH_PACKAGE: &str = "pedant-graph";

/// The version the implementation tree starts it at. release-plz owns every
/// version after this one, so this is the only version this module pins.
pub const GRAPH_INITIAL_VERSION: &str = "0.1.0";

/// The package `release-plz.toml` must release immediately before it.
pub const GRAPH_RELEASE_PREDECESSOR: &str = "pedant-core";

/// The graph's production dependencies, and whether each selects defaults.
///
/// `default-features = false` on core is the whole parse-only claim in one
/// manifest line: the judgment surface, the semantic tier, and every
/// rust-analyzer package stay out of the library closure.
pub const GRAPH_NORMAL_DEPENDENCIES: &[(&str, bool)] =
    &[("pedant-core", false), ("pedant-types", true)];

/// The one core feature the graph's dev edge may select, for the malformed
/// resolution states a validated public boundary cannot express.
pub const GRAPH_DEV_CORE_FEATURE: &str = "resolution-test-support";

/// One acceptance identity: the `[ci]` key, the manifest's exact value, and the
/// exact step `.github/workflows/ci.yml` must carry, if any.
///
/// The two spellings are stated separately because they differ for the doc
/// identity alone: a TOML basic string cannot carry an unescaped `"`, so the
/// manifest quotes `RUSTDOCFLAGS` with `'` while the workflow quotes it with
/// `"`, exactly as every other doc key in both files already does. Stating both
/// keeps the comparison exact instead of loosening it to a substring.
pub struct GraphCiIdentity {
    /// The `[ci]` key.
    pub key: &'static str,
    /// The value `.manifest.toml` declares.
    pub command: &'static str,
    /// The step the workflow runs, or `None` for a local-acceptance identity
    /// the workflow must not carry.
    pub workflow_step: Option<&'static str>,
}

/// The five acceptance identities this plan adds.
pub const GRAPH_CI_IDENTITIES: &[GraphCiIdentity] = &[
    GraphCiIdentity {
        key: "graph_dependency_closure",
        command: "docs/scripts/run_graph_proof.sh graph-dependency-closure",
        workflow_step: Some("docs/scripts/run_graph_proof.sh graph-dependency-closure"),
    },
    GraphCiIdentity {
        key: "graph_source_capabilities",
        command: "docs/scripts/run_graph_proof.sh graph-source-capabilities",
        workflow_step: Some("docs/scripts/run_graph_proof.sh graph-source-capabilities"),
    },
    // Local acceptance, and the workflow must carry no step for it. The mode
    // lists and then runs the complete `resolution-test-support` substrate
    // target, whose owners read `.manifest.toml`, `docs/design-rationale.md`,
    // and `docs/testing.md`. None of those reaches a clone, and their reader
    // panics rather than skip, so a GitHub job running this mode is red as
    // committed. `resolution-owner-registration` is local-only for exactly the
    // same reason. The graph target itself stays covered there: the workflow's
    // bare `cargo test` builds and runs it whole.
    GraphCiIdentity {
        key: "graph_owner_registration",
        command: "docs/scripts/run_graph_proof.sh graph-owner-registration",
        workflow_step: None,
    },
    GraphCiIdentity {
        key: "clippy_graph",
        command: "cargo clippy -p pedant-graph --all-targets -- -D warnings",
        workflow_step: Some("cargo clippy -p pedant-graph --all-targets -- -D warnings"),
    },
    GraphCiIdentity {
        key: "doc_graph",
        command: "RUSTDOCFLAGS='-D missing_docs' cargo doc --no-deps -p pedant-graph",
        workflow_step: Some("RUSTDOCFLAGS=\"-D missing_docs\" cargo doc --no-deps -p pedant-graph"),
    },
];

/// The eight production source trees, in the order both scan commands name them.
pub const FIRST_PARTY_SOURCE_TREES: &str = "pedant/src pedant-core/src pedant-graph/src \
                                            pedant-lang/src pedant-mcp/src pedant-snippet/src \
                                            pedant-syntax/src pedant-types/src";

/// The graph test root and its whole support tree, which the resolution
/// test-coverage key must name.
///
/// The support tree is named whole rather than child by child: the child it
/// omitted would be the one nothing checks.
pub const GRAPH_TEST_CHECK_PATHS: &[&str] = &[
    "pedant-graph/tests/graph.rs",
    "pedant-graph/tests/graph_support",
];

/// The graph manifest starts at its stated version with the stated dependency
/// shape, and declares no feature table.
pub fn assert_graph_manifest(manifest: &toml::Table) {
    let version = manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{GRAPH_PACKAGE} declares no package version"));
    assert_eq!(
        version, GRAPH_INITIAL_VERSION,
        "the implementation tree starts {GRAPH_PACKAGE} at its specified initial version"
    );

    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{GRAPH_PACKAGE} declares [dependencies]"));
    for (name, defaults) in GRAPH_NORMAL_DEPENDENCIES {
        let spec = dependencies
            .get(*name)
            .unwrap_or_else(|| panic!("{GRAPH_PACKAGE} depends on {name}"));
        assert_eq!(
            spec.get("default-features").and_then(toml::Value::as_bool),
            (!defaults).then_some(false),
            "{GRAPH_PACKAGE} must select {name}'s default features exactly as modelled"
        );
        assert!(
            spec.get("features").is_none(),
            "{GRAPH_PACKAGE}'s production edge on {name} selects no feature"
        );
    }

    let dev_core = manifest
        .get("dev-dependencies")
        .and_then(|table| table.get(GRAPH_RELEASE_PREDECESSOR))
        .unwrap_or_else(|| panic!("{GRAPH_PACKAGE} carries a dev edge on its core dependency"));
    let dev_features: Vec<&str> = dev_core
        .get("features")
        .and_then(toml::Value::as_array)
        .expect("the graph's dev core edge selects features")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(
        dev_features,
        [GRAPH_DEV_CORE_FEATURE],
        "only the malformed-input proofs select a core feature, and only this one"
    );

    assert!(
        manifest.get("features").is_none(),
        "{GRAPH_PACKAGE} declares no feature table; the active contract requires a feature-free graph crate"
    );
}

/// `release-plz.toml` releases the graph immediately after its core dependency.
pub fn assert_graph_release_position(entries: &[&str]) {
    let core = entries
        .iter()
        .position(|entry| *entry == GRAPH_RELEASE_PREDECESSOR)
        .unwrap_or_else(|| panic!("release-plz.toml releases {GRAPH_RELEASE_PREDECESSOR}"));
    let graph = entries
        .iter()
        .position(|entry| *entry == GRAPH_PACKAGE)
        .unwrap_or_else(|| panic!("release-plz.toml releases {GRAPH_PACKAGE}"));
    assert_eq!(
        graph,
        core + 1,
        "{GRAPH_PACKAGE} is registered immediately after {GRAPH_RELEASE_PREDECESSOR}: {entries:?}"
    );
}

/// Each acceptance identity holds its exact value, and the workflow a clone
/// receives runs exactly one step for it — or none, where the identity is local.
///
/// The absent case is asserted as hard as the present one. A local-acceptance
/// identity whose mode reads untracked documents is red the moment a step for it
/// lands, so "the workflow carries no step" is the claim, not an omission.
pub fn assert_graph_ci_identities(ci: &toml::Table, workflow: &str) {
    for identity in GRAPH_CI_IDENTITIES {
        let declared = ci
            .get(identity.key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("[ci].{} is declared", identity.key));
        assert_eq!(
            declared, identity.command,
            "[ci].{} must hold the acceptance command this plan states",
            identity.key
        );
        let (expected, step) = match identity.workflow_step {
            Some(step) => (1, format!("- run: {step}")),
            None => (0, format!("- run: {}", identity.command)),
        };
        let count = workflow.lines().filter(|line| line.trim() == step).count();
        assert_eq!(
            count, expected,
            "the workflow must carry exactly {expected} executable [ci].{} step: {step}",
            identity.key
        );
    }
}

/// Both scan commands cover all eight production trees, the resolution
/// test-coverage key reaches the graph root and its support tree, and the
/// shellcheck subject list names the new runner.
pub fn assert_graph_check_and_gate_coverage(ci: &toml::Table, verification: &toml::Table) {
    assert_first_party_trees_agree();

    // Equality against the trees the command names, not containment of the
    // modelled list. A ninth tree appended to the key satisfies `contains` and
    // leaves this model, `[ci].pedant_gate`, and `[verification].gate` free to
    // disagree with it.
    let check = ci_value(ci, "pedant_check");
    assert_eq!(
        scanned_trees(&check),
        modelled_trees(),
        "[ci].pedant_check must scan exactly the eight production trees: {check}"
    );

    let gate = format!("pedant gate --format github {FIRST_PARTY_SOURCE_TREES}");
    assert_eq!(
        ci_value(ci, "pedant_gate"),
        gate,
        "[ci].pedant_gate must gate all eight production trees"
    );
    assert_eq!(
        verification
            .get("gate")
            .and_then(toml::Value::as_str)
            .expect("[verification].gate is declared"),
        gate,
        "[verification].gate must gate the same eight trees on the final tree"
    );

    let coverage = ci_value(ci, "pedant_resolution_test_check");
    let paths: Vec<&str> = coverage.split_whitespace().collect();
    for path in GRAPH_TEST_CHECK_PATHS {
        assert_eq!(
            paths.iter().filter(|entry| *entry == path).count(),
            1,
            "[ci].pedant_resolution_test_check must name {path} exactly once"
        );
    }

    let shellcheck_runner = ci_value(ci, "shellcheck");
    assert_eq!(
        shellcheck_runner, "docs/scripts/run_shellcheck.sh",
        "[ci].shellcheck must use the version-pinned runner"
    );
    assert!(
        read_text(&shellcheck_runner).contains(GRAPH_PROOF_RUNNER),
        "[ci].shellcheck must lint {GRAPH_PROOF_RUNNER}"
    );
    assert!(
        read_text(".gitignore")
            .lines()
            .any(|line| line.trim() == GITIGNORE_REINCLUSION),
        "{GRAPH_PROOF_RUNNER} must be re-included, or CI reads it from a checkout that lacks it"
    );
}

/// The eight trees this module names, in the order both scan commands use.
fn modelled_trees() -> Vec<&'static str> {
    FIRST_PARTY_SOURCE_TREES.split_whitespace().collect()
}

/// The source trees one `pedant check` command names, in its own order.
fn scanned_trees(command: &str) -> Vec<&str> {
    command
        .split_whitespace()
        .filter(|argument| argument.ends_with("/src"))
        .collect()
}

/// This module's tree inventory and `resolution::authority_model`'s are one set.
///
/// Two inventories of the same eight trees, in two orders, with nothing
/// comparing them, is one inventory going stale. A ninth member added to the
/// forbidden-identifier scan and forgotten here would leave that scan sweeping
/// nine trees while the check and gate commands scanned eight, and both sides
/// would pass. Compared as sets, because the orders differ by design: the
/// commands lead with `pedant/src` and the scan sorts by path.
fn assert_first_party_trees_agree() {
    let named: BTreeSet<&str> = modelled_trees().into_iter().collect();
    let scanned: BTreeSet<&str> = FIRST_PARTY_SOURCES.iter().copied().collect();
    assert_eq!(
        named, scanned,
        "the scanned and gated tree inventory must equal the forbidden-identifier scan's"
    );
}

fn ci_value(ci: &toml::Table, key: &str) -> String {
    ci.get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("[ci].{key} is declared"))
        .to_owned()
}
