//! The written-down model of `docs/scripts/run_graph_proof.sh`.
//!
//! The runner is the artifact that decides what the graph's repository-boundary
//! proofs execute, and nothing in a cargo build reads it. This module does: it
//! parses the script's declarations back out of its text, through
//! [`crate::shell_script`], and compares them whole with the model below.
//! Equality is the point. A containment check would accept a runner that had
//! quietly dropped half its inventory, which is the regression worth catching.
//!
//! The scripts are local tooling a clone does not receive, and [`read_text`]
//! panics on an absent path rather than let a missing file read as a satisfied
//! clause.

use std::collections::{BTreeMap, BTreeSet};

use crate::resolution::authority_scan::read_text;
use crate::shell_script::{assert_registration_rows, mode_arms, model_scalars};

/// The graph proof runner, which this model reads as a text.
pub const GRAPH_PROOF_RUNNER: &str = "docs/scripts/run_graph_proof.sh";

/// The three modes it accepts, and no fourth.
pub const GRAPH_PROOF_MODES: &[&str] = &[
    "graph-dependency-closure",
    "graph-source-capabilities",
    "graph-owner-registration",
];

/// Every shell scalar the runner's fixed model must declare, and no other.
///
/// The two `cargo tree` commands are the dependency proof: capturing the
/// library's `normal,build,features` edges apart from the harness's
/// `normal,build,dev,features` edges is what stops dev-only feature unification
/// from masquerading as the published library's shape.
///
/// Compared as a set, so the coverage runs in both directions. Asking the
/// runner for each modelled name proved only that those three survive; a fourth
/// scalar the runner added, or a re-declaration further down the same section,
/// was invisible to the model and to the lookup that took the first match.
pub const GRAPH_PROOF_SCALARS: &[(&str, &str)] = &[
    (
        "PRODUCTION_TREE_COMMAND",
        "cargo tree -p pedant-graph --no-default-features --edges normal,build,features --prefix none",
    ),
    (
        "TEST_TREE_COMMAND",
        "cargo tree -p pedant-graph --no-default-features --edges normal,build,dev,features --prefix none",
    ),
    ("GRAPH_SOURCE_TREE", "pedant-graph/src"),
];

/// The two capture sites the dependency mode binds its command scalars at.
///
/// A scalar the model states and no call site reads proves nothing. Deleting
/// `capture_tree test "${TEST_TREE_COMMAND}"` leaves the declaration standing,
/// stops the dev closure being captured at all, and every equality above still
/// holds. The lines are therefore compared verbatim and in order against every
/// `capture_tree` invocation the runner makes, so a removed capture and an added
/// one both fail.
pub const GRAPH_TREE_CAPTURES: &[&str] = &[
    "capture_tree production \"${PRODUCTION_TREE_COMMAND}\" || return 1",
    "capture_tree test \"${TEST_TREE_COMMAND}\" || return 1",
];

/// The shell array holding the owner-registration inventory.
pub const GRAPH_REGISTRATION_ARRAY: &str = "GRAPH_REGISTRATION_ROWS";

/// The complete owner-registration inventory, matching the plan's table.
///
/// One row per configuration — `<cargo arguments>|<predicates>` — because the
/// pairing is the claim and the runner's three hardcoded call sites were the
/// only thing stating it. Nothing read those call sites, so deleting one
/// stopped twenty-two predicates being proved while both of its declarations
/// stood and this model passed. The resolution runner has taken the paired
/// shape since it was written, and [`crate::shell_script`] compares both.
///
/// Equality, not containment: the runner sizes nothing from this array, but a
/// containment check would accept a runner that had quietly dropped half its
/// inventory, which is the regression worth catching.
pub const GRAPH_REGISTRATION_ROWS: &[(&str, &[&str])] = &[
    (
        "-p pedant-core --no-default-features --test substrate",
        &[
            "release_contract::published_versions_and_requirements_form_releaseable_graph",
            "resolution::fingerprint::snapshot_fingerprint_is_retained_and_redacted",
            "resolution::fingerprint::snapshot_fingerprint_production_claim_mapping_is_complete",
            "resolution::fingerprint::snapshot_fingerprint_has_one_production_hash_owner",
            "resolution::project::testing_contract_tracks_exact_34_root_transition",
        ],
    ),
    (
        "-p pedant-core --no-default-features --features resolution-test-support --test substrate",
        &[
            "release_contract::graph_release_and_verification_owners_are_exact",
            "release_contract::ci_installs_every_proof_runner_tool_before_execution",
            "resolution::authority::resolution_authority_shape_and_root_inventory_are_exact",
            "resolution::fingerprint::snapshot_fingerprint_covers_every_projection_claim",
        ],
    ),
    (
        "-p pedant-graph --test graph",
        &[
            "graph_defensive_error_paths_are_complete_and_wired",
            "graph_defensive_malformed_inputs_return_exact_errors",
            "graph_id_capacity_uses_one_checked_insertion_owner",
            "graph_identity_checks_dominate_projection_state_construction",
            "graph_ids_languages_and_limits_are_dense_checked_and_atomic",
            "graph_projection_uses_only_supplied_resolution_facts",
            "graph_public_identity_defaults_and_schema_are_exact",
            "graph_public_lifecycle_surface_is_closed",
            "graph_public_reading_surface_is_complete",
            "rust_graph_builds_and_serializes_after_fixture_teardown",
            "rust_graph_containment_is_a_unit_local_forest",
            "rust_graph_edges_retain_candidate_certainty_and_evidence",
            "rust_graph_json_v1_covers_every_graph_owned_variant",
            "rust_graph_json_v1_is_exact_compact_and_deterministic",
            "rust_graph_maps_every_rust_reference_kind_exactly",
            "rust_graph_maps_every_rust_symbol_kind_exactly_once",
            "rust_graph_preserves_cargo_dependency_evidence",
            "rust_graph_qualifies_unit_roots_and_shared_source_files",
            "rust_graph_rejects_identity_mismatch_before_capacity_checks",
            "rust_graph_retains_enclosed_top_level_and_candidate_free_references",
            "rust_graph_separates_logical_parentage_from_source_location",
            "rust_graph_tiers_change_only_resolution_evidence",
        ],
    ),
];

/// The refusals the runner writes itself, keeping a graph mode from passing on
/// empty or vacuous evidence.
///
/// Each names a distinct way a mode could otherwise report a result it never
/// obtained: an unrendered dependency graph, a member list that derived an
/// empty forbid set, a broken feature matcher read as "no match", a dev capture
/// that is not the graph's, an empty source tree, and an unknown mode.
pub const GRAPH_PROOF_REJECTIONS: &[&str] = &[
    "so nothing was inspected",
    "the workspace member list could not be read",
    "the member list forbids no workspace package",
    "the pedant-core feature matcher failed",
    "so this capture is not the graph's test graph",
    "holds no Rust source, so a clean profile would constrain nothing",
    "is not one of the three accepted modes",
];

/// The runner's own list-before-run library, and the refusals it owns.
///
/// The two proof runners share it, so a rejection deleted there would weaken
/// both at once. It is stated here rather than left to the resolution model,
/// which asserts the resolution runner's own text.
pub const PROOF_LIBRARY: &str = "docs/scripts/check_lib.sh";

/// Every refusal the shared library owes.
pub const PROOF_LIBRARY_REJECTIONS: &[&str] = &[
    "registered no test at all",
    "is registered ${count:-0} times, not once",
    "selected no test",
    "completed successfully ${count:-0} times, not once",
    "matcher-failed",
];

/// The graph refusals the runner delegates to that same library.
///
/// The runner calls the library's forbid checks and its sentinel mirror rather
/// than repeating them, so the text that refuses a broken matcher or an
/// under-covered mirror lives in `check_lib.sh`. Modelling these against the
/// runner would fail on a runner that delegates correctly; modelling them
/// nowhere would let a deleted guard read as a proven closure. They sit apart
/// from [`PROOF_LIBRARY_REJECTIONS`], which the two runners share for the
/// list-before-run counting the graph modes do not delegate.
pub const GRAPH_DELEGATED_REJECTIONS: &[&str] = &[
    "the forbidden-package matcher failed",
    "the forbidden-feature matcher failed",
    "the rust-analyzer matcher failed",
    "matcher failed against",
    "so the reach guard would not range over the real source set",
];

/// The step router, which selects work by changed path and so must name the
/// new member.
pub const STEP_ROUTER: &str = "docs/scripts/verify_step.sh";

/// The path clause that routes a graph change into the Rust verification set.
pub const STEP_ROUTER_GRAPH_CLAUSE: &str = "    pedant-graph/\n";

/// The affected router, which names no member and so must select none.
pub const AFFECTED_ROUTER: &str = "docs/scripts/verify_affected.sh";

/// Its one Cargo invocation, verbatim.
///
/// The whole line, and the only one: `cargo test -p pedant-core` contains the
/// unnarrowed command as a substring, so a containment check would still pass
/// on the run that had stopped covering the graph member. The root manifest is
/// virtual, so a package-free `cargo test` is what makes this router
/// authoritative for a crate it never mentions.
pub const AFFECTED_WORKSPACE_RUN: &str = "cargo_run test cargo test";

/// The resolution runner, whose Tier 2 inventory this plan revises.
pub const RESOLUTION_PROOF_RUNNER: &str = "docs/scripts/run_resolution_proof.sh";

/// The semantic owner that inventory gains.
///
/// `resolution::authority_runner` compares the whole Tier 2 array with its own
/// model. This is the second, narrower constraint: the model itself could be
/// edited to drop the name and still equal a shortened runner, and only a
/// requirement stated somewhere else rejects that.
pub const SEMANTIC_FINGERPRINT_PREDICATE: &str =
    "resolution::semantic::semantic_handshake_reuses_retained_snapshot_fingerprint";

/// The ignore file that decides whether the graph runner reaches a clone.
///
/// `docs/scripts/` is ignored wholesale and re-included one file at a time, so a
/// runner CI names and the repository never commits fails the job on a fresh
/// checkout rather than here.
pub const GITIGNORE_REINCLUSION: &str = "!docs/scripts/run_graph_proof.sh";

/// The step router reaches the new member, and the affected router stays the
/// authoritative workspace run for it.
pub fn assert_graph_verification_routing() {
    assert!(
        read_text(STEP_ROUTER).contains(STEP_ROUTER_GRAPH_CLAUSE),
        "{STEP_ROUTER} must carry {STEP_ROUTER_GRAPH_CLAUSE:?} so a graph change is verified"
    );

    assert_affected_run_covers_every_member();
}

/// The affected router runs the whole workspace, so the new member needs no
/// clause of its own there.
///
/// Equality against every Cargo invocation in the file, not presence of one:
/// the property 2.T1 owes is that this router selects no package, and a
/// narrowed or added run is the only way it stops covering `pedant-graph`.
fn assert_affected_run_covers_every_member() {
    let router = read_text(AFFECTED_ROUTER);
    let invocations = router
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo_run "))
        .collect::<Vec<&str>>();

    assert_eq!(
        invocations,
        [AFFECTED_WORKSPACE_RUN],
        "{AFFECTED_ROUTER} must run exactly the unnarrowed workspace suite, so the graph member it never names stays covered"
    );
}

/// Both command scalars reach a capture, and no third capture is taken.
///
/// Equality against every `capture_tree` invocation in the file, not presence
/// of each: the declaration and the call site are two halves of one claim, and
/// the model above compares only the first half.
fn assert_tree_commands_are_captured(runner: &str) {
    let captures = runner
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("capture_tree "))
        .collect::<Vec<&str>>();

    assert_eq!(
        captures, GRAPH_TREE_CAPTURES,
        "{GRAPH_PROOF_RUNNER} must capture exactly the two modelled trees, each through its own command scalar"
    );
}

/// Every modelled refusal is present in `text`, the tracked contents of `file`.
///
/// Containment, not equality: a script is free to refuse more than the model
/// names, and only the loss of a modelled refusal turns an empty result into a
/// passing one.
fn assert_rejections(file: &str, text: &str, rejections: &[&str]) {
    for rejection in rejections {
        assert!(
            text.contains(rejection),
            "{file} must refuse with {rejection:?}"
        );
    }
}

/// The graph runner is closed: three modes, the exact commands, the exact
/// registration inventory, and a refusal for every empty result, whether the
/// runner writes it or delegates it to the shared library.
pub fn assert_graph_proof_runner() {
    let runner = read_text(GRAPH_PROOF_RUNNER);

    assert_eq!(
        mode_arms(&runner),
        GRAPH_PROOF_MODES
            .iter()
            .map(|mode| (*mode).to_owned())
            .collect::<BTreeSet<String>>(),
        "{GRAPH_PROOF_RUNNER} must dispatch exactly the three declared modes"
    );

    assert_eq!(
        model_scalars(GRAPH_PROOF_RUNNER, &runner),
        GRAPH_PROOF_SCALARS
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<BTreeMap<String, String>>(),
        "{GRAPH_PROOF_RUNNER}'s fixed model must declare exactly the modelled scalars"
    );

    assert_tree_commands_are_captured(&runner);

    assert_registration_rows(
        GRAPH_PROOF_RUNNER,
        &runner,
        GRAPH_REGISTRATION_ARRAY,
        GRAPH_PROOF_SCALARS,
        GRAPH_REGISTRATION_ROWS,
    );

    assert_rejections(GRAPH_PROOF_RUNNER, &runner, GRAPH_PROOF_REJECTIONS);

    let library = read_text(PROOF_LIBRARY);
    assert_rejections(PROOF_LIBRARY, &library, GRAPH_DELEGATED_REJECTIONS);
    assert_rejections(PROOF_LIBRARY, &library, PROOF_LIBRARY_REJECTIONS);

    assert!(
        read_text(RESOLUTION_PROOF_RUNNER).contains(SEMANTIC_FINGERPRINT_PREDICATE),
        "{RESOLUTION_PROOF_RUNNER} must require {SEMANTIC_FINGERPRINT_PREDICATE} in its Tier 2 inventory"
    );
}
