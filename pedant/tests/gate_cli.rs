//! Operator journeys through the spawned `pedant gate` binary.
//!
//! This root states the claims. Every child runs under the package-shared
//! process guard, and every assertion body lives in `gate_cli_support/`, so
//! this file registers tests and delegates.

#[path = "package_support/process_guard.rs"]
mod process_guard;

#[path = "gate_cli_support/fixture.rs"]
mod fixture;

#[path = "gate_cli_support/capability_modes.rs"]
mod capability_modes;

#[path = "gate_cli_support/catalog.rs"]
mod catalog;

#[path = "gate_cli_support/ceilings.rs"]
mod ceilings;

#[path = "gate_cli_support/failures.rs"]
mod failures;

#[path = "gate_cli_support/output.rs"]
mod output;

#[path = "gate_cli_support/ownership.rs"]
mod ownership;

#[path = "gate_cli_support/project.rs"]
mod project;

#[path = "gate_cli_support/topology.rs"]
mod topology;

#[cfg(feature = "semantic")]
#[path = "gate_cli_support/semantic.rs"]
mod semantic;

#[test]
fn test_gate_cli_build_script_denied() {
    capability_modes::test_gate_cli_build_script_denied();
}

#[test]
fn test_gate_cli_clean_crate() {
    capability_modes::test_gate_cli_clean_crate();
}

#[test]
fn test_gate_cli_json_format() {
    capability_modes::test_gate_cli_json_format();
}

#[test]
fn test_gate_cli_warn_only_exit_zero() {
    capability_modes::test_gate_cli_warn_only_exit_zero();
}

#[test]
fn test_gate_cli_with_config_override() {
    capability_modes::test_gate_cli_with_config_override();
}

#[test]
fn test_cli_mixed_rust_python_default_separate() {
    capability_modes::test_cli_mixed_rust_python_default_separate();
}

#[test]
fn test_cli_runtime_and_install_hook_same_language_separate() {
    capability_modes::test_cli_runtime_and_install_hook_same_language_separate();
}

#[test]
fn test_cli_cross_language_flag() {
    capability_modes::test_cli_cross_language_flag();
}

/// The gate accepts exactly one input mode, and the legacy modes construct no
/// graph and keep their exact output.
#[test]
fn project_gate_input_modes_are_disjoint_and_legacy_modes_stay_graph_free() {
    project::input_modes_are_disjoint();
    ownership::legacy_gate_dispatch_is_graph_free();
}

/// Project mode selects every and only primary workspace target, in project
/// order, independent of filesystem creation order.
///
/// Both workspaces are built here and shared: the selection owner and the
/// record owner ask different questions of the same two repositories, and
/// building four identical fourteen-file trees would answer neither twice.
#[test]
fn project_gate_selects_every_primary_workspace_target_in_stable_order() {
    let forward = fixture::workspace_fixture(false);
    let reversed = fixture::workspace_fixture(true);
    project::selects_every_primary_target_in_stable_order(&forward, &reversed);
    output::records_are_stable_across_creation_order(&forward, &reversed);
}

/// The live topology admits exactly the resolved code relations and excludes
/// possible candidates and dependency edges.
#[test]
fn project_gate_structural_rules_follow_resolved_only_evidence() {
    topology::structural_rules_follow_resolved_only_evidence();
}

/// Every configured ceiling refuses before a verdict is evaluated.
#[test]
fn project_gate_applies_every_resource_ceiling_before_verdicts() {
    ceilings::applies_every_resource_ceiling_before_verdicts();
    ownership::project_pipeline_wiring_is_exact();
}

/// Configuration authority is explicit, then project-local, then global, then
/// defaults, and a discovered failure is fatal in project mode.
#[test]
fn project_gate_config_precedence_and_failure_contract_are_exact() {
    project::config_precedence_and_failure_contract_are_exact();
}

/// Every project failure returns exit 2 with no verdict and no success payload,
/// and every declared refusal is covered by a case or declared defensive.
#[test]
fn project_gate_failures_are_buffered_and_exit_two() {
    failures::failures_are_buffered_and_exit_two();
    ownership::project_failures_reach_one_exit_owner();
    ownership::every_project_refusal_is_covered_or_defensive();
}

/// Text, JSON, and GitHub project records are exact, anchored, and actionable.
#[test]
fn project_gate_outputs_are_exact_and_actionable() {
    output::outputs_are_exact_and_actionable();
    ownership::project_output_is_one_description_owner();
}

/// Tier 1 reads the declared repository and invokes no toolchain.
#[test]
fn project_gate_tier1_invokes_no_toolchain() {
    project::tier1_invokes_no_toolchain();
}

/// An explicit semantic request evaluates every target from one verified
/// context or fails all-target.
#[cfg(feature = "semantic")]
#[test]
fn project_gate_semantic_is_single_context_all_target_or_error() {
    semantic::semantic_is_single_context_all_target_or_error();
    ownership::semantic_context_is_loaded_once_before_iteration();
}

/// The module, support, dependency, and release boundaries are exact.
#[test]
fn module_boundary_repository_boundaries_are_exact() {
    ownership::repository_boundaries_are_exact();
}

/// Every structural rule is listed once and explained once.
#[test]
fn module_boundary_catalog_is_listed_and_explained_once() {
    catalog::catalog_is_listed_and_explained_once();
}
