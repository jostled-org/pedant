#![cfg(feature = "checks")]
//! The gate root: every case is registered here as a bare wrapper, and every
//! assertion lives in the support module that owns its subject.
//!
//! The `#[path]` attributes are required. Default resolution would place these
//! files in `tests/gate/`, which pedant's `conflicting-module-root` rule
//! rejects beside `gate.rs`, and its advice — fold the root into `gate/mod.rs`
//! — does not apply to a cargo test root, since cargo builds a test executable
//! per `tests/*.rs` and would stop building this one. A sibling directory
//! satisfies both: cargo declares no target for it, because it holds no
//! `main.rs`.

/// Capability findings, data-flow facts, and graph-neutral module-boundary rows.
#[path = "gate_support/fixture.rs"]
mod fixture;

/// Capability-combination predicates and the capability catalog.
#[path = "gate_support/capability.rs"]
mod capability;

/// Flow-aware, quality, performance, and concurrency predicates.
#[path = "gate_support/data_flow.rs"]
mod data_flow;

/// Nested `[gate.module-boundary]` configuration and the structural catalog.
#[path = "gate_support/configuration.rs"]
mod configuration;

/// Module-boundary constructors and thresholds.
#[path = "gate_support/module_boundary.rs"]
mod module_boundary;

/// Verdict subjects, annotation precedence, retained counts, and input order.
#[path = "gate_support/evidence.rs"]
mod evidence;

/// The exact serialized verdict contract.
#[path = "gate_support/serialization.rs"]
mod serialization;

/// The judgment-versus-topology boundary and the public gate surface.
#[path = "gate_support/ownership.rs"]
mod ownership;

#[test]
fn test_build_script_network_denied() {
    capability::test_build_script_network_denied();
}

#[test]
fn test_build_script_download_exec_denied() {
    capability::test_build_script_download_exec_denied();
}

#[test]
fn test_build_script_exec_warns() {
    capability::test_build_script_exec_warns();
}

#[test]
fn test_proc_macro_network_denied() {
    capability::test_proc_macro_network_denied();
}

#[test]
fn test_clean_profile_no_verdicts() {
    capability::test_clean_profile_no_verdicts();
}

#[test]
fn test_runtime_findings_skip_build_rules() {
    capability::test_runtime_findings_skip_build_rules();
}

#[test]
fn test_rule_disabled_via_config() {
    capability::test_rule_disabled_via_config();
}

#[test]
fn test_severity_override_via_config() {
    capability::test_severity_override_via_config();
}

#[test]
fn test_gate_disabled_entirely() {
    capability::test_gate_disabled_entirely();
}

#[test]
fn test_gate_config_rejects_unknown_rule_name() {
    capability::test_gate_config_rejects_unknown_rule_name();
}

#[test]
fn test_all_gate_rules_returns_all_rules() {
    capability::test_all_gate_rules_returns_all_rules();
}

#[test]
fn test_env_access_network_info() {
    capability::test_env_access_network_info();
}

#[test]
fn test_env_access_alone_no_verdict() {
    capability::test_env_access_alone_no_verdict();
}

#[test]
fn test_key_material_network_warns() {
    capability::test_key_material_network_warns();
}

#[test]
fn test_crypto_import_network_no_key_material_verdict() {
    capability::test_crypto_import_network_no_key_material_verdict();
}

#[test]
fn test_pem_key_material_network() {
    capability::test_pem_key_material_network();
}

#[test]
fn key_material_gate_uses_origin_import_not_key_material() {
    capability::key_material_gate_uses_origin_import_not_key_material();
}

#[test]
fn key_material_gate_uses_origin_string_literal_is_key_material() {
    capability::key_material_gate_uses_origin_string_literal_is_key_material();
}

#[test]
fn key_material_gate_falls_back_to_heuristic_for_legacy() {
    capability::key_material_gate_falls_back_to_heuristic_for_legacy();
}

#[test]
fn test_env_to_network_gate_rule() {
    data_flow::test_env_to_network_gate_rule();
}

#[test]
fn test_file_to_network_gate_rule() {
    data_flow::test_file_to_network_gate_rule();
}

#[test]
fn test_network_to_exec_gate_rule() {
    data_flow::test_network_to_exec_gate_rule();
}

#[test]
fn test_flow_rules_dont_fire_without_data_flows() {
    data_flow::test_flow_rules_dont_fire_without_data_flows();
}

#[test]
fn test_all_gate_rules_includes_flow_rules() {
    data_flow::test_all_gate_rules_includes_flow_rules();
}

#[test]
fn test_dead_store_gate_rule() {
    data_flow::test_dead_store_gate_rule();
}

#[test]
fn test_unnecessary_clone_gate_rule() {
    data_flow::test_unnecessary_clone_gate_rule();
}

#[test]
fn test_lock_across_await_gate_rule() {
    data_flow::test_lock_across_await_gate_rule();
}

#[test]
fn test_inconsistent_lock_order_gate_rule() {
    data_flow::test_inconsistent_lock_order_gate_rule();
}

#[test]
fn test_all_gate_rules_includes_new_rules() {
    data_flow::test_all_gate_rules_includes_new_rules();
}

#[test]
fn test_data_flow_kind_display_returns_kebab_case() {
    data_flow::test_data_flow_kind_display_returns_kebab_case();
}

#[test]
fn test_quality_perf_rules_dont_fire_without_dataflow() {
    data_flow::test_quality_perf_rules_dont_fire_without_dataflow();
}

#[test]
fn swallowed_ok_gate_rule_fires_on_kind() {
    data_flow::swallowed_ok_gate_rule_fires_on_kind();
}

#[test]
fn unobserved_spawn_gate_rule_fires_on_kind() {
    data_flow::unobserved_spawn_gate_rule_fires_on_kind();
}

#[test]
fn immutable_growable_gate_rule_fires_on_kind() {
    data_flow::immutable_growable_gate_rule_fires_on_kind();
}

#[test]
fn gate_verdicts_match_before_and_after_summary_evaluation() {
    data_flow::gate_verdicts_match_before_and_after_summary_evaluation();
}

#[test]
fn module_boundary_input_validation_is_total_and_ordered() {
    module_boundary::module_boundary_input_validation_is_total_and_ordered();
}

#[test]
fn module_boundary_default_threshold_boundaries_are_exact() {
    module_boundary::module_boundary_default_threshold_boundaries_are_exact();
}

#[test]
fn module_boundary_crossing_cycles_are_partition_exact() {
    module_boundary::module_boundary_crossing_cycles_are_partition_exact();
}

#[test]
fn module_boundary_evidence_is_complete_and_ordered() {
    evidence::module_boundary_evidence_is_complete_and_ordered();
}

#[test]
fn module_boundary_enablement_and_catalog_are_single_authority() {
    configuration::module_boundary_enablement_and_catalog_are_single_authority();
}

#[test]
fn gate_evidence_serialization_is_exact_and_legacy_json_is_unchanged() {
    serialization::gate_evidence_serialization_is_exact_and_legacy_json_is_unchanged();
}

#[test]
fn module_boundary_ownership_and_public_surface_are_exact() {
    ownership::module_boundary_ownership_and_public_surface_are_exact();
}
