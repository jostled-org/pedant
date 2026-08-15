//! Flow-aware, quality, performance, and concurrency gate predicates, plus the
//! whole-summary equivalence case that spans both capability families.

use pedant_core::check_config::GateConfig;
use pedant_core::gate::{
    GateInputSummary, GateSeverity, all_gate_rules, evaluate_gate_rules, is_gate_rule,
    is_module_boundary_rule,
};
use pedant_core::ir::DataFlowKind;
use pedant_types::{Capability, FindingOrigin};

use crate::fixture::{
    assert_rule_absent, assert_rule_severity, eval, finding, finding_with_origin, flow_fact,
    kind_fact, rule_names,
};

/// The flow-aware rule names, owned here because this module drives them.
const FLOW_RULES: &[&str] = &["env-to-network", "file-to-network", "network-to-exec"];

/// Every rule keyed on a data-flow kind rather than a capability combination.
const KIND_RULES: &[&str] = &[
    "dead-store",
    "discarded-result",
    "partial-error-handling",
    "swallowed-ok",
    "immutable-growable",
    "repeated-call",
    "unnecessary-clone",
    "allocation-in-loop",
    "redundant-collect",
    "lock-across-await",
    "inconsistent-lock-order",
    "unobserved-spawn",
];

pub(crate) fn test_env_to_network_gate_rule() {
    let flows = [flow_fact(Capability::EnvAccess, Capability::Network)];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "env-to-network", GateSeverity::Deny);
}

pub(crate) fn test_file_to_network_gate_rule() {
    let flows = [flow_fact(Capability::FileRead, Capability::Network)];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "file-to-network", GateSeverity::Deny);
}

pub(crate) fn test_network_to_exec_gate_rule() {
    let flows = [flow_fact(Capability::Network, Capability::ProcessExec)];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "network-to-exec", GateSeverity::Deny);
}

pub(crate) fn test_flow_rules_dont_fire_without_data_flows() {
    let findings = [
        finding(Capability::EnvAccess, false),
        finding(Capability::Network, false),
    ];
    let verdicts = eval(&findings, &[], &GateConfig::default());

    // The combination rule fires, so the absent flow rule is an evaluated
    // negative rather than an empty result.
    assert_rule_severity(&verdicts, "env-access-network", GateSeverity::Info);
    assert_rule_absent(&verdicts, "env-to-network");
}

pub(crate) fn test_all_gate_rules_includes_flow_rules() {
    let flow_rules = all_gate_rules()
        .iter()
        .filter(|rule| FLOW_RULES.contains(&rule.name))
        .count();
    assert_eq!(
        flow_rules,
        FLOW_RULES.len(),
        "every flow-aware rule appears in the rule list"
    );
}

pub(crate) fn test_dead_store_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::DeadStore,
        "x overwritten before read",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "dead-store", GateSeverity::Warn);
}

pub(crate) fn test_unnecessary_clone_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::UnnecessaryClone,
        "s.clone() but s never used after",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "unnecessary-clone", GateSeverity::Info);
}

pub(crate) fn test_lock_across_await_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::LockAcrossAwait,
        "guard held across .await",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "lock-across-await", GateSeverity::Deny);
}

pub(crate) fn test_inconsistent_lock_order_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::InconsistentLockOrder,
        "m1,m2 vs m2,m1",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "inconsistent-lock-order", GateSeverity::Deny);
}

/// `capability.rs` owns the rule count; this case owns which names the catalog
/// carries and which catalog answers for them.
pub(crate) fn test_all_gate_rules_includes_new_rules() {
    let listed = all_gate_rules();
    let names: Box<[&str]> = listed.iter().map(|rule| rule.name).collect();
    for rule in KIND_RULES {
        assert!(names.contains(rule), "{rule} is missing from the rule list");
        assert!(is_gate_rule(rule), "{rule} is a built-in gate rule");
        assert!(
            !is_module_boundary_rule(rule),
            "{rule} belongs to the capability catalog alone"
        );
    }
    assert!(
        !is_gate_rule("no-such-rule"),
        "an unwritten name is no gate rule"
    );
}

pub(crate) fn test_data_flow_kind_display_returns_kebab_case() {
    assert_eq!(DataFlowKind::TaintFlow.to_string(), "taint-flow");
    assert_eq!(DataFlowKind::DeadStore.to_string(), "dead-store");
    assert_eq!(
        DataFlowKind::DiscardedResult.to_string(),
        "discarded-result"
    );
    assert_eq!(
        DataFlowKind::PartialErrorHandling.to_string(),
        "partial-error-handling"
    );
    assert_eq!(DataFlowKind::RepeatedCall.to_string(), "repeated-call");
    assert_eq!(
        DataFlowKind::UnnecessaryClone.to_string(),
        "unnecessary-clone"
    );
    assert_eq!(
        DataFlowKind::AllocationInLoop.to_string(),
        "allocation-in-loop"
    );
    assert_eq!(
        DataFlowKind::RedundantCollect.to_string(),
        "redundant-collect"
    );
    assert_eq!(
        DataFlowKind::LockAcrossAwait.to_string(),
        "lock-across-await"
    );
    assert_eq!(
        DataFlowKind::InconsistentLockOrder.to_string(),
        "inconsistent-lock-order"
    );
    assert_eq!(
        DataFlowKind::ImmutableGrowable.to_string(),
        "immutable-growable"
    );
    assert_eq!(DataFlowKind::SwallowedOk.to_string(), "swallowed-ok");
    assert_eq!(
        DataFlowKind::UnobservedSpawn.to_string(),
        "unobserved-spawn"
    );
}

/// One dead-store fact fires its own rule and no other kind-keyed rule: each
/// predicate reads the kind it names rather than the presence of any fact.
pub(crate) fn test_quality_perf_rules_dont_fire_without_dataflow() {
    let flows = [kind_fact(DataFlowKind::DeadStore, "x overwritten")];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "dead-store", GateSeverity::Warn);
    for rule in KIND_RULES.iter().filter(|rule| **rule != "dead-store") {
        assert_rule_absent(&verdicts, rule);
    }
}

pub(crate) fn swallowed_ok_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::SwallowedOk,
        ".ok() on Result where Option is discarded",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "swallowed-ok", GateSeverity::Warn);
}

pub(crate) fn unobserved_spawn_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::UnobservedSpawn,
        "Thread spawned with dropped JoinHandle",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "unobserved-spawn", GateSeverity::Warn);
}

pub(crate) fn immutable_growable_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::ImmutableGrowable,
        "Vec never mutated after construction",
    )];
    let verdicts = eval(&[], &flows, &GateConfig::default());
    assert_rule_severity(&verdicts, "immutable-growable", GateSeverity::Info);
}

pub(crate) fn gate_verdicts_match_before_and_after_summary_evaluation() {
    // Mix of capability findings triggering multiple rule categories.
    let findings = [
        finding(Capability::Network, true),     // build-script-network
        finding(Capability::ProcessExec, true), // build-script-exec, build-script-download-exec
        finding(Capability::FileWrite, true),   // build-script-file-write
        finding(Capability::ProcMacro, false),  // proc-macro-network (with Network above)
        finding(Capability::EnvAccess, false),  // env-access-network (with Network)
        finding(Capability::Network, false),    // runtime network
        finding_with_origin(
            // key-material-network
            Capability::Crypto,
            FindingOrigin::StringLiteral,
            "0a1b2c3d…0a1b",
        ),
    ];
    // Mix of data-flow facts triggering flow and quality/perf/concurrency rules.
    let data_flows = [
        flow_fact(Capability::EnvAccess, Capability::Network), // env-to-network
        flow_fact(Capability::FileRead, Capability::Network),  // file-to-network
        kind_fact(DataFlowKind::DeadStore, "x overwritten"),   // dead-store
        kind_fact(DataFlowKind::LockAcrossAwait, "guard held"), // lock-across-await
        kind_fact(DataFlowKind::UnnecessaryClone, "s.clone()"), // unnecessary-clone
    ];
    let config = GateConfig::default();

    // Build summary and evaluate through the summary path.
    let summary = GateInputSummary::from_analysis(&findings, &data_flows);
    let verdicts = evaluate_gate_rules(&summary, &config);

    // All expected rules must fire.
    let rules = rule_names(&verdicts);
    let expected = [
        "build-script-network",
        "build-script-exec",
        "build-script-download-exec",
        "build-script-file-write",
        "proc-macro-network",
        "env-access-network",
        "key-material-network",
        "env-to-network",
        "file-to-network",
        "dead-store",
        "lock-across-await",
        "unnecessary-clone",
    ];
    for name in expected {
        assert!(
            rules.contains(&name),
            "expected rule {name} to fire, got: {rules:?}"
        );
    }

    // Rules that should NOT fire (no matching data).
    let absent = [
        "network-to-exec",
        "redundant-collect",
        "inconsistent-lock-order",
    ];
    for name in absent {
        assert_rule_absent(&verdicts, name);
    }
}
