use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::check_config::{GateConfig, GateRuleOverride};
use pedant_core::gate::{GateSeverity, all_gate_rules, evaluate_gate_rules};
use pedant_core::ir::{DataFlowFact, DataFlowKind, IrSpan};
use pedant_types::{Capability, CapabilityFinding, CapabilityProfile, SourceLocation};

fn finding(capability: Capability, build_script: bool) -> CapabilityFinding {
    finding_with_evidence(capability, build_script, "test evidence")
}

fn finding_with_evidence(
    capability: Capability,
    build_script: bool,
    evidence: &str,
) -> CapabilityFinding {
    CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::from("test.rs"),
            line: 1,
            column: 1,
        },
        evidence: Arc::from(evidence),
        build_script,
        reachable: None,
    }
}

fn profile(findings: Vec<CapabilityFinding>) -> CapabilityProfile {
    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

#[test]
fn test_build_script_network_denied() {
    let p = profile(vec![finding(Capability::Network, true)]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "build-script-network")
        .expect("expected build-script-network verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_build_script_download_exec_denied() {
    let p = profile(vec![
        finding(Capability::Network, true),
        finding(Capability::ProcessExec, true),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());

    let download_exec = verdicts
        .iter()
        .find(|v| v.rule == "build-script-download-exec")
        .expect("expected build-script-download-exec verdict");
    assert_eq!(download_exec.severity, GateSeverity::Deny);

    assert!(
        verdicts.iter().any(|v| v.rule == "build-script-network"),
        "build-script-network should fire independently"
    );
}

#[test]
fn test_build_script_exec_warns() {
    let p = profile(vec![finding(Capability::ProcessExec, true)]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "build-script-exec")
        .expect("expected build-script-exec verdict");
    assert_eq!(v.severity, GateSeverity::Warn);
}

#[test]
fn test_proc_macro_network_denied() {
    let p = profile(vec![
        finding(Capability::ProcMacro, false),
        finding(Capability::Network, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "proc-macro-network")
        .expect("expected proc-macro-network verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_clean_profile_no_verdicts() {
    let p = profile(vec![finding(Capability::FileRead, false)]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    assert!(
        verdicts.is_empty(),
        "expected no verdicts for clean profile"
    );
}

#[test]
fn test_runtime_findings_skip_build_rules() {
    let p = profile(vec![
        finding(Capability::Network, false),
        finding(Capability::ProcessExec, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let build_verdicts: Vec<_> = verdicts
        .iter()
        .filter(|v| v.rule.starts_with("build-script-"))
        .collect();
    assert!(
        build_verdicts.is_empty(),
        "no build-script rules should fire for runtime findings"
    );
}

#[test]
fn test_rule_disabled_via_config() {
    let p = profile(vec![finding(Capability::Network, true)]);
    let mut overrides = BTreeMap::new();
    overrides.insert(
        Box::from("build-script-network"),
        GateRuleOverride::Disabled,
    );
    let config = GateConfig {
        enabled: true,
        overrides,
    };
    let verdicts = evaluate_gate_rules(&p.findings, &[], &config);
    assert!(
        !verdicts.iter().any(|v| v.rule == "build-script-network"),
        "disabled rule should not produce a verdict"
    );
}

#[test]
fn test_severity_override_via_config() {
    let p = profile(vec![finding(Capability::Network, true)]);
    let mut overrides = BTreeMap::new();
    overrides.insert(
        Box::from("build-script-network"),
        GateRuleOverride::Severity(GateSeverity::Info),
    );
    let config = GateConfig {
        enabled: true,
        overrides,
    };
    let verdicts = evaluate_gate_rules(&p.findings, &[], &config);
    let v = verdicts
        .iter()
        .find(|v| v.rule == "build-script-network")
        .expect("expected build-script-network verdict");
    assert_eq!(v.severity, GateSeverity::Info);
}

#[test]
fn test_gate_disabled_entirely() {
    let p = profile(vec![
        finding(Capability::Network, true),
        finding(Capability::ProcessExec, true),
    ]);
    let config = GateConfig {
        enabled: false,
        overrides: BTreeMap::new(),
    };
    let verdicts = evaluate_gate_rules(&p.findings, &[], &config);
    assert!(
        verdicts.is_empty(),
        "disabled gate should produce no verdicts"
    );
}

#[test]
fn test_all_gate_rules_returns_all_rules() {
    let rules = all_gate_rules();
    assert_eq!(
        rules.len(),
        24,
        "expected 24 rules (9 capability + 3 flow + 12 quality/perf/concurrency/error)"
    );
    for rule in rules {
        assert!(!rule.name.is_empty(), "rule name must not be empty");
        assert!(
            !rule.description.is_empty(),
            "rule description must not be empty"
        );
    }
}

// --- Step 2: Runtime combination rules ---

#[test]
fn test_env_access_network_info() {
    let p = profile(vec![
        finding(Capability::EnvAccess, false),
        finding(Capability::Network, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "env-access-network")
        .expect("expected env-access-network verdict");
    assert_eq!(v.severity, GateSeverity::Info);
}

#[test]
fn test_env_access_alone_no_verdict() {
    let p = profile(vec![finding(Capability::EnvAccess, false)]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    assert!(
        !verdicts.iter().any(|v| v.rule == "env-access-network"),
        "env-access-network should not fire without Network"
    );
}

#[test]
fn test_key_material_network_warns() {
    let p = profile(vec![
        finding_with_evidence(
            Capability::Crypto,
            false,
            "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
        ),
        finding(Capability::Network, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "key-material-network")
        .expect("expected key-material-network verdict");
    assert_eq!(v.severity, GateSeverity::Warn);
}

#[test]
fn test_crypto_import_network_no_key_material_verdict() {
    let p = profile(vec![
        finding_with_evidence(Capability::Crypto, false, "sha2::Digest"),
        finding(Capability::Network, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    assert!(
        !verdicts.iter().any(|v| v.rule == "key-material-network"),
        "import-based crypto should not trigger key-material-network"
    );
}

#[test]
fn test_pem_key_material_network() {
    let p = profile(vec![
        finding_with_evidence(
            Capability::Crypto,
            false,
            "-----BEGIN PRIVATE KEY-----MIIEvgIBA...",
        ),
        finding(Capability::Network, false),
    ]);
    let verdicts = evaluate_gate_rules(&p.findings, &[], &GateConfig::default());
    assert!(
        verdicts.iter().any(|v| v.rule == "key-material-network"),
        "PEM key material with network should trigger key-material-network"
    );
}

// --- Step 6: Flow-aware gate rules ---

fn kind_fact(kind: DataFlowKind, message: &str) -> DataFlowFact {
    DataFlowFact {
        kind,
        source_capability: None,
        source_span: IrSpan { line: 1, column: 0 },
        sink_capability: None,
        sink_span: IrSpan { line: 5, column: 0 },
        call_chain: Box::new([]),
        message: Box::from(message),
    }
}

fn flow_fact(source: Capability, sink: Capability) -> DataFlowFact {
    DataFlowFact {
        kind: DataFlowKind::TaintFlow,
        source_capability: Some(source),
        source_span: IrSpan { line: 1, column: 0 },
        sink_capability: Some(sink),
        sink_span: IrSpan { line: 5, column: 0 },
        call_chain: Box::new([]),
        message: format!("{source:?} flows to {sink:?}").into_boxed_str(),
    }
}

#[test]
fn test_env_to_network_gate_rule() {
    let flows = [flow_fact(Capability::EnvAccess, Capability::Network)];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "env-to-network")
        .expect("expected env-to-network verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_file_to_network_gate_rule() {
    let flows = [flow_fact(Capability::FileRead, Capability::Network)];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "file-to-network")
        .expect("expected file-to-network verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_network_to_exec_gate_rule() {
    let flows = [flow_fact(Capability::Network, Capability::ProcessExec)];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "network-to-exec")
        .expect("expected network-to-exec verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_flow_rules_dont_fire_without_data_flows() {
    let findings = [
        finding(Capability::EnvAccess, false),
        finding(Capability::Network, false),
    ];
    let verdicts = evaluate_gate_rules(&findings, &[], &GateConfig::default());

    // Flow-aware rules should NOT fire without data flows
    assert!(
        !verdicts.iter().any(|v| v.rule == "env-to-network"),
        "env-to-network should not fire without DataFlowFact"
    );

    // Existing combination rule should still fire
    assert!(
        verdicts.iter().any(|v| v.rule == "env-access-network"),
        "env-access-network combination rule should still fire"
    );
}

#[test]
fn test_all_gate_rules_includes_flow_rules() {
    let rules = all_gate_rules();
    let flow_rules: Vec<_> = rules
        .iter()
        .filter(|r| {
            r.name == "env-to-network" || r.name == "file-to-network" || r.name == "network-to-exec"
        })
        .collect();
    assert_eq!(
        flow_rules.len(),
        3,
        "expected 3 flow-aware rules in rule list"
    );
}

// --- Step 4: Quality, performance, and concurrency gate rules ---

#[test]
fn test_dead_store_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::DeadStore,
        "x overwritten before read",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "dead-store")
        .expect("expected dead-store verdict");
    assert_eq!(v.severity, GateSeverity::Warn);
}

#[test]
fn test_unnecessary_clone_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::UnnecessaryClone,
        "s.clone() but s never used after",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "unnecessary-clone")
        .expect("expected unnecessary-clone verdict");
    assert_eq!(v.severity, GateSeverity::Info);
}

#[test]
fn test_lock_across_await_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::LockAcrossAwait,
        "guard held across .await",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "lock-across-await")
        .expect("expected lock-across-await verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_inconsistent_lock_order_gate_rule() {
    let flows = [kind_fact(
        DataFlowKind::InconsistentLockOrder,
        "m1,m2 vs m2,m1",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "inconsistent-lock-order")
        .expect("expected inconsistent-lock-order verdict");
    assert_eq!(v.severity, GateSeverity::Deny);
}

#[test]
fn test_all_gate_rules_includes_new_rules() {
    let rules = all_gate_rules();
    assert_eq!(
        rules.len(),
        24,
        "expected 24 rules (9 capability + 3 flow + 12 quality/perf/concurrency/error)"
    );
}

#[test]
fn test_data_flow_kind_display_returns_kebab_case() {
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

#[test]
fn test_quality_perf_rules_dont_fire_without_dataflow() {
    let verdicts = evaluate_gate_rules(&[], &[], &GateConfig::default());
    let new_rule_names = [
        "dead-store",
        "discarded-result",
        "partial-error-handling",
        "repeated-call",
        "unnecessary-clone",
        "allocation-in-loop",
        "redundant-collect",
        "lock-across-await",
        "inconsistent-lock-order",
    ];
    for name in new_rule_names {
        assert!(
            !verdicts.iter().any(|v| v.rule == name),
            "{name} should not fire without DataFlowFacts"
        );
    }
}

// --- Swallowed errors and silent panics gate rules ---

#[test]
fn swallowed_ok_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::SwallowedOk,
        ".ok() on Result where Option is discarded",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "swallowed-ok")
        .expect("expected swallowed-ok verdict");
    assert_eq!(v.severity, GateSeverity::Warn);
}

#[test]
fn unobserved_spawn_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::UnobservedSpawn,
        "Thread spawned with dropped JoinHandle",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "unobserved-spawn")
        .expect("expected unobserved-spawn verdict");
    assert_eq!(v.severity, GateSeverity::Warn);
}

#[test]
fn immutable_growable_gate_rule_fires_on_kind() {
    let flows = [kind_fact(
        DataFlowKind::ImmutableGrowable,
        "Vec never mutated after construction",
    )];
    let verdicts = evaluate_gate_rules(&[], &flows, &GateConfig::default());
    let v = verdicts
        .iter()
        .find(|v| v.rule == "immutable-growable")
        .expect("expected immutable-growable verdict");
    assert_eq!(v.severity, GateSeverity::Info);
}
