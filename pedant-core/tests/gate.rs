use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::check_config::{GateConfig, GateRuleOverride};
use pedant_core::gate::{GateSeverity, all_gate_rules, evaluate_gate_rules};
use pedant_core::ir::{DataFlowFact, IrSpan};
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
        12,
        "expected 12 rules (7 compile-time + 2 runtime + 3 flow-aware)"
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

fn flow_fact(source: Capability, sink: Capability) -> DataFlowFact {
    DataFlowFact {
        source_capability: source,
        source_span: IrSpan { line: 1, column: 0 },
        sink_capability: sink,
        sink_span: IrSpan { line: 5, column: 0 },
        call_chain: Box::new([]),
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
