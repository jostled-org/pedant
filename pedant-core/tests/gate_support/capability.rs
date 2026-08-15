//! Capability-combination gate predicates: build hooks, proc macros, runtime
//! combinations, embedded key material, and the capability catalog.

use std::collections::BTreeMap;

use pedant_core::check_config::{GateConfig, GateRuleOverride, ModuleBoundaryConfig};
use pedant_core::gate::{GateSeverity, all_gate_rules};
use pedant_types::{Capability, FindingOrigin};

use crate::fixture::{
    assert_gate_config_rejections, assert_no_verdicts, assert_rule_absent, assert_rule_severity,
    eval, finding, finding_with_evidence, finding_with_origin, rule_names,
};

/// A hex string long enough to read as embedded key material.
const HEX_KEY: &str = "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b";

/// Every rejected `[gate]` body owned by the capability surface.
const REJECTIONS: &[(&str, &str)] = &[(
    "enabled = true\nunknown-rule = \"warn\"\n",
    "unknown gate rule 'unknown-rule'",
)];

/// A gate config whose only non-default state is the capability override map.
fn config_with_overrides(
    enabled: bool,
    overrides: BTreeMap<Box<str>, GateRuleOverride>,
) -> GateConfig {
    GateConfig {
        enabled,
        overrides,
        module_boundary: ModuleBoundaryConfig::default(),
    }
}

pub(crate) fn test_build_script_network_denied() {
    let verdicts = eval(
        &[finding(Capability::Network, true)],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "build-script-network", GateSeverity::Deny);
}

pub(crate) fn test_build_script_download_exec_denied() {
    let verdicts = eval(
        &[
            finding(Capability::Network, true),
            finding(Capability::ProcessExec, true),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "build-script-download-exec", GateSeverity::Deny);
    assert_rule_severity(&verdicts, "build-script-network", GateSeverity::Deny);
}

pub(crate) fn test_build_script_exec_warns() {
    let verdicts = eval(
        &[finding(Capability::ProcessExec, true)],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "build-script-exec", GateSeverity::Warn);
}

pub(crate) fn test_proc_macro_network_denied() {
    let verdicts = eval(
        &[
            finding(Capability::ProcMacro, false),
            finding(Capability::Network, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "proc-macro-network", GateSeverity::Deny);
}

pub(crate) fn test_clean_profile_no_verdicts() {
    let verdicts = eval(
        &[finding(Capability::FileRead, false)],
        &[],
        &GateConfig::default(),
    );
    assert_no_verdicts(&verdicts, "a file-read-only profile fires no rule");
}

pub(crate) fn test_runtime_findings_skip_build_rules() {
    let verdicts = eval(
        &[
            finding(Capability::Network, false),
            finding(Capability::ProcessExec, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert!(
        !verdicts
            .iter()
            .any(|verdict| verdict.rule.starts_with("build-script-")),
        "no build-script rule should fire for runtime findings, got {:?}",
        rule_names(&verdicts)
    );
}

pub(crate) fn test_rule_disabled_via_config() {
    let findings = [finding(Capability::Network, true)];
    let default = eval(&findings, &[], &GateConfig::default());
    assert_rule_severity(&default, "build-script-network", GateSeverity::Deny);

    let mut overrides = BTreeMap::new();
    overrides.insert(
        Box::from("build-script-network"),
        GateRuleOverride::Disabled,
    );
    let disabled = eval(&findings, &[], &config_with_overrides(true, overrides));
    assert_rule_absent(&disabled, "build-script-network");
}

pub(crate) fn test_severity_override_via_config() {
    let mut overrides = BTreeMap::new();
    overrides.insert(
        Box::from("build-script-network"),
        GateRuleOverride::Severity(GateSeverity::Info),
    );
    let verdicts = eval(
        &[finding(Capability::Network, true)],
        &[],
        &config_with_overrides(true, overrides),
    );
    assert_rule_severity(&verdicts, "build-script-network", GateSeverity::Info);
}

pub(crate) fn test_gate_disabled_entirely() {
    let findings = [
        finding(Capability::Network, true),
        finding(Capability::ProcessExec, true),
    ];
    assert_rule_severity(
        &eval(&findings, &[], &GateConfig::default()),
        "build-script-network",
        GateSeverity::Deny,
    );

    let disabled = eval(
        &findings,
        &[],
        &config_with_overrides(false, BTreeMap::new()),
    );
    assert_no_verdicts(&disabled, "a disabled gate produces no verdict");
}

pub(crate) fn test_gate_config_rejects_unknown_rule_name() {
    assert_gate_config_rejections(REJECTIONS);
}

pub(crate) fn test_all_gate_rules_returns_all_rules() {
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

pub(crate) fn test_env_access_network_info() {
    let verdicts = eval(
        &[
            finding(Capability::EnvAccess, false),
            finding(Capability::Network, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "env-access-network", GateSeverity::Info);
}

pub(crate) fn test_env_access_alone_no_verdict() {
    let verdicts = eval(
        &[finding(Capability::EnvAccess, false)],
        &[],
        &GateConfig::default(),
    );
    assert_no_verdicts(
        &verdicts,
        "env-access alone fires no rule, env-access-network included",
    );
}

pub(crate) fn test_key_material_network_warns() {
    let verdicts = eval(
        &[
            finding_with_evidence(Capability::Crypto, false, HEX_KEY),
            finding(Capability::Network, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "key-material-network", GateSeverity::Warn);
}

pub(crate) fn test_crypto_import_network_no_key_material_verdict() {
    // The env-access finding is the positive control: it proves the same
    // evaluation that emitted nothing for the crypto import did run.
    let verdicts = eval(
        &[
            finding_with_evidence(Capability::Crypto, false, "sha2::Digest"),
            finding(Capability::Network, false),
            finding(Capability::EnvAccess, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_eq!(
        rule_names(&verdicts),
        ["env-access-network"],
        "import-shaped crypto evidence emits every other rule and no key-material-network"
    );
}

pub(crate) fn test_pem_key_material_network() {
    let verdicts = eval(
        &[
            finding_with_evidence(
                Capability::Crypto,
                false,
                "-----BEGIN PRIVATE KEY-----MIIEvgIBA...",
            ),
            finding(Capability::Network, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "key-material-network", GateSeverity::Warn);
}

pub(crate) fn key_material_gate_uses_origin_import_not_key_material() {
    // Import-based crypto finding should NOT count as embedded key material.
    // The env-access finding is the positive control for the whole emitted set.
    let verdicts = eval(
        &[
            finding_with_origin(Capability::Crypto, FindingOrigin::Import, "sha2::Digest"),
            finding(Capability::Network, false),
            finding(Capability::EnvAccess, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_eq!(
        rule_names(&verdicts),
        ["env-access-network"],
        "import origin metadata emits every other rule and no key-material-network"
    );
}

pub(crate) fn key_material_gate_uses_origin_string_literal_is_key_material() {
    // String-literal crypto finding SHOULD count as embedded key material.
    let verdicts = eval(
        &[
            finding_with_origin(
                Capability::Crypto,
                FindingOrigin::StringLiteral,
                "0a1b2c3d…0a1b",
            ),
            finding(Capability::Network, false),
        ],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "key-material-network", GateSeverity::Warn);
}

pub(crate) fn key_material_gate_falls_back_to_heuristic_for_legacy() {
    // Findings without origin metadata should still work via the evidence heuristic.
    let legacy = finding_with_evidence(Capability::Crypto, false, HEX_KEY);
    assert!(
        legacy.origin.is_none(),
        "a legacy finding carries no origin metadata to classify"
    );
    let verdicts = eval(
        &[legacy, finding(Capability::Network, false)],
        &[],
        &GateConfig::default(),
    );
    assert_rule_severity(&verdicts, "key-material-network", GateSeverity::Warn);
}
