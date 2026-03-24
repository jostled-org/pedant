//! Gate rules engine: evaluates capability profiles and data flows against security rules.
//!
//! Capability-combination rules fire on suspicious co-occurrence of capabilities.
//! Flow-aware rules fire when taint analysis detects a data path from source to sink.

use std::fmt;

use pedant_types::{Capability, CapabilityFinding};
use serde::Serialize;

use crate::check_config::GateConfig;
use crate::check_config::GateRuleOverride;
use crate::ir::DataFlowFact;

/// Controls whether a gate verdict blocks CI, warns, or is purely informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateSeverity {
    /// Blocks CI/publish with a non-zero exit code.
    Deny,
    /// Displayed but does not affect exit code.
    Warn,
    /// Logged for audit trail; no user-facing output by default.
    Info,
}

impl fmt::Display for GateSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => f.write_str("deny"),
            Self::Warn => f.write_str("warn"),
            Self::Info => f.write_str("info"),
        }
    }
}

/// Produced when a gate rule's predicate matches the capability profile.
#[derive(Serialize)]
pub struct GateVerdict {
    /// Kebab-case rule identifier (e.g., `"build-script-network"`).
    pub rule: &'static str,
    /// Effective severity after config overrides.
    pub severity: GateSeverity,
    /// Why this combination of capabilities is suspicious.
    pub rationale: &'static str,
}

/// Public metadata for a built-in gate rule, used by `--list-checks` and MCP tools.
pub struct GateRuleInfo {
    /// Kebab-case identifier used in config overrides and output.
    pub name: &'static str,
    /// Severity applied when no config override is present.
    pub default_severity: GateSeverity,
    /// One-line summary of the suspicious pattern.
    pub description: &'static str,
}

/// Internal rule definition pairing metadata with a predicate.
struct BuiltinRule {
    name: &'static str,
    default_severity: GateSeverity,
    description: &'static str,
    rationale: &'static str,
    predicate: fn(&[CapabilityFinding]) -> bool,
}

fn has_capability(
    findings: &[CapabilityFinding],
    cap: Capability,
    build_script_only: bool,
) -> bool {
    findings
        .iter()
        .any(|f| f.capability == cap && (!build_script_only || f.build_script))
}

const BUILTIN_RULES: &[BuiltinRule] = &[
    // --- Compile-time execution rules (build scripts) ---
    BuiltinRule {
        name: "build-script-network",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access",
        rationale: "Build scripts should not make network requests",
        predicate: |f| has_capability(f, Capability::Network, true),
    },
    BuiltinRule {
        name: "build-script-exec",
        default_severity: GateSeverity::Warn,
        description: "Build script spawning processes",
        rationale: "Build scripts spawning processes is common (cc, pkg-config) but risky",
        predicate: |f| has_capability(f, Capability::ProcessExec, true),
    },
    BuiltinRule {
        name: "build-script-download-exec",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access and process execution",
        rationale: "Download-and-execute in build script — classic supply chain attack",
        predicate: |f| {
            has_capability(f, Capability::Network, true)
                && has_capability(f, Capability::ProcessExec, true)
        },
    },
    BuiltinRule {
        name: "build-script-file-write",
        default_severity: GateSeverity::Warn,
        description: "Build script with filesystem write access",
        rationale: "Build scripts writing outside OUT_DIR is suspicious",
        predicate: |f| has_capability(f, Capability::FileWrite, true),
    },
    // --- Compile-time execution rules (proc macros) ---
    BuiltinRule {
        name: "proc-macro-network",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with network access",
        rationale: "Proc macros have no legitimate reason for network access",
        predicate: |f| {
            has_capability(f, Capability::ProcMacro, false)
                && has_capability(f, Capability::Network, false)
        },
    },
    BuiltinRule {
        name: "proc-macro-exec",
        default_severity: GateSeverity::Deny,
        description: "Proc macro spawning processes",
        rationale: "Proc macros have no legitimate reason to spawn processes",
        predicate: |f| {
            has_capability(f, Capability::ProcMacro, false)
                && has_capability(f, Capability::ProcessExec, false)
        },
    },
    BuiltinRule {
        name: "proc-macro-file-write",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with filesystem write access",
        rationale: "Proc macros should not write to the filesystem",
        predicate: |f| {
            has_capability(f, Capability::ProcMacro, false)
                && has_capability(f, Capability::FileWrite, false)
        },
    },
    // --- Runtime combination rules ---
    BuiltinRule {
        name: "env-access-network",
        default_severity: GateSeverity::Info,
        description: "Environment variable access with network capability",
        rationale: "Reading environment variables and accessing network — review for credential harvesting",
        predicate: |f| {
            has_capability(f, Capability::EnvAccess, false)
                && has_capability(f, Capability::Network, false)
        },
    },
    BuiltinRule {
        name: "key-material-network",
        default_severity: GateSeverity::Warn,
        description: "Embedded key material with network access",
        rationale: "Embedded key material with network access — verify intent",
        predicate: |f| has_capability(f, Capability::Network, false) && has_key_material(f),
    },
];

/// Check if findings contain Crypto entries from key material (not import paths).
///
/// Key material findings have evidence that is NOT a module path (no `::`)
/// and is not just a constant marker. Import-based findings like `sha2::Digest`
/// contain `::`.
fn has_key_material(findings: &[CapabilityFinding]) -> bool {
    findings
        .iter()
        .any(|f| f.capability == Capability::Crypto && !f.evidence.contains("::"))
}

/// Internal rule definition pairing metadata with a data flow predicate.
struct FlowRule {
    name: &'static str,
    default_severity: GateSeverity,
    description: &'static str,
    rationale: &'static str,
    predicate: fn(&[DataFlowFact]) -> bool,
}

fn has_flow(data_flows: &[DataFlowFact], source: Capability, sink: Capability) -> bool {
    data_flows
        .iter()
        .any(|f| f.source_capability == source && f.sink_capability == sink)
}

const FLOW_RULES: &[FlowRule] = &[
    FlowRule {
        name: "env-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from environment variable to network sink",
        rationale: "Environment variable value reaches a network call — potential credential exfiltration",
        predicate: |f| has_flow(f, Capability::EnvAccess, Capability::Network),
    },
    FlowRule {
        name: "file-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from file read to network sink",
        rationale: "File content reaches a network call — potential data exfiltration",
        predicate: |f| has_flow(f, Capability::FileRead, Capability::Network),
    },
    FlowRule {
        name: "network-to-exec",
        default_severity: GateSeverity::Deny,
        description: "Data flows from network source to process execution",
        rationale: "Network-sourced data reaches process execution — remote code execution risk",
        predicate: |f| has_flow(f, Capability::Network, Capability::ProcessExec),
    },
];

/// Enumerate every built-in gate rule with its default severity and description.
pub fn all_gate_rules() -> Box<[GateRuleInfo]> {
    BUILTIN_RULES
        .iter()
        .map(|r| GateRuleInfo {
            name: r.name,
            default_severity: r.default_severity,
            description: r.description,
        })
        .chain(FLOW_RULES.iter().map(|r| GateRuleInfo {
            name: r.name,
            default_severity: r.default_severity,
            description: r.description,
        }))
        .collect()
}

/// Run every enabled gate rule against the findings, returning fired verdicts.
///
/// Evaluates both capability-combination rules (from `findings`) and
/// flow-aware rules (from `data_flows`). Respects per-rule config overrides.
pub fn evaluate_gate_rules(
    findings: &[CapabilityFinding],
    data_flows: &[DataFlowFact],
    config: &GateConfig,
) -> Box<[GateVerdict]> {
    if !config.enabled {
        return Box::new([]);
    }

    let capability_verdicts = BUILTIN_RULES.iter().filter_map(|rule| {
        let severity = resolve_severity(rule.name, rule.default_severity, config)?;
        (rule.predicate)(findings).then_some(GateVerdict {
            rule: rule.name,
            severity,
            rationale: rule.rationale,
        })
    });

    let flow_verdicts = FLOW_RULES.iter().filter_map(|rule| {
        let severity = resolve_severity(rule.name, rule.default_severity, config)?;
        (rule.predicate)(data_flows).then_some(GateVerdict {
            rule: rule.name,
            severity,
            rationale: rule.rationale,
        })
    });

    capability_verdicts.chain(flow_verdicts).collect()
}

/// Resolve the effective severity for a rule, returning `None` if disabled.
fn resolve_severity(
    name: &str,
    default: GateSeverity,
    config: &GateConfig,
) -> Option<GateSeverity> {
    match config.overrides.get(name) {
        Some(GateRuleOverride::Disabled) => None,
        Some(GateRuleOverride::Severity(s)) => Some(*s),
        None => Some(default),
    }
}
