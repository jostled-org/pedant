//! Gate rules engine: evaluates capability profiles and data flows against security rules.
//!
//! Capability-combination rules fire on suspicious co-occurrence of capabilities.
//! Flow-aware rules fire when taint analysis detects a data path from source to sink.

use std::fmt;

use pedant_types::{Capability, CapabilityFinding};
use serde::Serialize;

use crate::check_config::GateConfig;
use crate::check_config::GateRuleOverride;
use crate::ir::{DataFlowFact, DataFlowKind};

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
    /// Why this combination of capabilities is suspicious.
    pub rationale: &'static str,
}

/// Internal rule definition pairing metadata with a predicate over `T` findings.
struct Rule<T> {
    name: &'static str,
    default_severity: GateSeverity,
    description: &'static str,
    rationale: &'static str,
    predicate: fn(&[T]) -> bool,
}

impl<T> Rule<T> {
    /// Extract public metadata from this rule.
    fn info(&self) -> GateRuleInfo {
        GateRuleInfo {
            name: self.name,
            default_severity: self.default_severity,
            description: self.description,
            rationale: self.rationale,
        }
    }

    /// Evaluate this rule against `data`, returning a verdict if the predicate fires
    /// and the rule is not disabled by config.
    fn evaluate(&self, data: &[T], config: &GateConfig) -> Option<GateVerdict> {
        let severity = resolve_severity(self.name, self.default_severity, config)?;
        (self.predicate)(data).then_some(GateVerdict {
            rule: self.name,
            severity,
            rationale: self.rationale,
        })
    }
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

const BUILTIN_RULES: &[Rule<CapabilityFinding>] = &[
    // --- Compile-time execution rules (build scripts) ---
    Rule {
        name: "build-script-network",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access",
        rationale: "Build scripts should not make network requests",
        predicate: |f| has_capability(f, Capability::Network, true),
    },
    Rule {
        name: "build-script-exec",
        default_severity: GateSeverity::Warn,
        description: "Build script spawning processes",
        rationale: "Build scripts spawning processes is common (cc, pkg-config) but risky",
        predicate: |f| has_capability(f, Capability::ProcessExec, true),
    },
    Rule {
        name: "build-script-download-exec",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access and process execution",
        rationale: "Download-and-execute in build script — classic supply chain attack",
        predicate: |f| {
            has_capability(f, Capability::Network, true)
                && has_capability(f, Capability::ProcessExec, true)
        },
    },
    Rule {
        name: "build-script-file-write",
        default_severity: GateSeverity::Warn,
        description: "Build script with filesystem write access",
        rationale: "Build scripts writing outside OUT_DIR is suspicious",
        predicate: |f| has_capability(f, Capability::FileWrite, true),
    },
    // --- Compile-time execution rules (proc macros) ---
    Rule {
        name: "proc-macro-network",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with network access",
        rationale: "Proc macros have no legitimate reason for network access",
        predicate: |f| {
            has_capability(f, Capability::ProcMacro, false)
                && has_capability(f, Capability::Network, false)
        },
    },
    Rule {
        name: "proc-macro-exec",
        default_severity: GateSeverity::Deny,
        description: "Proc macro spawning processes",
        rationale: "Proc macros have no legitimate reason to spawn processes",
        predicate: |f| {
            has_capability(f, Capability::ProcMacro, false)
                && has_capability(f, Capability::ProcessExec, false)
        },
    },
    Rule {
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
    Rule {
        name: "env-access-network",
        default_severity: GateSeverity::Info,
        description: "Environment variable access with network capability",
        rationale: "Reading environment variables and accessing network — review for credential harvesting",
        predicate: |f| {
            has_capability(f, Capability::EnvAccess, false)
                && has_capability(f, Capability::Network, false)
        },
    },
    Rule {
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

fn has_flow(data_flows: &[DataFlowFact], source: Capability, sink: Capability) -> bool {
    data_flows
        .iter()
        .any(|f| f.source_capability == Some(source) && f.sink_capability == Some(sink))
}

fn has_kind(data_flows: &[DataFlowFact], kind: DataFlowKind) -> bool {
    data_flows.iter().any(|f| f.kind == kind)
}

const FLOW_RULES: &[Rule<DataFlowFact>] = &[
    Rule {
        name: "env-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from environment variable to network sink",
        rationale: "Environment variable value reaches a network call — potential credential exfiltration",
        predicate: |f| has_flow(f, Capability::EnvAccess, Capability::Network),
    },
    Rule {
        name: "file-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from file read to network sink",
        rationale: "File content reaches a network call — potential data exfiltration",
        predicate: |f| has_flow(f, Capability::FileRead, Capability::Network),
    },
    Rule {
        name: "network-to-exec",
        default_severity: GateSeverity::Deny,
        description: "Data flows from network source to process execution",
        rationale: "Network-sourced data reaches process execution — remote code execution risk",
        predicate: |f| has_flow(f, Capability::Network, Capability::ProcessExec),
    },
    // --- Quality rules ---
    Rule {
        name: "dead-store",
        default_severity: GateSeverity::Warn,
        description: "Value assigned then overwritten before read",
        rationale: "Dead store indicates wasted computation or a missing read",
        predicate: |f| has_kind(f, DataFlowKind::DeadStore),
    },
    Rule {
        name: "discarded-result",
        default_severity: GateSeverity::Warn,
        description: "Result-returning function called without binding the return",
        rationale: "Discarded Result silently drops errors — handle or explicitly discard",
        predicate: |f| has_kind(f, DataFlowKind::DiscardedResult),
    },
    Rule {
        name: "partial-error-handling",
        default_severity: GateSeverity::Warn,
        description: "Result handled on some paths, dropped on others",
        rationale: "Inconsistent error handling — some branches swallow errors silently",
        predicate: |f| has_kind(f, DataFlowKind::PartialErrorHandling),
    },
    // --- Performance rules ---
    Rule {
        name: "repeated-call",
        default_severity: GateSeverity::Info,
        description: "Same function called with identical arguments in single scope",
        rationale: "Repeated call with same arguments — cache the result in a local binding",
        predicate: |f| has_kind(f, DataFlowKind::RepeatedCall),
    },
    Rule {
        name: "unnecessary-clone",
        default_severity: GateSeverity::Info,
        description: "Clone called but original never used afterward",
        rationale: "Unnecessary clone — move the original instead of copying",
        predicate: |f| has_kind(f, DataFlowKind::UnnecessaryClone),
    },
    Rule {
        name: "allocation-in-loop",
        default_severity: GateSeverity::Info,
        description: "Heap allocation inside loop body",
        rationale: "Allocation per iteration — hoist outside the loop and reuse with clear()",
        predicate: |f| has_kind(f, DataFlowKind::AllocationInLoop),
    },
    Rule {
        name: "redundant-collect",
        default_severity: GateSeverity::Info,
        description: "Collect followed immediately by re-iteration",
        rationale: "Redundant collect — chain iterator operations without intermediate Vec",
        predicate: |f| has_kind(f, DataFlowKind::RedundantCollect),
    },
    // --- Concurrency rules ---
    Rule {
        name: "lock-across-await",
        default_severity: GateSeverity::Deny,
        description: "Lock guard held across .await point",
        rationale: "Lock guard held across await — potential deadlock or task starvation",
        predicate: |f| has_kind(f, DataFlowKind::LockAcrossAwait),
    },
    Rule {
        name: "inconsistent-lock-order",
        default_severity: GateSeverity::Deny,
        description: "Same locks acquired in different orders across functions",
        rationale: "Inconsistent lock ordering across functions — potential deadlock",
        predicate: |f| has_kind(f, DataFlowKind::InconsistentLockOrder),
    },
];

/// Enumerate every built-in gate rule with its default severity and description.
pub fn all_gate_rules() -> Box<[GateRuleInfo]> {
    BUILTIN_RULES
        .iter()
        .map(Rule::info)
        .chain(FLOW_RULES.iter().map(Rule::info))
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

    let capability_verdicts = BUILTIN_RULES
        .iter()
        .filter_map(|rule| rule.evaluate(findings, config));

    let flow_verdicts = FLOW_RULES
        .iter()
        .filter_map(|rule| rule.evaluate(data_flows, config));

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
