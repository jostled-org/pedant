//! Gate rules engine: evaluates capability profiles and data flows against security rules.
//!
//! Capability-combination rules fire on suspicious co-occurrence of capabilities.
//! Flow-aware rules fire when taint analysis detects a data path from source to sink.

use std::collections::BTreeSet;
use std::fmt;

use pedant_types::{Capability, CapabilityFinding, FindingOrigin};
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

/// Precomputed summary of capability findings and data flows for gate evaluation.
///
/// Built once per evaluation from raw findings and flows. Every rule predicate
/// reads from this summary instead of rescanning the original slices.
pub struct GateInputSummary {
    all_capabilities: BTreeSet<Capability>,
    build_hook_capabilities: BTreeSet<Capability>,
    has_key_material: bool,
    flow_kinds: BTreeSet<DataFlowKind>,
    taint_pairs: BTreeSet<(Capability, Capability)>,
}

/// Check if a single finding represents embedded key material (not a crypto import).
///
/// When `origin` metadata is present, uses it directly: `StringLiteral` origin
/// indicates embedded key material. Falls back to evidence-based heuristic
/// (no `::` in evidence) for legacy findings without origin metadata.
fn is_key_material(f: &CapabilityFinding) -> bool {
    match (f.capability, f.origin) {
        (Capability::Crypto, Some(FindingOrigin::StringLiteral)) => true,
        (Capability::Crypto, None) => !f.evidence.contains("::"),
        _ => false,
    }
}

impl GateInputSummary {
    /// Build a summary from raw findings and data flow facts.
    pub fn from_analysis(findings: &[CapabilityFinding], flows: &[DataFlowFact]) -> Self {
        let mut all_capabilities = BTreeSet::new();
        let mut build_hook_capabilities = BTreeSet::new();
        let has_key_material = findings.iter().any(is_key_material);

        for finding in findings {
            all_capabilities.insert(finding.capability);
            if finding.is_build_hook() {
                build_hook_capabilities.insert(finding.capability);
            }
        }

        Self::with_capability_sets(
            all_capabilities,
            build_hook_capabilities,
            has_key_material,
            flows,
        )
    }

    /// Build a summary from borrowed finding references and data flow facts.
    pub fn from_refs(findings: &[&CapabilityFinding], flows: &[DataFlowFact]) -> Self {
        let mut all_capabilities = BTreeSet::new();
        let mut build_hook_capabilities = BTreeSet::new();
        let has_key_material = findings.iter().any(|f| is_key_material(f));

        for finding in findings {
            all_capabilities.insert(finding.capability);
            if finding.is_build_hook() {
                build_hook_capabilities.insert(finding.capability);
            }
        }

        Self::with_capability_sets(
            all_capabilities,
            build_hook_capabilities,
            has_key_material,
            flows,
        )
    }

    fn with_capability_sets(
        all_capabilities: BTreeSet<Capability>,
        build_hook_capabilities: BTreeSet<Capability>,
        has_key_material: bool,
        flows: &[DataFlowFact],
    ) -> Self {
        let mut flow_kinds = BTreeSet::new();
        let mut taint_pairs = BTreeSet::new();
        for flow in flows {
            flow_kinds.insert(flow.kind);
            if let (Some(src), Some(sink)) = (flow.source_capability, flow.sink_capability) {
                taint_pairs.insert((src, sink));
            }
        }

        Self {
            all_capabilities,
            build_hook_capabilities,
            has_key_material,
            flow_kinds,
            taint_pairs,
        }
    }

    fn has_capability(&self, cap: Capability) -> bool {
        self.all_capabilities.contains(&cap)
    }

    fn has_build_hook_capability(&self, cap: Capability) -> bool {
        self.build_hook_capabilities.contains(&cap)
    }

    fn has_flow(&self, source: Capability, sink: Capability) -> bool {
        self.taint_pairs.contains(&(source, sink))
    }

    fn has_kind(&self, kind: DataFlowKind) -> bool {
        self.flow_kinds.contains(&kind)
    }
}

/// Internal rule definition pairing metadata with a predicate over `GateInputSummary`.
struct Rule {
    name: &'static str,
    default_severity: GateSeverity,
    description: &'static str,
    rationale: &'static str,
    predicate: fn(&GateInputSummary) -> bool,
}

impl Rule {
    /// Extract public metadata from this rule.
    fn info(&self) -> GateRuleInfo {
        GateRuleInfo {
            name: self.name,
            default_severity: self.default_severity,
            description: self.description,
            rationale: self.rationale,
        }
    }

    /// Evaluate this rule against the summary, returning a verdict if the predicate
    /// fires and the rule is not disabled by config.
    fn evaluate(&self, summary: &GateInputSummary, config: &GateConfig) -> Option<GateVerdict> {
        let severity = resolve_severity(self.name, self.default_severity, config)?;
        (self.predicate)(summary).then_some(GateVerdict {
            rule: self.name,
            severity,
            rationale: self.rationale,
        })
    }
}

const RULES: &[Rule] = &[
    // --- Compile-time execution rules (build scripts) ---
    Rule {
        name: "build-script-network",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access",
        rationale: "Build scripts should not make network requests",
        predicate: |s| s.has_build_hook_capability(Capability::Network),
    },
    Rule {
        name: "build-script-exec",
        default_severity: GateSeverity::Warn,
        description: "Build script spawning processes",
        rationale: "Build scripts spawning processes is common (cc, pkg-config) but risky",
        predicate: |s| s.has_build_hook_capability(Capability::ProcessExec),
    },
    Rule {
        name: "build-script-download-exec",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access and process execution",
        rationale: "Download-and-execute in build script — classic supply chain attack",
        predicate: |s| {
            s.has_build_hook_capability(Capability::Network)
                && s.has_build_hook_capability(Capability::ProcessExec)
        },
    },
    Rule {
        name: "build-script-file-write",
        default_severity: GateSeverity::Warn,
        description: "Build script with filesystem write access",
        rationale: "Build scripts writing outside OUT_DIR is suspicious",
        predicate: |s| s.has_build_hook_capability(Capability::FileWrite),
    },
    // --- Compile-time execution rules (proc macros) ---
    Rule {
        name: "proc-macro-network",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with network access",
        rationale: "Proc macros have no legitimate reason for network access",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::Network)
        },
    },
    Rule {
        name: "proc-macro-exec",
        default_severity: GateSeverity::Deny,
        description: "Proc macro spawning processes",
        rationale: "Proc macros have no legitimate reason to spawn processes",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::ProcessExec)
        },
    },
    Rule {
        name: "proc-macro-file-write",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with filesystem write access",
        rationale: "Proc macros should not write to the filesystem",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::FileWrite)
        },
    },
    // --- Runtime combination rules ---
    Rule {
        name: "env-access-network",
        default_severity: GateSeverity::Info,
        description: "Environment variable access with network capability",
        rationale: "Reading environment variables and accessing network — review for credential harvesting",
        predicate: |s| {
            s.has_capability(Capability::EnvAccess) && s.has_capability(Capability::Network)
        },
    },
    Rule {
        name: "key-material-network",
        default_severity: GateSeverity::Warn,
        description: "Embedded key material with network access",
        rationale: "Embedded key material with network access — verify intent",
        predicate: |s| s.has_capability(Capability::Network) && s.has_key_material,
    },
    // --- Flow-aware rules ---
    Rule {
        name: "env-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from environment variable to network sink",
        rationale: "Environment variable value reaches a network call — potential credential exfiltration",
        predicate: |s| s.has_flow(Capability::EnvAccess, Capability::Network),
    },
    Rule {
        name: "file-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from file read to network sink",
        rationale: "File content reaches a network call — potential data exfiltration",
        predicate: |s| s.has_flow(Capability::FileRead, Capability::Network),
    },
    Rule {
        name: "network-to-exec",
        default_severity: GateSeverity::Deny,
        description: "Data flows from network source to process execution",
        rationale: "Network-sourced data reaches process execution — remote code execution risk",
        predicate: |s| s.has_flow(Capability::Network, Capability::ProcessExec),
    },
    // --- Quality rules ---
    Rule {
        name: "dead-store",
        default_severity: GateSeverity::Warn,
        description: "Value assigned then overwritten before read",
        rationale: "Dead store indicates wasted computation or a missing read",
        predicate: |s| s.has_kind(DataFlowKind::DeadStore),
    },
    Rule {
        name: "discarded-result",
        default_severity: GateSeverity::Warn,
        description: "Result-returning function called without binding the return",
        rationale: "Discarded Result silently drops errors — handle or explicitly discard",
        predicate: |s| s.has_kind(DataFlowKind::DiscardedResult),
    },
    Rule {
        name: "partial-error-handling",
        default_severity: GateSeverity::Warn,
        description: "Result handled on some paths, dropped on others",
        rationale: "Inconsistent error handling — some branches swallow errors silently",
        predicate: |s| s.has_kind(DataFlowKind::PartialErrorHandling),
    },
    Rule {
        name: "swallowed-ok",
        default_severity: GateSeverity::Warn,
        description: ".ok() on Result where Option is discarded",
        rationale: ".ok() silently drops the error — handle the Result or explicitly discard with comment",
        predicate: |s| s.has_kind(DataFlowKind::SwallowedOk),
    },
    Rule {
        name: "immutable-growable",
        default_severity: GateSeverity::Info,
        description: "Vec or String never mutated after construction",
        rationale: "Immutable growable collection — use Box<[T]> or Box<str> instead",
        predicate: |s| s.has_kind(DataFlowKind::ImmutableGrowable),
    },
    // --- Performance rules ---
    Rule {
        name: "repeated-call",
        default_severity: GateSeverity::Info,
        description: "Same function called with identical arguments in single scope",
        rationale: "Repeated call with same arguments — cache the result in a local binding",
        predicate: |s| s.has_kind(DataFlowKind::RepeatedCall),
    },
    Rule {
        name: "unnecessary-clone",
        default_severity: GateSeverity::Info,
        description: "Clone called but original never used afterward",
        rationale: "Unnecessary clone — move the original instead of copying",
        predicate: |s| s.has_kind(DataFlowKind::UnnecessaryClone),
    },
    Rule {
        name: "allocation-in-loop",
        default_severity: GateSeverity::Info,
        description: "Heap allocation inside loop body",
        rationale: "Allocation per iteration — hoist outside the loop and reuse with clear()",
        predicate: |s| s.has_kind(DataFlowKind::AllocationInLoop),
    },
    Rule {
        name: "redundant-collect",
        default_severity: GateSeverity::Info,
        description: "Collect followed immediately by re-iteration",
        rationale: "Redundant collect — chain iterator operations without intermediate Vec",
        predicate: |s| s.has_kind(DataFlowKind::RedundantCollect),
    },
    // --- Concurrency rules ---
    Rule {
        name: "lock-across-await",
        default_severity: GateSeverity::Deny,
        description: "Lock guard held across .await point",
        rationale: "Lock guard held across await — potential deadlock or task starvation",
        predicate: |s| s.has_kind(DataFlowKind::LockAcrossAwait),
    },
    Rule {
        name: "inconsistent-lock-order",
        default_severity: GateSeverity::Deny,
        description: "Same locks acquired in different orders across functions",
        rationale: "Inconsistent lock ordering across functions — potential deadlock",
        predicate: |s| s.has_kind(DataFlowKind::InconsistentLockOrder),
    },
    Rule {
        name: "unobserved-spawn",
        default_severity: GateSeverity::Warn,
        description: "Thread/task spawned with dropped JoinHandle",
        rationale: "Dropped JoinHandle means panics in the spawned thread/task vanish silently",
        predicate: |s| s.has_kind(DataFlowKind::UnobservedSpawn),
    },
];

/// Enumerate every built-in gate rule with its default severity and description.
pub fn all_gate_rules() -> Box<[GateRuleInfo]> {
    RULES.iter().map(Rule::info).collect()
}

/// Run every enabled gate rule against a precomputed summary, returning fired verdicts.
///
/// Build the summary via `GateInputSummary::from_analysis` before calling this.
/// Respects per-rule config overrides.
pub fn evaluate_gate_rules(summary: &GateInputSummary, config: &GateConfig) -> Box<[GateVerdict]> {
    if !config.enabled {
        return Box::new([]);
    }

    RULES
        .iter()
        .filter_map(|rule| rule.evaluate(summary, config))
        .collect()
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
