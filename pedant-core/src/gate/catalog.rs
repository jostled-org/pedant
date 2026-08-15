//! Rule metadata and the two rule catalogs: capability and module boundary.
//!
//! A rule pairs static metadata with a predicate. The predicate's input type is
//! the only thing that differs between the two catalogs, so both share one rule
//! shape, one metadata projection, and one severity resolution.

use std::collections::BTreeMap;

use pedant_types::Capability;

use crate::check_config::{GateRuleOverride, ModuleBoundaryConfig};
use crate::ir::DataFlowKind;

use super::capability::GateInputSummary;
use super::module_boundary;
use super::verdict::{GateEvidence, GateSeverity, GateVerdict, ModuleBoundaryMeasurement};

/// Public metadata for a built-in gate rule, used by `--list-checks` and MCP tools.
pub struct GateRuleInfo {
    /// Kebab-case identifier used in config overrides and output.
    pub name: &'static str,
    /// Severity applied when no config override is present.
    pub default_severity: GateSeverity,
    /// One-line summary of the pattern the rule detects.
    pub description: &'static str,
    /// Why the detected pattern is worth a verdict.
    pub rationale: &'static str,
}

/// Internal rule definition pairing metadata with a predicate.
pub(super) struct GateRule<P> {
    pub(super) name: &'static str,
    pub(super) default_severity: GateSeverity,
    pub(super) description: &'static str,
    pub(super) rationale: &'static str,
    pub(super) predicate: P,
}

impl<P> GateRule<P> {
    /// Extract public metadata from this rule.
    fn info(&self) -> GateRuleInfo {
        GateRuleInfo {
            name: self.name,
            default_severity: self.default_severity,
            description: self.description,
            rationale: self.rationale,
        }
    }

    /// Project this rule's metadata onto a fired verdict.
    ///
    /// Both evaluators emit through here, so a field added to `GateVerdict` has
    /// one construction site rather than one per catalog.
    pub(super) fn verdict(
        &self,
        severity: GateSeverity,
        evidence: Option<GateEvidence>,
    ) -> GateVerdict {
        GateVerdict {
            rule: self.name,
            severity,
            rationale: self.rationale,
            evidence,
        }
    }
}

/// A rule over a precomputed capability and data-flow summary.
pub(super) type CapabilityRule = GateRule<fn(&GateInputSummary) -> bool>;

/// A rule over one validated graph-neutral structural measurement.
pub(super) type ModuleBoundaryRule =
    GateRule<fn(&ModuleBoundaryMeasurement, &ModuleBoundaryConfig) -> bool>;

pub(super) const CAPABILITY_RULES: &[CapabilityRule] = &[
    // --- Compile-time execution rules (build scripts) ---
    CapabilityRule {
        name: "build-script-network",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access",
        rationale: "Build scripts should not make network requests",
        predicate: |s| s.has_build_hook_capability(Capability::Network),
    },
    CapabilityRule {
        name: "build-script-exec",
        default_severity: GateSeverity::Warn,
        description: "Build script spawning processes",
        rationale: "Build scripts spawning processes is common (cc, pkg-config) but risky",
        predicate: |s| s.has_build_hook_capability(Capability::ProcessExec),
    },
    CapabilityRule {
        name: "build-script-download-exec",
        default_severity: GateSeverity::Deny,
        description: "Build script with network access and process execution",
        rationale: "Download-and-execute in build script — classic supply chain attack",
        predicate: |s| {
            s.has_build_hook_capability(Capability::Network)
                && s.has_build_hook_capability(Capability::ProcessExec)
        },
    },
    CapabilityRule {
        name: "build-script-file-write",
        default_severity: GateSeverity::Warn,
        description: "Build script with filesystem write access",
        rationale: "Build scripts writing outside OUT_DIR is suspicious",
        predicate: |s| s.has_build_hook_capability(Capability::FileWrite),
    },
    // --- Compile-time execution rules (proc macros) ---
    CapabilityRule {
        name: "proc-macro-network",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with network access",
        rationale: "Proc macros have no legitimate reason for network access",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::Network)
        },
    },
    CapabilityRule {
        name: "proc-macro-exec",
        default_severity: GateSeverity::Deny,
        description: "Proc macro spawning processes",
        rationale: "Proc macros have no legitimate reason to spawn processes",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::ProcessExec)
        },
    },
    CapabilityRule {
        name: "proc-macro-file-write",
        default_severity: GateSeverity::Deny,
        description: "Proc macro with filesystem write access",
        rationale: "Proc macros should not write to the filesystem",
        predicate: |s| {
            s.has_capability(Capability::ProcMacro) && s.has_capability(Capability::FileWrite)
        },
    },
    // --- Runtime combination rules ---
    CapabilityRule {
        name: "env-access-network",
        default_severity: GateSeverity::Info,
        description: "Environment variable access with network capability",
        rationale: "Reading environment variables and accessing network — review for credential harvesting",
        predicate: |s| {
            s.has_capability(Capability::EnvAccess) && s.has_capability(Capability::Network)
        },
    },
    CapabilityRule {
        name: "key-material-network",
        default_severity: GateSeverity::Warn,
        description: "Embedded key material with network access",
        rationale: "Embedded key material with network access — verify intent",
        predicate: |s| s.has_capability(Capability::Network) && s.has_key_material(),
    },
    // --- Flow-aware rules ---
    CapabilityRule {
        name: "env-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from environment variable to network sink",
        rationale: "Environment variable value reaches a network call — potential credential exfiltration",
        predicate: |s| s.has_flow(Capability::EnvAccess, Capability::Network),
    },
    CapabilityRule {
        name: "file-to-network",
        default_severity: GateSeverity::Deny,
        description: "Data flows from file read to network sink",
        rationale: "File content reaches a network call — potential data exfiltration",
        predicate: |s| s.has_flow(Capability::FileRead, Capability::Network),
    },
    CapabilityRule {
        name: "network-to-exec",
        default_severity: GateSeverity::Deny,
        description: "Data flows from network source to process execution",
        rationale: "Network-sourced data reaches process execution — remote code execution risk",
        predicate: |s| s.has_flow(Capability::Network, Capability::ProcessExec),
    },
    // --- Quality rules ---
    CapabilityRule {
        name: "dead-store",
        default_severity: GateSeverity::Warn,
        description: "Value assigned then overwritten before read",
        rationale: "Dead store indicates wasted computation or a missing read",
        predicate: |s| s.has_kind(DataFlowKind::DeadStore),
    },
    CapabilityRule {
        name: "discarded-result",
        default_severity: GateSeverity::Warn,
        description: "Result-returning function called without binding the return",
        rationale: "Discarded Result silently drops errors — handle or explicitly discard",
        predicate: |s| s.has_kind(DataFlowKind::DiscardedResult),
    },
    CapabilityRule {
        name: "partial-error-handling",
        default_severity: GateSeverity::Warn,
        description: "Result handled on some paths, dropped on others",
        rationale: "Inconsistent error handling — some branches swallow errors silently",
        predicate: |s| s.has_kind(DataFlowKind::PartialErrorHandling),
    },
    CapabilityRule {
        name: "swallowed-ok",
        default_severity: GateSeverity::Warn,
        description: ".ok() on Result where Option is discarded",
        rationale: ".ok() silently drops the error — handle the Result or explicitly discard with comment",
        predicate: |s| s.has_kind(DataFlowKind::SwallowedOk),
    },
    CapabilityRule {
        name: "immutable-growable",
        default_severity: GateSeverity::Info,
        description: "Vec or String never mutated after construction",
        rationale: "Immutable growable collection — use Box<[T]> or Box<str> instead",
        predicate: |s| s.has_kind(DataFlowKind::ImmutableGrowable),
    },
    // --- Performance rules ---
    CapabilityRule {
        name: "repeated-call",
        default_severity: GateSeverity::Info,
        description: "Same function called with identical arguments in single scope",
        rationale: "Repeated call with same arguments — cache the result in a local binding",
        predicate: |s| s.has_kind(DataFlowKind::RepeatedCall),
    },
    CapabilityRule {
        name: "unnecessary-clone",
        default_severity: GateSeverity::Info,
        description: "Clone called but original never used afterward",
        rationale: "Unnecessary clone — move the original instead of copying",
        predicate: |s| s.has_kind(DataFlowKind::UnnecessaryClone),
    },
    CapabilityRule {
        name: "allocation-in-loop",
        default_severity: GateSeverity::Info,
        description: "Heap allocation inside loop body",
        rationale: "Allocation per iteration — hoist outside the loop and reuse with clear()",
        predicate: |s| s.has_kind(DataFlowKind::AllocationInLoop),
    },
    CapabilityRule {
        name: "redundant-collect",
        default_severity: GateSeverity::Info,
        description: "Collect followed immediately by re-iteration",
        rationale: "Redundant collect — chain iterator operations without intermediate Vec",
        predicate: |s| s.has_kind(DataFlowKind::RedundantCollect),
    },
    // --- Concurrency rules ---
    CapabilityRule {
        name: "lock-across-await",
        default_severity: GateSeverity::Deny,
        description: "Lock guard held across .await point",
        rationale: "Lock guard held across await — potential deadlock or task starvation",
        predicate: |s| s.has_kind(DataFlowKind::LockAcrossAwait),
    },
    CapabilityRule {
        name: "inconsistent-lock-order",
        default_severity: GateSeverity::Deny,
        description: "Same locks acquired in different orders across functions",
        rationale: "Inconsistent lock ordering across functions — potential deadlock",
        predicate: |s| s.has_kind(DataFlowKind::InconsistentLockOrder),
    },
    CapabilityRule {
        name: "unobserved-spawn",
        default_severity: GateSeverity::Warn,
        description: "Thread/task spawned with dropped JoinHandle",
        rationale: "Dropped JoinHandle means panics in the spawned thread/task vanish silently",
        predicate: |s| s.has_kind(DataFlowKind::UnobservedSpawn),
    },
];

pub(super) const MODULE_BOUNDARY_RULES: &[ModuleBoundaryRule] = &[
    ModuleBoundaryRule {
        name: "large-scc",
        default_severity: GateSeverity::Warn,
        description: "Cyclic component exceeds the configured member limit",
        rationale: "cyclic component exceeds max-scc-members",
        predicate: module_boundary::is_large_component,
    },
    ModuleBoundaryRule {
        name: "boundary-crossing-scc",
        default_severity: GateSeverity::Deny,
        description: "Cycle crosses a declared module boundary",
        rationale: "cycle crosses declared module partitions",
        predicate: |measurement, _| module_boundary::is_boundary_crossing_component(measurement),
    },
    ModuleBoundaryRule {
        name: "misplaced-symbol",
        default_severity: GateSeverity::Warn,
        description: "Symbol has stronger outgoing affinity to another module",
        rationale: "foreign-edge affinity meets the misplaced-symbol threshold",
        predicate: module_boundary::is_misplaced_symbol,
    },
    ModuleBoundaryRule {
        name: "low-module-cohesion",
        default_severity: GateSeverity::Warn,
        description: "Module sends too little selected traffic to itself",
        rationale: "internal-edge cohesion is below the configured threshold",
        predicate: module_boundary::is_low_cohesion_module,
    },
];

/// Enumerate every built-in capability and data-flow rule.
pub fn all_gate_rules() -> Box<[GateRuleInfo]> {
    CAPABILITY_RULES.iter().map(GateRule::info).collect()
}

/// Enumerate every built-in module-boundary rule.
pub fn all_module_boundary_rules() -> Box<[GateRuleInfo]> {
    MODULE_BOUNDARY_RULES.iter().map(GateRule::info).collect()
}

/// Whether a written name is a built-in capability or data-flow rule.
///
/// Configuration asks per key, so it reads the catalog directly rather than
/// through the listing, which allocates the whole projection to answer once.
pub fn is_gate_rule(name: &str) -> bool {
    CAPABILITY_RULES.iter().any(|rule| rule.name == name)
}

/// Whether a written name is a built-in module-boundary rule.
pub fn is_module_boundary_rule(name: &str) -> bool {
    MODULE_BOUNDARY_RULES.iter().any(|rule| rule.name == name)
}

/// Resolve the effective severity for a rule, returning `None` if disabled.
pub(super) fn resolve_severity(
    name: &str,
    default: GateSeverity,
    overrides: &BTreeMap<Box<str>, GateRuleOverride>,
) -> Option<GateSeverity> {
    match overrides.get(name) {
        Some(GateRuleOverride::Disabled) => None,
        Some(GateRuleOverride::Severity(severity)) => Some(*severity),
        None => Some(default),
    }
}
