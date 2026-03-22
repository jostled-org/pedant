//! Gate rules engine: evaluates capability profiles against built-in security rules.
//!
//! Each rule is a predicate over a [`pedant_types::CapabilityProfile`] that produces a verdict
//! when suspicious capability combinations are detected.

use std::fmt;

use pedant_types::{Capability, CapabilityFinding};
use serde::Serialize;

use crate::check_config::GateConfig;
use crate::check_config::GateRuleOverride;

/// Severity level for a gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateSeverity {
    /// Hard failure — blocks publish/CI.
    Deny,
    /// Advisory — displayed but does not block.
    Warn,
    /// Informational — logged for review.
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

/// Result of a gate rule firing against a capability profile.
#[derive(Serialize)]
pub struct GateVerdict {
    /// Rule name (e.g. `"build-script-network"`).
    pub rule: &'static str,
    /// Effective severity (default or overridden by config).
    pub severity: GateSeverity,
    /// Human-readable explanation of why this rule fired.
    pub rationale: &'static str,
}

/// Metadata about a built-in gate rule.
pub struct GateRuleInfo {
    /// Rule name used in config and output.
    pub name: &'static str,
    /// Severity when no config override is set.
    pub default_severity: GateSeverity,
    /// What this rule detects.
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

static BUILTIN_RULES: &[BuiltinRule] = &[
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

/// Returns metadata for all built-in gate rules.
pub fn all_gate_rules() -> Box<[GateRuleInfo]> {
    BUILTIN_RULES
        .iter()
        .map(|r| GateRuleInfo {
            name: r.name,
            default_severity: r.default_severity,
            description: r.description,
        })
        .collect()
}

/// Evaluate all gate rules against capability findings.
///
/// Returns verdicts for rules whose predicates match. Respects config
/// overrides for disabling rules and changing severity.
pub fn evaluate_gate_rules(
    findings: &[CapabilityFinding],
    config: &GateConfig,
) -> Box<[GateVerdict]> {
    if !config.enabled {
        return Box::new([]);
    }

    BUILTIN_RULES
        .iter()
        .filter_map(|rule| {
            let severity = match config.overrides.get(rule.name) {
                Some(GateRuleOverride::Disabled) => return None,
                Some(GateRuleOverride::Severity(s)) => *s,
                None => rule.default_severity,
            };

            (rule.predicate)(findings).then_some(GateVerdict {
                rule: rule.name,
                severity,
                rationale: rule.rationale,
            })
        })
        .collect()
}
