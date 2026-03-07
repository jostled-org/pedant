use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilityFinding, CapabilityProfile};

/// The difference between two capability profiles.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityDiff {
    /// Findings present in `new` but not in `old`.
    pub added: Vec<CapabilityFinding>,
    /// Findings present in `old` but not in `new`.
    pub removed: Vec<CapabilityFinding>,
    /// Capabilities that appear in `new` but had zero findings in `old`.
    pub new_capabilities: Vec<Capability>,
    /// Capabilities that appeared in `old` but have zero findings in `new`.
    pub dropped_capabilities: Vec<Capability>,
}

impl CapabilityDiff {
    /// Compute the diff between an old and new profile.
    pub fn compute(old: &CapabilityProfile, new: &CapabilityProfile) -> Self {
        let added: Vec<CapabilityFinding> = new
            .findings
            .iter()
            .filter(|f| !old.findings.contains(f))
            .cloned()
            .collect();

        let removed: Vec<CapabilityFinding> = old
            .findings
            .iter()
            .filter(|f| !new.findings.contains(f))
            .cloned()
            .collect();

        let old_caps = old.capabilities();
        let new_caps = new.capabilities();

        let new_capabilities: Vec<Capability> = new_caps
            .iter()
            .filter(|c| !old_caps.contains(c))
            .copied()
            .collect();

        let dropped_capabilities: Vec<Capability> = old_caps
            .iter()
            .filter(|c| !new_caps.contains(c))
            .copied()
            .collect();

        Self {
            added,
            removed,
            new_capabilities,
            dropped_capabilities,
        }
    }
}
