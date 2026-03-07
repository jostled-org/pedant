use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilityFinding};

/// A collection of capability findings for a crate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityProfile {
    /// All findings from the analysis.
    pub findings: Vec<CapabilityFinding>,
}

impl CapabilityProfile {
    /// Returns deduplicated, sorted set of capabilities present in the profile.
    pub fn capabilities(&self) -> Vec<Capability> {
        let mut caps: Vec<Capability> = self.findings.iter().map(|f| f.capability).collect();
        caps.sort();
        caps.dedup();
        caps
    }

    /// Returns findings filtered to a specific capability.
    pub fn findings_for(&self, capability: Capability) -> Vec<&CapabilityFinding> {
        self.findings
            .iter()
            .filter(|f| f.capability == capability)
            .collect()
    }
}
