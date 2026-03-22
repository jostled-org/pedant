use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilityFinding};

/// A collection of capability findings for a crate.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityProfile {
    /// All findings from the analysis.
    pub findings: Box<[CapabilityFinding]>,
}

impl CapabilityProfile {
    /// Returns deduplicated, sorted set of capabilities present in the profile.
    /// Recomputes on each call; callers needing repeated access should cache the result.
    pub fn capabilities(&self) -> Box<[Capability]> {
        let mut caps: Vec<Capability> = self.findings.iter().map(|f| f.capability).collect();
        caps.sort();
        caps.dedup();
        caps.into_boxed_slice()
    }

    /// Returns findings filtered to a specific capability.
    pub fn findings_for(&self, capability: Capability) -> impl Iterator<Item = &CapabilityFinding> {
        self.findings
            .iter()
            .filter(move |f| f.capability == capability)
    }
}
