use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilityFinding};

/// Aggregated capability findings for a crate or file.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityProfile {
    /// Every capability finding, unsorted and possibly duplicated across files.
    pub findings: Box<[CapabilityFinding]>,
}

impl CapabilityProfile {
    /// Deduplicated, sorted capability set. Recomputes on each call -- cache if needed.
    pub fn capabilities(&self) -> Box<[Capability]> {
        let mut caps: Vec<Capability> = self.findings.iter().map(|f| f.capability).collect();
        caps.sort();
        caps.dedup();
        caps.into_boxed_slice()
    }

    /// Iterate over findings matching a single capability type.
    pub fn findings_for(&self, capability: Capability) -> impl Iterator<Item = &CapabilityFinding> {
        self.findings
            .iter()
            .filter(move |f| f.capability == capability)
    }
}
