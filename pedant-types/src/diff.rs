use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::{Capability, CapabilityFinding, CapabilityProfile};

/// Set-difference between two capability profiles.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityDiff {
    /// Findings present in `new` but absent from `old`.
    pub added: Box<[CapabilityFinding]>,
    /// Findings present in `old` but absent from `new`.
    pub removed: Box<[CapabilityFinding]>,
    /// Capability types that gained their first finding.
    pub new_capabilities: Box<[Capability]>,
    /// Capability types that lost their last finding.
    pub dropped_capabilities: Box<[Capability]>,
}

impl CapabilityDiff {
    /// No findings were added, removed, or changed capability type.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.new_capabilities.is_empty()
            && self.dropped_capabilities.is_empty()
    }

    /// Produce the set-difference between two profiles.
    pub fn compute(old: &CapabilityProfile, new: &CapabilityProfile) -> Self {
        let old_set: FxHashSet<&CapabilityFinding> = old.findings.iter().collect();
        let new_set: FxHashSet<&CapabilityFinding> = new.findings.iter().collect();

        let added: Box<[CapabilityFinding]> = new
            .findings
            .iter()
            .filter(|f| !old_set.contains(f))
            .cloned()
            .collect();

        let removed: Box<[CapabilityFinding]> = old
            .findings
            .iter()
            .filter(|f| !new_set.contains(f))
            .cloned()
            .collect();

        let old_caps: FxHashSet<Capability> = old.findings.iter().map(|f| f.capability).collect();
        let new_caps: FxHashSet<Capability> = new.findings.iter().map(|f| f.capability).collect();

        let mut new_capabilities: Vec<Capability> =
            new_caps.difference(&old_caps).copied().collect();
        new_capabilities.sort_unstable();

        let mut dropped_capabilities: Vec<Capability> =
            old_caps.difference(&new_caps).copied().collect();
        dropped_capabilities.sort_unstable();

        Self {
            added,
            removed,
            new_capabilities: new_capabilities.into_boxed_slice(),
            dropped_capabilities: dropped_capabilities.into_boxed_slice(),
        }
    }
}
