use std::mem;

use serde::{Deserialize, Serialize};

use crate::{
    Capability, CapabilityFinding, CapabilityProfile, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

/// A complete capability analysis.
///
/// A `CapabilityAnalysis` is the flat profile plus the symbol projection over
/// the same findings.
///
/// `profile` owns every finding and stays the persisted and policy authority —
/// attestations, baseline diffs, gate evaluation, CLI output, and MCP payloads
/// all read it and nothing else. `symbols` is a projection over those same
/// findings for a library caller that needs lexical evidence.
///
/// Deserialization checks structure only. It validates field types and enum
/// values; it does not check that a symbol finding appears in the flat profile,
/// that a symbol profile is non-empty, or that an occurrence is owned once.
/// Those are guarantees for analyses Pedant emits, enforced by the producers.
/// A structurally valid external document may state inconsistent facts, exactly
/// as an external [`CapabilityProfile`] may today.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAnalysis {
    /// Every finding the analysis produced, in detection order.
    pub profile: CapabilityProfile,
    /// Whether symbol attribution ran against a complete callable inventory.
    pub symbol_attribution: SymbolAttributionStatus,
    /// Findings grouped by owning callable, in analysis-input and declaration
    /// order. Sealed after construction, so `Box<[T]>` rather than `Vec<T>`.
    pub symbols: Box<[SymbolCapabilityProfile]>,
}

impl CapabilityAnalysis {
    /// Borrow the flat profile every persisted and policy consumer reads.
    pub fn profile(&self) -> &CapabilityProfile {
        &self.profile
    }

    /// Report whether this analysis attributed its findings to callables.
    ///
    /// See [`SymbolAttributionStatus`] for what each state claims.
    pub fn symbol_attribution(&self) -> SymbolAttributionStatus {
        self.symbol_attribution
    }

    /// Borrow the ordered symbol profiles.
    pub fn symbols(&self) -> &[SymbolCapabilityProfile] {
        &self.symbols
    }

    /// Deduplicated, sorted capability set of the flat profile.
    pub fn capabilities(&self) -> Box<[Capability]> {
        self.profile.capabilities()
    }

    /// Iterate the flat findings matching a single capability type.
    pub fn findings_for(&self, capability: Capability) -> impl Iterator<Item = &CapabilityFinding> {
        self.profile.findings_for(capability)
    }

    /// Consume the analysis and keep only its flat profile.
    ///
    /// This is the projection every current consumer of a `CapabilityAnalysis`
    /// takes, so the symbol evidence costs them no clone.
    pub fn into_profile(self) -> CapabilityProfile {
        self.profile
    }

    /// Consume two envelopes and produce one, in operand order.
    ///
    /// Flat findings from `self` precede those from `other`, and no occurrence
    /// is deduplicated. Symbol identities present in both operands coalesce
    /// into the first profile's position; every other identity appends. The
    /// status follows [`SymbolAttributionStatus::combine`].
    pub fn merge(self, other: Self) -> Self {
        Self {
            profile: append_findings(self.profile, other.profile),
            symbol_attribution: self.symbol_attribution.combine(other.symbol_attribution),
            symbols: append_symbols(self.symbols, other.symbols),
        }
    }
}

/// Concatenate two flat profiles, keeping every occurrence in operand order.
fn append_findings(first: CapabilityProfile, second: CapabilityProfile) -> CapabilityProfile {
    let mut findings = first.findings.into_vec();
    findings.extend(second.findings.into_vec());
    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

/// Concatenate two symbol lists, coalescing exact identity matches in place.
fn append_symbols(
    first: Box<[SymbolCapabilityProfile]>,
    second: Box<[SymbolCapabilityProfile]>,
) -> Box<[SymbolCapabilityProfile]> {
    let mut merged = first.into_vec();
    for entry in second.into_vec() {
        match merged.iter().position(|held| held.symbol == entry.symbol) {
            Some(index) => coalesce_into(&mut merged[index], entry.profile),
            None => merged.push(entry),
        }
    }
    merged.into_boxed_slice()
}

/// Append `addition` to a held symbol profile without moving its position.
fn coalesce_into(held: &mut SymbolCapabilityProfile, addition: CapabilityProfile) {
    let existing = mem::take(&mut held.profile);
    held.profile = append_findings(existing, addition);
}
