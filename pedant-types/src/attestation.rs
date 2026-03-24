use serde::{Deserialize, Serialize};

use crate::CapabilityProfile;

/// How deeply the source was analyzed, affecting finding accuracy.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisTier {
    /// Pattern-based detection on unresolved syntax trees.
    Syntactic,
    /// Type-resolved analysis via rust-analyzer.
    Semantic,
    /// Full inter-procedural data-flow tracking.
    DataFlow,
}

/// Signed attestation binding a source hash to its capability profile.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AttestationContent {
    /// Schema version for forward compatibility (e.g., `"0.1.0"`).
    pub spec_version: Box<str>,
    /// SHA-256 digest of the concatenated source files.
    pub source_hash: Box<str>,
    /// Crate name from `Cargo.toml`.
    pub crate_name: Box<str>,
    /// Crate version from `Cargo.toml`.
    pub crate_version: Box<str>,
    /// How deeply the source was analyzed.
    pub analysis_tier: AnalysisTier,
    /// UTC seconds since Unix epoch.
    pub timestamp: u64,
    /// Capability findings from the analysis.
    pub profile: CapabilityProfile,
}
