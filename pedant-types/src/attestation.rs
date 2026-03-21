use serde::{Deserialize, Serialize};

use crate::CapabilityProfile;

/// The depth of analysis performed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisTier {
    /// Pattern-based detection on syntax trees.
    Syntactic,
    /// Type-aware analysis with resolved names.
    Semantic,
    /// Full data-flow tracking through the program.
    DataFlow,
}

/// The content of a capability attestation for a crate.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AttestationContent {
    /// Schema version for forward compatibility.
    pub spec_version: Box<str>,
    /// Hash of the analyzed source.
    pub source_hash: Box<str>,
    /// Name of the analyzed crate.
    pub crate_name: Box<str>,
    /// Version of the analyzed crate.
    pub crate_version: Box<str>,
    /// Depth of the analysis performed.
    pub analysis_tier: AnalysisTier,
    /// Seconds since Unix epoch (UTC).
    pub timestamp: u64,
    /// The capability profile produced by analysis.
    pub profile: CapabilityProfile,
}
