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

/// How complete capability extraction was for a hashed source set.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct AnalysisCompleteness {
    /// Number of reachable files whose capabilities were analyzed successfully.
    pub analyzed_files: usize,
    /// Number of reachable files that were hashed but skipped for capability analysis.
    pub skipped_files: usize,
    /// Relative paths of hashed files that could not be analyzed.
    #[serde(default, skip_serializing_if = "<[Box<str>]>::is_empty")]
    pub skipped_paths: Box<[Box<str>]>,
}

impl AnalysisCompleteness {
    /// Returns true when capability extraction succeeded for all hashed files.
    pub fn is_complete(&self) -> bool {
        self.skipped_files == 0
    }
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
    /// Whether capability analysis covered all hashed files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_completeness: Option<AnalysisCompleteness>,
    /// Capability findings from the analysis.
    pub profile: CapabilityProfile,
}
