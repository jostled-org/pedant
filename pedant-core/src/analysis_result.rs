use pedant_types::CapabilityProfile;

use crate::ir::{DataFlowFact, FnFingerprint};
use crate::violation::Violation;

/// Output of a single file analysis: violations and capabilities.
pub struct AnalysisResult {
    /// Style violations produced by the checks pipeline.
    pub violations: Box<[Violation]>,
    /// Capability findings from use-path and string-literal detection.
    pub capabilities: CapabilityProfile,
    /// Cross-function data flow edges (populated only by semantic enrichment).
    pub data_flows: Box<[DataFlowFact]>,
    /// Structural fingerprints for duplicate detection (one per function).
    pub fn_fingerprints: Box<[FnFingerprint]>,
}
