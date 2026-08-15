use pedant_types::CapabilityAnalysis;

use crate::ir::{DataFlowFact, FnFingerprint};
use crate::violation::Violation;

/// Output of a single file analysis: violations and capabilities.
pub struct AnalysisResult {
    /// Style violations produced by the checks pipeline.
    pub violations: Box<[Violation]>,
    /// Capability findings from use-path and string-literal detection, plus
    /// the callables that contain them. Every persisted and policy consumer
    /// reads `capabilities.profile`; the symbol projection is for a library
    /// caller that needs lexical evidence.
    pub capabilities: CapabilityAnalysis,
    /// Cross-function data flow edges (populated only by semantic enrichment).
    /// `Arc<[T]>` shared with the semantic file analysis cache — no deep copy.
    pub data_flows: std::sync::Arc<[DataFlowFact]>,
    /// Structural fingerprints for duplicate detection (one per function).
    pub fn_fingerprints: Box<[FnFingerprint]>,
}
