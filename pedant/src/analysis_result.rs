use pedant_types::CapabilityProfile;

use crate::violation::Violation;

/// Combined result of violation analysis and capability detection.
pub struct AnalysisResult {
    /// Violations found by the nesting/pattern visitor.
    pub violations: Vec<Violation>,
    /// Capability profile from path-based detection.
    pub capabilities: CapabilityProfile,
}
