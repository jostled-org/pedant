use serde::{Deserialize, Serialize};

/// Whether a producer classified every finding against a complete callable
/// inventory.
///
/// A `SymbolAttributionStatus` is honest about the parse behind an analysis, so
/// a caller can tell module-level evidence from a parser that never ran. Absent
/// symbols alone cannot carry that distinction, which is why no state is
/// spelled as an empty successful symbol list.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolAttributionStatus {
    /// Every finding was classified against the complete callable inventory of
    /// the applicable input.
    ///
    /// This does not claim every finding belongs to a callable: imports,
    /// attributes, literals, `unsafe` code, and foreign blocks at file or
    /// module scope stay flat evidence.
    Complete,
    /// A source analyzer emitted flat findings without a complete structural
    /// parse — a disabled grammar, a failed parse, or an error-bearing recovery
    /// tree. The flat findings remain authoritative.
    Unavailable,
    /// The input has no source-callable model at all, such as a manifest or a
    /// hook file.
    NotApplicable,
}

impl SymbolAttributionStatus {
    /// Reduce two merged operands to one status under a closed precedence.
    ///
    /// `Unavailable` dominates every combination, because one input without a
    /// complete parse means the merged envelope cannot claim complete
    /// attribution. Otherwise `Complete` dominates `NotApplicable`: a manifest
    /// operand has no callable claim to weaken.
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unavailable, _) | (_, Self::Unavailable) => Self::Unavailable,
            (Self::Complete, _) | (_, Self::Complete) => Self::Complete,
            (Self::NotApplicable, Self::NotApplicable) => Self::NotApplicable,
        }
    }
}
