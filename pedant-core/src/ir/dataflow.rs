//! Data-flow findings: taint edges, quality issues, and concurrency hazards.
//!
//! Only semantic enrichment populates these; every other path leaves the slice
//! empty.

use std::fmt;

use pedant_types::Capability;

use super::facts::IrSpan;

/// Discriminant for data flow findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataFlowKind {
    /// Tainted data flows from a capability source to a capability sink.
    TaintFlow,
    /// Value assigned then overwritten before read.
    DeadStore,
    /// Function returning Result called without binding the return.
    DiscardedResult,
    /// Result handled on some paths, dropped on others.
    PartialErrorHandling,
    /// Same function called with identical arguments within a single scope.
    RepeatedCall,
    /// `.clone()` called but the original is never used afterward.
    UnnecessaryClone,
    /// `Vec::new()`, `String::new()`, or `format!()` inside a loop body.
    AllocationInLoop,
    /// `.collect()` followed immediately by `.iter()` or `.into_iter()`.
    RedundantCollect,
    /// Lock guard held across an `.await` point (potential deadlock or task starvation).
    LockAcrossAwait,
    /// Same locks acquired in different orders across functions (potential deadlock).
    InconsistentLockOrder,
    /// Vec or String binding never mutated after construction.
    ImmutableGrowable,
    /// `.ok()` called on Result where the resulting Option is discarded.
    SwallowedOk,
    /// Thread or task spawned with the JoinHandle dropped or unbound.
    UnobservedSpawn,
}

impl DataFlowKind {
    /// Kebab-case identifier for this data flow kind.
    pub fn code(self) -> &'static str {
        match self {
            Self::TaintFlow => "taint-flow",
            Self::DeadStore => "dead-store",
            Self::DiscardedResult => "discarded-result",
            Self::PartialErrorHandling => "partial-error-handling",
            Self::RepeatedCall => "repeated-call",
            Self::UnnecessaryClone => "unnecessary-clone",
            Self::AllocationInLoop => "allocation-in-loop",
            Self::RedundantCollect => "redundant-collect",
            Self::LockAcrossAwait => "lock-across-await",
            Self::InconsistentLockOrder => "inconsistent-lock-order",
            Self::ImmutableGrowable => "immutable-growable",
            Self::SwallowedOk => "swallowed-ok",
            Self::UnobservedSpawn => "unobserved-spawn",
        }
    }
}

impl fmt::Display for DataFlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Data flow finding: taint edge, quality issue, or concurrency hazard.
#[derive(Debug, Clone)]
pub struct DataFlowFact {
    /// What kind of data flow issue this represents.
    pub kind: DataFlowKind,
    /// Where the tainted data originates (taint flows only).
    pub source_capability: Option<Capability>,
    /// Location of the source expression.
    pub source_span: IrSpan,
    /// Where the tainted data is consumed (taint flows only).
    pub sink_capability: Option<Capability>,
    /// Location of the sink expression.
    pub sink_span: IrSpan,
    /// Intermediate function names the data passes through.
    pub call_chain: Box<[Box<str>]>,
    /// Human-readable description of the finding.
    pub message: Box<str>,
}
