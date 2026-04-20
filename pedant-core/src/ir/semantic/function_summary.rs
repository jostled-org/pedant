//! Per-function analysis summaries.
//!
//! `FunctionSummaryData` stores range indices into the file-level
//! `data_flows` array plus lock acquisitions derived once from `FnContext`.
//! `FunctionAnalysisSummary` is the borrowed public view that resolves
//! ranges against the shared flow slice.

use super::super::facts::DataFlowFact;
use super::common::LockAcquisition;

/// Half-open range into the file-level `data_flows` slice.
///
/// Stored as `u32` pair — a single file will never produce 4 billion
/// flow facts. Eliminates per-function `Box<[DataFlowFact]>` ownership;
/// all facts live once in the file-level `Arc<[DataFlowFact]>`.
#[derive(Clone, Copy)]
pub(super) struct FlowRange {
    start: u32,
    end: u32,
}

impl FlowRange {
    /// Record a range from the current aggregate length before and after
    /// appending a batch of facts.
    pub(super) fn new(start: usize, end: usize) -> Self {
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    /// Slice the shared flow array to this function's domain partition.
    pub(super) fn slice<'a>(&self, flows: &'a [DataFlowFact]) -> &'a [DataFlowFact] {
        &flows[self.start as usize..self.end as usize]
    }
}

/// Owned per-function cached semantic state.
///
/// Stores domain-partitioned flow ranges (indices into the file-level
/// `data_flows`) and lock acquisitions. Everything is immutable after
/// construction and borrowed through `FunctionAnalysisSummary`.
pub(super) struct FunctionSummaryData {
    pub(super) lock_acquisitions: Box<[LockAcquisition]>,
    pub(super) taint: FlowRange,
    pub(super) quality: FlowRange,
    pub(super) performance: FlowRange,
    pub(super) concurrency: FlowRange,
}

/// Borrowed view into one function's precomputed analysis state.
///
/// Resolves `FlowRange` indices against the file-level `data_flows`
/// slice. Never owns data.
pub struct FunctionAnalysisSummary<'a> {
    data: &'a FunctionSummaryData,
    flows: &'a [DataFlowFact],
}

impl<'a> FunctionAnalysisSummary<'a> {
    /// Create a summary view from stored function data and the shared flow slice.
    pub(super) fn new(data: &'a FunctionSummaryData, flows: &'a [DataFlowFact]) -> Self {
        Self { data, flows }
    }

    /// Quality findings: dead stores, discarded results, partial error
    /// handling, swallowed `.ok()`, immutable growable bindings.
    pub fn quality_issues(&self) -> &[DataFlowFact] {
        self.data.quality.slice(self.flows)
    }

    /// Performance findings: repeated calls, unnecessary clones,
    /// allocations in loops, redundant collects.
    pub fn performance_issues(&self) -> &[DataFlowFact] {
        self.data.performance.slice(self.flows)
    }

    /// Concurrency findings: lock guards across `.await`, inconsistent
    /// lock ordering, unobserved spawn calls.
    pub fn concurrency_issues(&self) -> &[DataFlowFact] {
        self.data.concurrency.slice(self.flows)
    }

    /// Taint flow findings: capability source → sink propagation.
    pub fn taint_flows(&self) -> &[DataFlowFact] {
        self.data.taint.slice(self.flows)
    }
}
