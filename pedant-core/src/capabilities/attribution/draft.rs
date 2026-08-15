//! One capability finding paired with the callable that contains it, before
//! the analysis envelope is assembled.
//!
//! A draft is the only place a finding is mutable. Semantic reachability
//! enriches it between detection and projection, so the projection seals both
//! the flat profile and the symbol profiles from settled values.

use pedant_types::CapabilityFinding;

/// One drafted finding and the callable index it belongs to.
pub(crate) struct DraftedFinding {
    /// The finding exactly as it will appear in the flat profile.
    pub(crate) finding: CapabilityFinding,
    /// Index into `FileIr::functions`, or `None` for module-scope evidence.
    pub(crate) containing_fn: Option<usize>,
}

/// Every drafted finding of one analysis, in detection order.
#[derive(Default)]
pub(crate) struct CapabilityDraft {
    entries: Vec<DraftedFinding>,
}

impl CapabilityDraft {
    /// Append one finding under the callable owner its source fact stated.
    pub(crate) fn push(&mut self, finding: CapabilityFinding, containing_fn: Option<usize>) {
        self.entries.push(DraftedFinding {
            finding,
            containing_fn,
        });
    }

    /// The drafted findings, for a pass that annotates them before projection.
    ///
    /// Semantic reachability is that pass, and it runs inside the lint
    /// pipeline, so no other configuration hands the draft out mutably.
    #[cfg(all(feature = "checks", feature = "semantic"))]
    pub(crate) fn entries_mut(&mut self) -> &mut [DraftedFinding] {
        &mut self.entries
    }

    /// Consume the draft, yielding its findings in detection order.
    pub(crate) fn into_entries(self) -> Vec<DraftedFinding> {
        self.entries
    }
}
