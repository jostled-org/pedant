//! What one site names, decided before the span it was written at is read.
//!
//! Every classification reaches one of three shapes: definitions a lookup
//! found, nothing with the gap that stopped it, or a run-time choice among the
//! definitions a dispatch could reach. Naming them here keeps a classifier from
//! assembling a certainty of its own.

use pedant_types::{ReferenceKind, ResolutionGap};

/// What one site denotes, before it is written into a report record.
pub(super) struct Answer {
    pub(super) kind: ReferenceKind,
    pub(super) candidates: Box<[usize]>,
    pub(super) gap: Option<ResolutionGap>,
    pub(super) possible_only: bool,
}

impl Answer {
    /// One answer naming the definitions a lookup found.
    pub(super) fn found(
        kind: ReferenceKind,
        candidates: Box<[usize]>,
        gap: Option<ResolutionGap>,
    ) -> Self {
        Self {
            kind,
            candidates,
            gap,
            possible_only: false,
        }
    }

    /// One site that names nothing, and the gap that says why.
    pub(super) fn refused(kind: ReferenceKind, gap: ResolutionGap) -> Self {
        Self::found(kind, Box::from([]), Some(gap))
    }

    /// One answer whose target is chosen at run time.
    pub(super) fn dispatched(kind: ReferenceKind, candidates: Box<[usize]>) -> Self {
        Self {
            kind,
            candidates,
            gap: Some(ResolutionGap::DynamicDispatch),
            possible_only: true,
        }
    }
}
