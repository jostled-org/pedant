//! Whether one more record still fits under a configured ceiling.
//!
//! Every table this crate grows counts its records in `usize` and states its
//! ceiling as a configured `u32`, so the two have to be reconciled before the
//! comparison. One owner, because a ceiling reconciled two ways is a ceiling
//! two tables disagree about, and each caller keeps only the error variant its
//! own seam refuses through.

use super::identity::index_of;

/// Whether a table holding `held` records may still take one more.
///
/// The ceiling widens to the pointer width the table is counted in. On a target
/// where `usize` is narrower than `u32` the saturating answer is the widest
/// table that target can address, which no allocation reaches.
pub(crate) fn admits_one_more(held: usize, ceiling: u32) -> bool {
    held.saturating_add(1) <= index_of(ceiling)
}
