//! One count as the fixed-width field that holds it.
//!
//! Every collection here is measured as a `usize` and then stored, claimed, or
//! compared as a dense `u32` position or a wide `u64` allowance. Both
//! conversions saturate rather than wrap or panic, and the reason is the same
//! at every call site: a count that silently became small names a record
//! nobody retained, and a panic at a ceiling is the one failure a ceiling
//! exists to prevent.
//!
//! Written once because it was written six times — a `narrowed`, a `narrow`, a
//! `saturating`, a `position`, a `count`, and three restatements inline. Six
//! copies of one rule are six chances for one of them to wrap.

/// One count as a dense position or a narrow ceiling holds it.
pub(super) fn narrowed<Wide: TryInto<u32>>(count: Wide) -> u32 {
    count.try_into().unwrap_or(u32::MAX)
}

/// One count as a wide allowance measures it.
pub(super) fn widened<Wide: TryInto<u64>>(count: Wide) -> u64 {
    count.try_into().unwrap_or(u64::MAX)
}

/// One charged allowance as the capacity that reserves it.
///
/// The way back from [`widened`]: a running total this crate already charged,
/// read as the exact reservation a collection of that many records takes. Total
/// on every supported platform — each of these totals was charged beneath a
/// `u32` ceiling, and a `usize` is never narrower than that — and saturating
/// for the same reason the other two are.
pub(super) fn sized<Wide: TryInto<usize>>(count: Wide) -> usize {
    count.try_into().unwrap_or(usize::MAX)
}
