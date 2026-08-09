//! A half-open source range in the coordinates `syn` reports.

use crate::ir::facts::IrSpan;

/// Where a site starts and where it ends.
///
/// Both points use `syn`'s coordinates: a one-based line and a zero-based
/// character column. The report's zero-based UTF-8 byte columns are derived
/// from these by the resolver, which holds the exact source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrRange {
    /// The inclusive start point.
    pub start: IrSpan,
    /// The exclusive end point.
    pub end: IrSpan,
}
