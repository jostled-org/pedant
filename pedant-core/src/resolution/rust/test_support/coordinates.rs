//! The coordinate resolution one Rust site inventory is built on.
//!
//! A parsed source cannot reach the fallbacks in that resolution: `syn` numbers
//! lines from one and reports coordinates inside the text it parsed, so no
//! fixture drives them through
//! [`RustFileInventory::of_source`](super::super::RustFileInventory::of_source).
//! They still decide where an unresolvable site closes, and a branch nothing
//! states is a branch that can change meaning without anything going red.
//!
//! The adapter takes a text and a coordinate rather than the line table the
//! private functions take. The table borrows the text it indexed, and a proof
//! that built one itself could hand these functions a table over other bytes —
//! which is the one mistake the resolution is not written to survive. The
//! functions beneath now read the table's own text for the same reason, so this
//! adapter is the only place the two are ever named apart.

use pedant_types::StructureSpan;

use crate::ir::facts::IrSpan;
use crate::ir::sites::IrRange;
use crate::resolution::line_index::LineIndex;
use crate::resolution::rust::inventory::{offset_of, span_of};

/// One `syn` coordinate: a one-based line and a zero-based character column.
pub type SourceCoordinate = (usize, usize);

/// The byte offset one `syn` coordinate names in `text`.
pub fn source_offset_at(text: &str, at: SourceCoordinate) -> usize {
    offset_of(&LineIndex::new(text), spanned(at))
}

/// The byte-and-line extent one `syn` range covers in `text`.
pub fn source_span_between(
    text: &str,
    start: SourceCoordinate,
    end: SourceCoordinate,
) -> StructureSpan {
    span_of(
        &LineIndex::new(text),
        IrRange {
            start: spanned(start),
            end: spanned(end),
        },
    )
}

/// One coordinate pair as the IR spells it.
fn spanned((line, column): SourceCoordinate) -> IrSpan {
    IrSpan { line, column }
}
