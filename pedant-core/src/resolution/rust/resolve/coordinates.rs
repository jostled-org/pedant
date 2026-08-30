//! Report coordinates over one exact Rust source text.
//!
//! `syn` reports one-based lines and zero-based character columns; a report
//! reports zero-based lines and zero-based UTF-8 byte columns. Converting
//! between them needs the exact snapshotted bytes and the line table over them,
//! so the conversion lives beside the snapshot while the table itself is the
//! shared one every language's binding reads.

use std::sync::Arc;

use pedant_types::{SourcePosition, SourceSpan};

use crate::ir::facts::IrSpan;
use crate::ir::sites::IrRange;
use crate::resolution::line_index::LineIndex;

/// The report span one site range occupies, when the range exists in this
/// source and is not empty.
pub(super) fn span(index: &LineIndex<'_>, file: &Arc<str>, range: IrRange) -> Option<SourceSpan> {
    let start = position(index, range.start)?;
    let end = position(index, range.end)?;
    (start < end).then(|| SourceSpan::new(Arc::clone(file), start, end))
}

/// One `syn` coordinate as a report position, absent where the source states
/// no such coordinate.
///
/// The character-to-byte lookup belongs to the table; what stays here is the
/// one-based-to-zero-based line shift and the narrowing a report's fields need.
/// A coordinate the source does not hold is absence, because a report that
/// pointed at the widest extent instead would state a span nothing declares.
fn position(index: &LineIndex<'_>, span: IrSpan) -> Option<SourcePosition> {
    let line = span.line.checked_sub(1)?;
    let column = index.char_column(line, span.column)?;
    Some(SourcePosition::new(
        u32::try_from(line).ok()?,
        u32::try_from(column).ok()?,
    ))
}
