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
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

/// One line index per snapshot source, in the store's own order.
///
/// A source is instantiated once per module scope and read by three passes, so
/// indexing per instance rescanned the same bytes many times over to produce a
/// table that depends on the text alone.
pub(super) fn index_sources(snapshot: &RustResolutionSnapshot) -> Box<[LineIndex]> {
    snapshot
        .sources()
        .iter()
        .map(|source| LineIndex::new(source.text()))
        .collect()
}

/// The report span one site range occupies, when the range exists in this
/// source and is not empty.
pub(super) fn span(
    index: &LineIndex,
    text: &str,
    file: &Arc<str>,
    range: IrRange,
) -> Option<SourceSpan> {
    let start = position(index, text, range.start)?;
    let end = position(index, text, range.end)?;
    (start < end).then(|| SourceSpan::new(Arc::clone(file), start, end))
}

fn position(index: &LineIndex, text: &str, span: IrSpan) -> Option<SourcePosition> {
    let line = span.line.checked_sub(1)?;
    let (start, end) = index.line_bounds(line)?;
    let content = text.get(start..end)?;
    let column = content
        .char_indices()
        .nth(span.column)
        .map_or(content.len(), |(offset, _)| offset);
    Some(SourcePosition::new(
        u32::try_from(line).ok()?,
        u32::try_from(column).ok()?,
    ))
}
