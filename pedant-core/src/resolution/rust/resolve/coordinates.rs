//! Report coordinates over one exact source text.
//!
//! `syn` reports one-based lines and zero-based character columns; a report
//! reports zero-based lines and zero-based UTF-8 byte columns. Both directions
//! need the exact snapshotted bytes, so both live beside them here: the
//! resolver converts its site ranges, and the snapshot binding validates the
//! coordinates any report claims.

use std::sync::Arc;

use pedant_types::{SourcePosition, SourceSpan};

use crate::ir::facts::IrSpan;
use crate::ir::sites::IrRange;
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

/// The byte offset each line of one source starts at.
pub(super) struct LineIndex {
    starts: Box<[usize]>,
    length: usize,
}

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

impl LineIndex {
    /// Index the lines of one exact source text.
    pub(super) fn new(text: &str) -> Self {
        let mut starts = vec![0_usize];
        starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
        Self {
            starts: starts.into_boxed_slice(),
            length: text.len(),
        }
    }

    /// The report span one site range occupies, when the range exists in this
    /// source and is not empty.
    pub(super) fn span(&self, text: &str, file: &Arc<str>, range: IrRange) -> Option<SourceSpan> {
        let start = self.position(text, range.start)?;
        let end = self.position(text, range.end)?;
        (start < end).then(|| SourceSpan::new(Arc::clone(file), start, end))
    }

    /// Prove one report coordinate exists in this source and sits on a UTF-8
    /// code-point boundary.
    pub(super) fn holds(&self, text: &str, position: SourcePosition) -> bool {
        let line = usize::try_from(position.line()).unwrap_or(usize::MAX);
        let column = usize::try_from(position.column()).unwrap_or(usize::MAX);
        self.line_bounds(line)
            .is_some_and(|(start, end)| within(text, (start, end), column))
    }

    fn position(&self, text: &str, span: IrSpan) -> Option<SourcePosition> {
        let line = span.line.checked_sub(1)?;
        let (start, end) = self.line_bounds(line)?;
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

    /// The byte offsets one zero-based line spans, its line break excluded.
    fn line_bounds(&self, line: usize) -> Option<(usize, usize)> {
        let start = self.starts.get(line).copied()?;
        let end = match self.starts.get(line + 1) {
            Some(next) => next.saturating_sub(1),
            None => self.length,
        };
        Some((start, end))
    }
}

fn within(text: &str, bounds: (usize, usize), column: usize) -> bool {
    let (start, end) = bounds;
    let offset = start.saturating_add(column);
    offset <= end && text.is_char_boundary(offset)
}
