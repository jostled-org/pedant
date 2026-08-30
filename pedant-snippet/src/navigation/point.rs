//! One structure by handle, and one structure by point.
//!
//! Both answer with the same record and the same bytes, because both take the
//! same route: find the retained structure, describe it, and slice the retained
//! source at its span. Neither reopens the file — the text the span slices is
//! the text the index read, which is what makes the two answers identical for
//! the same structure however a caller named it.

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeIntelligenceState, CodeStructure, FileRecord,
    StructureHandle,
};

use super::describe::Describer;
use super::record::StructureSource;
use super::response::NavigationResponse;

/// Answer [`CodeIntelligenceState::read_structure`].
pub(crate) fn structure_by_handle(
    state: &CodeIntelligenceState,
    handle: StructureHandle,
) -> Result<NavigationResponse<StructureSource>, CodeIntelligenceError> {
    let index = state.index();
    let structure = index.structure(handle)?;
    let record = index.file(structure.path())?;
    Ok(NavigationResponse::whole(
        state,
        read(index, record, structure)?,
    ))
}

/// Answer [`CodeIntelligenceState::structure_at`].
pub(crate) fn structure_at_point(
    state: &CodeIntelligenceState,
    path: &str,
    line: u32,
    column: Option<u32>,
) -> Result<NavigationResponse<StructureSource>, CodeIntelligenceError> {
    let index = state.index();
    let record = index.file(path)?;
    let column = column.unwrap_or(1);
    let point = offset_of(record.text(), line, column).ok_or_else(|| {
        CodeIntelligenceError::UnknownPoint {
            path: Box::from(record.path()),
            line,
            column,
        }
    })?;
    let structure = narrowest(index.file_structures(record), point).ok_or_else(|| {
        CodeIntelligenceError::UnenclosedPoint {
            path: Box::from(record.path()),
            line,
            column,
        }
    })?;
    Ok(NavigationResponse::whole(
        state,
        read(index, record, structure)?,
    ))
}

/// One structure, described and read at its span.
///
/// # Errors
///
/// That the retained span does not slice the retained text. Both were taken
/// from one read of one file, so a span that misses it is a broken inventory
/// rather than an empty declaration — and an empty [`StructureSource`] would
/// render that break as a real answer, under an accessor that promises the
/// source its span covers byte for byte.
fn read(
    index: &CodeIntelligenceIndex,
    record: &FileRecord,
    structure: &CodeStructure,
) -> Result<StructureSource, CodeIntelligenceError> {
    let text = record
        .text()
        .get(structure.span().byte_range())
        .ok_or_else(|| CodeIntelligenceError::BrokenSpan {
            path: Box::from(record.path()),
        })?;
    Ok(StructureSource::stated(
        Describer::new(index).describe(structure),
        Box::from(text),
    ))
}

/// The narrowest of the structures whose extent covers `point`.
///
/// Narrowest by extent rather than by owner depth: the two agree on a forest of
/// strictly containing spans, and comparing extents needs no walk.
fn narrowest(structures: &[CodeStructure], point: usize) -> Option<&CodeStructure> {
    structures
        .iter()
        .filter(|structure| structure.span().byte_range().contains(&point))
        .min_by_key(|structure| {
            structure
                .span()
                .end_byte()
                .saturating_sub(structure.span().start_byte())
        })
}

/// The byte offset one one-based line and byte column names in `text`.
///
/// Absent when the file states no such position: a line past its last, a column
/// of zero, a column past the line's own bytes, or the offset one past the last
/// byte of the file. A line's own bytes stop before its terminator, so the last
/// addressable column on a line is the newline that ends it.
fn offset_of(text: &str, line: u32, column: u32) -> Option<usize> {
    if line == 0 || column == 0 {
        return None;
    }
    let mut start = 0_usize;
    let mut lines = text.split_inclusive('\n');
    for _ in 1..line {
        start += lines.next()?.len();
    }
    let content = lines.next()?;
    let addressable = content.strip_suffix('\n').unwrap_or(content).len();
    // The column is admitted before it is added, not after: a caller may state
    // any `u32`, and one near the maximum overflows the very addition whose
    // result the guard would then be reading.
    match column as usize <= addressable + 1 {
        true => Some(start + column as usize - 1).filter(|offset| *offset < text.len()),
        false => None,
    }
}
