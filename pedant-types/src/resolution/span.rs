//! Where a definition or reference sits in the snapshotted source.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A zero-based point in one source file.
///
/// A column counts UTF-8 bytes from the first byte after the preceding `\n`, so
/// a `\r` in a CRLF pair is an ordinary byte. Both coordinates are `u32` so a
/// serialized report reads the same on every platform.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct SourcePosition {
    line: u32,
    column: u32,
}

impl SourcePosition {
    /// A point at a zero-based line and UTF-8 byte column.
    pub fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }

    /// The zero-based line.
    pub fn line(self) -> u32 {
        self.line
    }

    /// The zero-based UTF-8 byte column.
    pub fn column(self) -> u32 {
        self.column
    }
}

/// A half-open range in one normalized repository-relative file.
///
/// The derived ordering is the report's structural sort key for sites: file,
/// then start, then end.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan {
    file: Arc<str>,
    start: SourcePosition,
    end: SourcePosition,
}

impl SourceSpan {
    /// A span over `file`, from `start` up to but excluding `end`.
    ///
    /// The path is validated when the report is constructed, so one file value
    /// shared by many sites is checked once per site rather than at every clone.
    pub fn new(file: Arc<str>, start: SourcePosition, end: SourcePosition) -> Self {
        Self { file, start, end }
    }

    /// The normalized repository-relative path.
    pub fn file(&self) -> &str {
        &self.file
    }

    /// The shared path value itself, for a decoder pointing many spans at one.
    pub(super) fn shared_file(&self) -> &Arc<str> {
        &self.file
    }

    /// Adopt an equal path value that other spans already share.
    ///
    /// Serde allocates one path per span on the way in, which is the opposite
    /// of what this type is for, so the decoder replaces each with the one
    /// canonical value before the report exists.
    pub(super) fn adopt_file(&mut self, file: Arc<str>) {
        self.file = file;
    }

    /// The inclusive start point.
    pub fn start(&self) -> SourcePosition {
        self.start
    }

    /// The exclusive end point.
    pub fn end(&self) -> SourcePosition {
        self.end
    }
}
