//! The byte offset each line of one source starts at.
//!
//! A report states zero-based lines and zero-based UTF-8 byte columns, and both
//! producing one of those coordinates and proving one exists need the same
//! table over the same exact bytes. One owner, because every language's snapshot
//! binding asks the same question of its own sources.

/// Where each line of one exact source text begins.
pub(crate) struct LineIndex {
    starts: Box<[usize]>,
    length: usize,
}

impl LineIndex {
    /// Index the lines of one exact source text.
    pub(crate) fn new(text: &str) -> Self {
        let mut starts = vec![0_usize];
        starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
        Self {
            starts: starts.into_boxed_slice(),
            length: text.len(),
        }
    }

    /// Whether one zero-based line and UTF-8 byte column exists in this source
    /// and sits on a code-point boundary.
    pub(crate) fn holds(&self, text: &str, line: u32, column: u32) -> bool {
        let line = usize::try_from(line).unwrap_or(usize::MAX);
        let column = usize::try_from(column).unwrap_or(usize::MAX);
        self.line_bounds(line)
            .is_some_and(|(start, end)| within(text, (start, end), column))
    }

    /// The byte offsets one zero-based line spans, its line break excluded.
    pub(crate) fn line_bounds(&self, line: usize) -> Option<(usize, usize)> {
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
