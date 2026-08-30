//! Naming one byte of one retained source in the coordinates a report uses.
//!
//! A resolution report states a zero-based line and a zero-based byte column; a
//! structure span states a byte offset. This is the one conversion between them
//! in this crate, and it runs over the exact text the index retained, which is
//! the text every language owner measured its own spans against.

use pedant_types::SourcePosition;

use super::count::{narrowed, widened};

/// The line starts of one retained source.
pub(super) struct LineTable {
    starts: Box<[u64]>,
}

impl LineTable {
    /// The table one retained source states.
    ///
    /// Counted first, then filled. `match_indices` supplies no length, so a
    /// table grown from it doubles its way to the answer and the boxing at the
    /// end then reallocates and copies the whole thing. One extra pass over the
    /// bytes buys the exact capacity and one allocation.
    pub(super) fn of(text: &str) -> Self {
        let lines = text.bytes().filter(|byte| *byte == b'\n').count();
        let mut starts: Vec<u64> = Vec::with_capacity(lines.saturating_add(1));
        starts.push(0);
        starts.extend(
            text.match_indices('\n')
                .map(|(at, _)| widened(at.saturating_add(1))),
        );
        Self {
            starts: starts.into_boxed_slice(),
        }
    }

    /// The zero-based line and byte column one offset sits at.
    ///
    /// The line is a position the constructor guarantees: the table always
    /// holds a start for offset zero, so `partition_point` returns at least
    /// one and the index it names is always inside the table. A miss would be a
    /// broken table reporting column zero of line zero for every byte, which is
    /// a wrong coordinate rather than an absent one. Production source here
    /// states no assertion, so the constructor above is what holds the
    /// invariant, and nothing at this call can tell a broken table from a
    /// correct one.
    pub(super) fn at(&self, offset: u64) -> SourcePosition {
        let line = self
            .starts
            .partition_point(|start| *start <= offset)
            .saturating_sub(1);
        let start = self.starts.get(line).copied().unwrap_or_default();
        SourcePosition::new(narrowed(line), narrowed(offset.saturating_sub(start)))
    }
}
