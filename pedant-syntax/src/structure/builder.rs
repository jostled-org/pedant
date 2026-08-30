//! Bounded retention of one source's structures.
//!
//! Every backend records through this one builder, so the depth ceiling, the
//! structure ceiling, the span, and the owner position each have one
//! implementation rather than one per grammar. Both ceilings refuse before the
//! state they would pay for exists: a depth is refused before the walk descends
//! to it, and a structure is refused before it is retained.
//!
//! A backend hands in the lines its structure covers rather than the builder
//! resolving them. Two of the three already hold the answer — a Go fact carries
//! its grammar positions and a tree-sitter node reports its own — so a line
//! table built here would be two passes over the source and two binary searches
//! per structure to restate what the caller was told by its parser. Only the
//! Rust route has to derive them, and it owns the index that does.

use std::ops::Range;

use pedant_types::{StructureKind, StructureSpan};

#[cfg(feature = "_ts_generic")]
use crate::extract::index::line_count;
use crate::language::SyntaxLanguage;
use crate::span::LineSpan;
use crate::structure::error::StructureError;
use crate::structure::fact::StructureFact;
use crate::structure::inventory::StructureInventory;
use crate::structure::limits::StructureInventoryLimits;
#[cfg(any(feature = "rust", feature = "_ts_generic"))]
use crate::structure::limits::admits_depth;

/// Accumulates one source's structures beneath both ceilings.
pub(crate) struct InventoryBuilder<'source> {
    source: &'source str,
    limits: StructureInventoryLimits,
    structures: Vec<StructureFact<'source>>,
}

impl<'source> InventoryBuilder<'source> {
    /// An empty inventory over `source`, bounded by `limits`.
    ///
    /// For a backend that does not know its structure count in advance.
    #[cfg(any(feature = "rust", feature = "_ts_generic"))]
    pub(crate) fn new(source: &'source str, limits: StructureInventoryLimits) -> Self {
        Self::with_capacity(source, limits, 0)
    }

    /// The same, sized for the `stated` structures the caller already counted.
    ///
    /// The count a caller states is what its source claims, not what this
    /// contract admits, so the ceiling clamps it here — the one place that
    /// ceiling is owned. A caller narrowed to a remaining repository budget of
    /// three otherwise reserved every slot a five-thousand-declaration source
    /// named and refused at the fourth, which is a structure paid for before it
    /// was refused.
    pub(crate) fn with_capacity(
        source: &'source str,
        limits: StructureInventoryLimits,
        stated: usize,
    ) -> Self {
        let admitted = usize::try_from(limits.max_structures_per_source()).unwrap_or(usize::MAX);
        Self {
            source,
            limits,
            structures: Vec::with_capacity(stated.min(admitted)),
        }
    }

    /// The source these structures are read from.
    ///
    /// Held here already, because sealing an inventory binds it to the text it
    /// was walked over. A walk that reads node text takes it from the one place
    /// that binding lives rather than carrying a second copy beside it.
    #[cfg(feature = "_ts_generic")]
    pub(crate) fn source(&self) -> &'source str {
        self.source
    }

    /// Admit descent to `depth`, counting the source root as zero.
    ///
    /// Called before the walk enters the level, so a refusal happens with the
    /// deeper nodes still unvisited.
    ///
    /// The comparison is [`admits_depth`], which the Go fact walk asks too; what
    /// is stated here is the refusal, because a refusal names the contract that
    /// made it. The ceiling is read once, so the value the refusal carries is
    /// the value the comparison made.
    #[cfg(any(feature = "rust", feature = "_ts_generic"))]
    pub(crate) fn admit_depth(&self, depth: usize) -> Result<(), StructureError> {
        let limit = self.limits.max_syntax_depth();
        match admits_depth(depth, limit) {
            true => Ok(()),
            false => Err(StructureError::SyntaxDepthExceeded { limit }),
        }
    }

    /// Retain one structure covering `bytes` on `lines`, returning the position
    /// that owns its children.
    ///
    /// The ceiling is checked against the inventory this call would grow, so
    /// the first structure past it is refused rather than retained and dropped.
    pub(crate) fn retain(
        &mut self,
        kind: StructureKind,
        name: Option<&'source str>,
        bytes: Range<usize>,
        lines: LineSpan,
        owner: Option<u32>,
    ) -> Result<u32, StructureError> {
        let position = self.admit_structure()?;
        let span = StructureSpan::new(bytes, line_number(lines.start), line_number(lines.end));
        self.structures
            .push(StructureFact::new(kind, name, span, owner));
        Ok(position)
    }

    /// Admit one more structure, and state the position it will hold.
    ///
    /// The sole capacity check, and the sole place a position is minted, for
    /// the same reason the depth check has one site: a second one could admit
    /// a structure this one refused. The ceiling is read once, so the value the
    /// refusal names is the value the comparison made.
    ///
    /// A count no `u32` can hold is past every ceiling this contract can state,
    /// and refusing it here keeps the position an inventory publishes a real
    /// index rather than a saturated one.
    fn admit_structure(&self) -> Result<u32, StructureError> {
        let limit = self.limits.max_structures_per_source();
        match u32::try_from(self.structures.len()) {
            Ok(retained) if retained < limit => Ok(retained),
            _ => Err(StructureError::StructureCapacityExceeded { limit }),
        }
    }

    /// Seal the completed walk into one inventory.
    pub(crate) fn seal(self, language: SyntaxLanguage) -> StructureInventory<'source> {
        StructureInventory::seal(self.source, language, self.structures.into_boxed_slice())
    }
}

/// One line as the published span states it.
///
/// The sole narrowing site for a line number in this crate. Saturating rather
/// than refusing: a source holding more than four billion lines is more than
/// four gigabytes of text, and the saturated value names the last line the model
/// can state rather than a low one an outline would show a reader.
fn line_number(line: usize) -> u32 {
    u32::try_from(line).unwrap_or(u32::MAX)
}

/// The one-based inclusive line extent between two zero-based grammar
/// positions.
///
/// Both tree-sitter and the Go fact span report a range's end as the position
/// one past its last byte, so a range whose last byte is a line terminator
/// closes at column zero of the line after it. A structure's closing line is the
/// line its last byte sits on, which is what a byte-indexed reading of the same
/// range answers and what an outline shows — so a zero column steps back one
/// line, never past the line the range opened on.
#[cfg(any(feature = "ts-go", feature = "_ts_generic"))]
pub(crate) fn lines_between(start_row: usize, end_row: usize, end_column: usize) -> LineSpan {
    let start = start_row.saturating_add(1);
    LineSpan {
        start,
        end: match end_column {
            0 => end_row.max(start),
            _ => end_row.saturating_add(1),
        },
    }
}

/// The one-based inclusive lines the whole of `source` covers.
///
/// The one structure no grammar node states: a Python or ECMAScript file is a
/// module its source declares nothing for, so its extent is the source's own
/// and no parser reports the position that closes it. A trailing newline shuts
/// the last line rather than opening a further one, which is the rule
/// [`lines_between`] applies to a range ending at column zero and the rule
/// [`line_count`] applies to the same bytes — one derivation, shared with the
/// Rust route's line index, so a file module and that index cannot count one
/// source two ways.
///
/// One scan over the text, for one structure. A line table would be the second
/// pass this walk exists to avoid, and it would be built to answer a single
/// question the other rows already carry answers for.
#[cfg(feature = "_ts_generic")]
pub(crate) fn lines_of(source: &str) -> LineSpan {
    LineSpan {
        start: 1,
        end: line_count(source),
    }
}
