//! Everything one Rust source states, extracted exactly once.
//!
//! This is the Rust language owner's answer to "what does this file declare?",
//! and it is the only route to that answer a provider has. A provider reads and
//! decodes; it does not parse, and it does not recognize a declaration. Keeping
//! the parse here is what lets several project slices share one source without
//! any of them owning a second Rust recognizer that could drift from this one.
//!
//! The measured nesting depth travels with the inventory because a snapshot
//! that reuses a shared record still owes its own depth ceiling an answer, and
//! re-lexing the text per slice would pay for a number this walk already knew.

use pedant_types::{StructureRecord, StructureSpan};

use crate::ir::FileIr;
use crate::ir::extract::{self, ParseCompatibility};
use crate::ir::facts::IrSpan;
use crate::ir::sites::{IrRange, StructureSite};
use crate::resolution::line_index::LineIndex;

use super::depth::syntax_depth;
use super::fault::RustSourceFault;
use super::limits::admits_depth;

/// One parsed Rust source: its facts, the depth it reached, and the editions
/// its tree is valid under.
#[derive(Debug)]
pub struct RustFileInventory {
    ir: FileIr,
    structures: Box<[StructureRecord]>,
    definitions: Box<[Option<StructureSpan>]>,
    syntax_depth: u32,
    compatibility: ParseCompatibility,
}

impl RustFileInventory {
    /// Bound, parse, and walk one Rust source.
    ///
    /// The depth ceiling is checked against the lexed text before the recursive
    /// parse runs, because the parse is what the ceiling exists to keep
    /// bounded; text that does not even lex is the invalid Rust it is.
    ///
    /// The parse admits the pre-2021 spelling of callable trait objects and
    /// records that it had to. Which editions may then *use* the tree is the
    /// asking snapshot's question, not the provider's: one physical source can
    /// be reached from packages on different editions, and refusing it at the
    /// first read would make the answer depend on which package asked first.
    pub fn of_source(
        path: &str,
        text: &str,
        max_syntax_depth: u32,
    ) -> Result<Self, RustSourceFault> {
        let depth = syntax_depth(text).map_err(|error| unparsed(&error))?;
        within_depth(depth, max_syntax_depth)?;
        let parsed = extract::parse_source_for_edition(path, text, true)
            .map_err(|error| unparsed(&error))?;
        let ir = extract::extract(path, &parsed.file, None);
        let (structures, definitions) = retained_structures(&ir, text);
        Ok(Self {
            structures,
            definitions,
            ir,
            syntax_depth: depth,
            compatibility: parsed.compatibility,
        })
    }

    /// The one-pass IR this source states.
    pub fn ir(&self) -> &FileIr {
        &self.ir
    }

    /// Every logical structure this source declares, in source order.
    ///
    /// The same sites the IR above records, with their `syn` line-and-character
    /// coordinates resolved against the exact text this parse read. Resolving
    /// them here is what keeps the byte extents byte-exact: the coordinates
    /// only mean something beside the string they were measured on, and this is
    /// the one place that string and those sites are both in hand.
    pub fn structures(&self) -> &[StructureRecord] {
        &self.structures
    }

    /// Where the declared name of the structure at `position` sits, absent for
    /// a declaration that states no definition.
    ///
    /// This is the Rust half of the graph join, stated by the owner that made
    /// both halves. A report points a graph node at the extent of a *name*; an
    /// outline states the extent of a whole *declaration*; and the two are
    /// linked by the definition-site ordinal this visitor already recorded.
    /// Answering here is what keeps a consumer from comparing a declaration
    /// extent with an identifier extent, which is a join two `impl` blocks over
    /// one type would satisfy.
    ///
    /// An `impl` block declares no name, so it answers `None`, and so does a
    /// position this source states no structure at.
    pub fn definition_span(&self, position: usize) -> Option<StructureSpan> {
        self.definitions.get(position).copied().flatten()
    }

    /// The deepest delimiter nesting the source text reached.
    pub fn syntax_depth(&self) -> u32 {
        self.syntax_depth
    }

    /// The strict-edition parse error this source only avoids under an edition
    /// that still spells callable trait objects without `dyn`.
    ///
    /// Absent when every edition parses the source as written.
    pub fn legacy_callable_trait_error(&self) -> Option<&str> {
        match &self.compatibility {
            ParseCompatibility::AllEditions => None,
            ParseCompatibility::LegacyCallableTraits { strict_error } => Some(strict_error),
        }
    }
}

/// The lexed nesting depth this parse may run beneath.
///
/// The comparison belongs to the one owner of it, so a provider and the
/// snapshot store that re-measures its record cannot disagree about which
/// depths a ceiling of `n` admits; what stays here is only the refusal this
/// language publishes.
fn within_depth(depth: u32, ceiling: u32) -> Result<(), RustSourceFault> {
    match admits_depth(depth, ceiling) {
        true => Ok(()),
        false => Err(RustSourceFault::SyntaxDepth {
            ceiling: ceiling.into(),
        }),
    }
}

/// Retain every structure site the IR recorded, byte-resolved against `text`,
/// beside the extent of the definition each one names.
///
/// One record per site and in the same order, because a site's owner is a
/// position in that list: dropping a site whose coordinate would not resolve
/// would silently re-point every owner after it. An unresolvable coordinate
/// therefore closes at the end of the source instead, which is the widest
/// extent the text can state and the one a containment test refuses first.
///
/// Both extents come out of one line table over one string. The declaration
/// extent is what an outline shows; the definition extent is where the report
/// points a graph node, and resolving the pair together is what lets a consumer
/// join the two without measuring either itself.
///
/// One pass over the sites, because the two lists are one list read twice: a
/// site's record and its definition extent both come out of the single
/// definition the site names, and building them apart searched the definition
/// table once per list for every declaration in the file.
fn retained_structures(
    ir: &FileIr,
    text: &str,
) -> (Box<[StructureRecord]>, Box<[Option<StructureSpan>]>) {
    let index = LineIndex::new(text);
    let (structures, definitions): (Vec<StructureRecord>, Vec<Option<StructureSpan>>) = ir
        .structure_sites
        .iter()
        .map(|site| retained_structure(ir, site, &index))
        .unzip();
    (
        structures.into_boxed_slice(),
        definitions.into_boxed_slice(),
    )
}

/// One site's record beside the extent of the definition it names.
///
/// The site keeps no name of its own: it and its definition are recorded by one
/// call, so the definition it states is the single copy both the declared name
/// and the definition extent are read from. An `impl` block states no
/// definition and therefore neither, which is what an absent name in the record
/// already means.
fn retained_structure(
    ir: &FileIr,
    site: &StructureSite,
    index: &LineIndex<'_>,
) -> (StructureRecord, Option<StructureSpan>) {
    let named = site
        .definition
        .and_then(|definition| ir.definition_sites.get(definition.index()));
    let record = StructureRecord::new(
        site.kind,
        named.map(|named| Box::from(&*named.name)),
        span_of(index, site.range),
        site.parent
            .and_then(|owner| u32::try_from(owner.index()).ok()),
    );
    (record, named.map(|named| span_of(index, named.range)))
}

/// The byte-and-line extent one site range covers in the text `index` was built
/// over.
///
/// The text is the table's, not a second argument beside it. A table and a text
/// that arrive separately can arrive mismatched, which is the one mistake the
/// borrow inside [`LineIndex`] exists to prevent, and both of these are reached
/// from a proof that could hand the two apart.
///
/// Visible to this language owner's proof adapter rather than to the crate: the
/// fallbacks below decide where an unresolvable site closes, and no parsed
/// source can drive them, so the one layer that can hold them to their contract
/// reaches them through `test_support`, which only the proof feature compiles.
pub(super) fn span_of(index: &LineIndex<'_>, range: IrRange) -> StructureSpan {
    let start = offset_of(index, range.start);
    let end = offset_of(index, range.end).max(start);
    StructureSpan::new(
        start..end,
        line_number(range.start.line),
        line_number(range.end.line),
    )
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

/// The byte offset one `syn` coordinate names, saturating where it names none.
///
/// The lookup itself belongs to [`LineIndex::char_offset`], which holds the
/// table and the exact text together; what this adds is the saturation an
/// inventory needs and the report coordinates deliberately do not.
///
/// Every fallback closes at the widest extent the text can state, and none of
/// them is reachable from a parsed source: `syn` numbers lines from one and
/// reports coordinates inside the text it parsed. They exist because a site
/// whose coordinate did not resolve must still take a position — dropping it
/// would re-point every owner recorded after it. Same visibility, and for the
/// same reason, as [`span_of`].
pub(super) fn offset_of(index: &LineIndex<'_>, at: IrSpan) -> usize {
    let Some(line) = at.line.checked_sub(1) else {
        return 0;
    };
    index
        .char_offset(line, at.column)
        .unwrap_or_else(|| index.source().len())
}

/// The parser's own reason, as the fault a provider refuses through.
fn unparsed<E: std::fmt::Display>(error: &E) -> RustSourceFault {
    RustSourceFault::Unparsed {
        reason: error.to_string().into_boxed_str(),
    }
}
