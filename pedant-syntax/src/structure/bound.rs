//! The inventory one already-parsed tree states.
//!
//! Parses nothing. Which backend answers is decided here rather than inside a
//! walk, because Go is routed to its fact inventory before any tree walk
//! begins and Rust reaches no grammar at all: both would otherwise fall into
//! the shared recognizer, which names none of their nodes, and answer with an
//! empty inventory that claims the source declares nothing.

use crate::language::SyntaxLanguage;
use crate::structure::error::StructureError;
use crate::structure::inventory::StructureInventory;
use crate::structure::limits::StructureInventoryLimits;
use crate::tree_sitter::Node;

/// Every structure the tree beneath `root` states.
///
/// `source` must be the exact string that tree was parsed from, and
/// `has_errors` its recovery answer, read from the one owner of that question
/// rather than asked again here.
pub(crate) fn inventory<'source>(
    root: Node<'_>,
    source: &'source str,
    language: SyntaxLanguage,
    has_errors: bool,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    match language {
        SyntaxLanguage::Go => go(root, source, has_errors, limits),
        // No grammar produces a Rust tree, so a session can never be bound to
        // one. Named rather than left to the shared recognizer, which states no
        // Rust node and would answer that a Rust source declares nothing.
        SyntaxLanguage::Rust => Err(StructureError::BackendUnavailable { language }),
        #[cfg(feature = "_ts_generic")]
        other => generic(root, source, other, has_errors, limits),
        #[cfg(not(feature = "_ts_generic"))]
        other => Err(StructureError::BackendUnavailable { language: other }),
    }
}

/// The Go projection, taken from the one Go grammar inventory.
///
/// A recovery tree refuses before the walk, the rule [`generic`] states and for
/// the same reason: the projection refuses one too, so walking first spent a
/// whole-tree fact extraction on facts the next line threw away — one discarded
/// walk per broken file for an indexer reading a repository. Refusing here also
/// makes Go agree with the other grammars about which refusal a source that is
/// both recovered and over-deep gets.
///
/// The fact walk runs beneath the same depth ceiling the structure walk would
/// and beneath the fact ceiling [`fact_ceiling`] states. The structure ceiling
/// is applied by the projection itself, after the facts exist.
///
/// The walk retains what the projection reads and nothing else. An import, a
/// reference, a binding, and a signature term are all charged against the fact
/// ceiling above, and the projection reads none of them, so the whole-inventory
/// walk spent this route's own ceiling on facts it then dropped.
#[cfg(feature = "ts-go")]
fn go<'source>(
    root: Node<'_>,
    source: &'source str,
    has_errors: bool,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    if has_errors {
        return Err(StructureError::Recovered {
            language: SyntaxLanguage::Go,
        });
    }
    let facts = crate::go::structure_facts(
        root,
        source,
        has_errors,
        crate::go::GoFactLimits::new(limits.max_syntax_depth(), fact_ceiling(source)),
    )
    .map_err(depth_or_carried)?;
    crate::structure::go::inventory(&facts, limits)
}

/// The fact ceiling one Go source states for itself.
///
/// The owner's structure ceiling is not it. A fact is not a structure — the
/// inventory also holds imports, references, scopes, and bindings — so charging
/// structures against it would refuse sources the structure ceiling admits, and
/// the Go row of the closed table would then be the one row a caller could not
/// take at the ceiling its own inventory needs.
///
/// The source, plus the one fact the walk opens with, is what can be projected.
/// Every fact the walk retains at a node is anchored in the tree these bytes
/// were parsed from, and a node the walk names covers at least one byte, so a
/// source of `n` bytes states no more than `n` of them. The file scope is the
/// exception: the walk opens it before it reads a node, so it is anchored at no
/// byte and a ceiling of `n` alone refused the empty source — whose complete
/// inventory is empty — at its very first fact. That bounds retention to the
/// input the caller already handed in, and it refuses nothing a complete walk
/// of this source would state.
#[cfg(feature = "ts-go")]
fn fact_ceiling(source: &str) -> u32 {
    // A source no `u32` can measure states no ceiling this contract can hold,
    // so it is handed the floor rather than the largest ceiling the type can
    // carry: the walk retains the file scope it opens with and refuses at its
    // second fact, which is the first one the source itself states. Saturating
    // instead would hand the least measurable source the most generous ceiling.
    u32::try_from(source.len()).unwrap_or(0).saturating_add(1)
}

/// The refusal one Go fact walk states, in this contract's own terms.
///
/// The depth ceiling handed to that walk is this contract's own, so its depth
/// refusal is this contract's depth refusal rather than a second spelling of
/// it. Every other Go refusal is carried whole, because it is an answer about
/// Go that nothing here can restate.
#[cfg(feature = "ts-go")]
fn depth_or_carried(refusal: crate::go::GoFactError) -> StructureError {
    match refusal {
        crate::go::GoFactError::SyntaxDepthExceeded { limit } => {
            StructureError::SyntaxDepthExceeded { limit }
        }
        source => StructureError::GoFacts { source },
    }
}

/// This build links no Go grammar, so no Go tree exists to project.
#[cfg(not(feature = "ts-go"))]
fn go<'source>(
    _: Node<'_>,
    _: &'source str,
    _: bool,
    _: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    Err(StructureError::BackendUnavailable {
        language: SyntaxLanguage::Go,
    })
}

/// The shared declaration walk, for a language the recognizer answers for.
///
/// A recovery tree refuses here rather than inside the walk: the walk would
/// still find recognizable declarations in one, and the ones recovery dropped
/// look exactly like declarations the source never wrote.
#[cfg(feature = "_ts_generic")]
fn generic<'source>(
    root: Node<'_>,
    source: &'source str,
    language: SyntaxLanguage,
    has_errors: bool,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    match has_errors {
        true => Err(StructureError::Recovered { language }),
        false => crate::structure::ts::inventory(root, source, language, limits),
    }
}
