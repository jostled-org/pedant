//! The public structure-inventory entry point and its backend dispatch.

use crate::backend::{Backend, backend};
use crate::language::SyntaxLanguage;
use crate::structure::error::StructureError;
use crate::structure::inventory::StructureInventory;
use crate::structure::limits::StructureInventoryLimits;

/// Take the complete structure inventory of one source.
///
/// This entry point parses `source` once. A caller that already holds a parse
/// session or a retained Go fact inventory asks that instead:
/// `tree_sitter::ParsedSyntax::structure_inventory` and
/// `go::GoFileFacts::structure_inventory` parse nothing, so no source is walked
/// twice for one answer. Both are published behind the features that supply
/// their backends.
///
/// The result is an error rather than an empty inventory whenever the source
/// states no complete structure set: a parser that fails, a parser that
/// recovered, a backend this build does not link, and either ceiling in
/// `limits`. An empty inventory means the source declares nothing.
///
/// Extraction reads no file, opens no network connection, and loads no project
/// model. The Rust backend's parser keeps a thread-local source map that
/// nothing frees; see `invalidate_parser_cache`, published behind the `rust`
/// feature.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "ts-bash")]
/// # {
/// use pedant_syntax::{
///     StructureInventoryLimits, StructureKind, SyntaxLanguage, structure_inventory,
/// };
///
/// let source = "greet() {\n  echo hi\n}\n";
/// let inventory =
///     structure_inventory(source, SyntaxLanguage::Bash, StructureInventoryLimits::default())
///         .expect("a complete inventory");
///
/// let function = inventory.structures().first().expect("one function");
/// assert_eq!(function.kind(), StructureKind::Function);
/// assert_eq!(function.name(), Some("greet"));
/// assert_eq!(function.span().line_count(), 3);
/// # }
/// ```
pub fn structure_inventory(
    source: &str,
    language: SyntaxLanguage,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'_>, StructureError> {
    match backend(language) {
        Some(selected) => inventory(selected, source, limits),
        None => Err(StructureError::BackendUnavailable { language }),
    }
}

/// Parse one source with `selected` and take the inventory of that tree.
///
/// A free function rather than a method on [`Backend`], for the reason
/// `extract` states: that type's own API is its selection and the text its
/// parser sees.
#[cfg(any(feature = "rust", feature = "_ts"))]
fn inventory(
    selected: Backend,
    source: &str,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'_>, StructureError> {
    // The parsed text and the caller's own source travel together, because an
    // inventory's spans outlive the parse: the Rust parser discards a leading
    // byte-order mark and reports every position against what is left, while the
    // offsets this route publishes must index the string the caller handed in.
    let parsed = selected.parsed_source(source);
    match selected {
        #[cfg(feature = "rust")]
        Backend::Rust => crate::structure::rust::inventory(parsed, limits),
        #[cfg(feature = "_ts")]
        Backend::TreeSitter(language) => from_grammar(parsed.text(), language, limits),
    }
}

/// This build links no parser, so no value of this type exists.
#[cfg(not(any(feature = "rust", feature = "_ts")))]
fn inventory(
    selected: Backend,
    _: &str,
    _: StructureInventoryLimits,
) -> Result<StructureInventory<'_>, StructureError> {
    match selected {}
}

/// Parse one source with its grammar and take the inventory of that tree.
#[cfg(feature = "_ts")]
fn from_grammar(
    source: &str,
    language: SyntaxLanguage,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'_>, StructureError> {
    let Some(parsed) = crate::tree_sitter::parse_bound(source, language) else {
        // Both absences leave `parse_bound` empty, and they are different
        // answers: a grammar this build omits states nothing about the source,
        // while a parser that ran and produced no tree states that the source
        // is unreadable.
        return Err(match crate::tree_sitter::links_grammar(language) {
            // A parser that produced no tree named no node, so there is no
            // position to carry; the Rust route, whose parser reports the span
            // it stopped at, is the one that fills this in.
            true => StructureError::Unparsed { language, at: None },
            false => StructureError::BackendUnavailable { language },
        });
    };
    parsed.structure_inventory(limits)
}
