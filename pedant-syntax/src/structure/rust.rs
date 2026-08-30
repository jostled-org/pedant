//! Rust structures, from one `syn` parse of a loose source.
//!
//! The route a Rust file that no project slice owns takes. A source a project
//! does own is walked once by `pedant-core`'s IR extractor instead, which
//! retains the same structures beside the definition sites they join to; this
//! backend states the same set for a file that extractor never sees.
//!
//! Which `syn` items are recognized, and what each declares, is
//! [`structure::items`](super::items) — the one table this walk and the
//! enclosing-unit selector both read.
//!
//! `syn` reports positions as one-based lines and zero-based character columns;
//! the shared source index turns those into byte ranges, so this backend never
//! counts bytes itself. It is also the one route that has to build that index:
//! the grammars beside it hand their walks the positions already.

use pedant_types::StructureKind;
use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Ident, ImplItemConst, ImplItemFn, ImplItemType, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, ItemTrait, ItemType, ItemUnion, TraitItemConst, TraitItemFn,
    TraitItemType,
};

use crate::backend::ParsedSource;
use crate::extract::index::{SourceIndex, span_range, span_text};
use crate::language::SyntaxLanguage;
use crate::location::Location;
use crate::structure::builder::InventoryBuilder;
use crate::structure::error::StructureError;
use crate::structure::inventory::StructureInventory;
use crate::structure::items::{callable_kind, rust_items};
use crate::structure::limits::StructureInventoryLimits;

/// Parse `source` once and seal every structure it states.
///
/// A `syn::parse_file` failure states no declaration set at all, so it refuses
/// rather than answering with an empty inventory. The refusal carries where the
/// parser stopped, because "the Rust parser produced no tree" with no position
/// is the one thing an operator holding a broken file cannot act on.
///
/// The parse leaves one `proc-macro2` source-map entry on the calling thread,
/// which nothing frees. A long-lived process taking inventories of Rust must
/// call [`invalidate_parser_cache`](crate::invalidate_parser_cache), which
/// documents what that costs.
///
/// The parse and the index read `parsed.text()`, because `syn` reports every
/// position against the text it lexed. The inventory is sealed over
/// `parsed.source()`, because its spans outlive the parse and a consumer that
/// retains them slices the file it read.
pub(super) fn inventory<'source>(
    parsed: ParsedSource<'source>,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    let text = parsed.text();
    let file = syn::parse_file(text).map_err(refused)?;
    let index = SourceIndex::new(text);
    let mut builder = InventoryBuilder::new(parsed.source(), limits);
    let mut walk = RustStructures {
        parsed,
        index: &index,
        builder: &mut builder,
        owner: None,
        depth: 0,
        refusal: None,
    };
    walk.visit_file(&file);
    match walk.refusal {
        Some(refusal) => Err(refusal),
        None => Ok(builder.seal(SyntaxLanguage::Rust)),
    }
}

/// One `syn` parse failure, as this contract states it.
///
/// The error's message is dropped and its position kept. A refusal here is
/// `Copy` and comparable, which a message is not, and the position is the half
/// an operator uses: `syn` reports the span it stopped at, and that is the line
/// and column the broken declaration opens at.
fn refused(error: syn::Error) -> StructureError {
    let start = error.span().start();
    StructureError::Unparsed {
        language: SyntaxLanguage::Rust,
        at: Some(Location {
            line: start.line,
            // `proc-macro2` counts columns from zero and this crate from one.
            column: Some(start.column.saturating_add(1)),
        }),
    }
}

/// Walks items, impl bodies, and trait bodies, retaining each declaration.
///
/// A refusal stops the walk rather than unwinding it: `syn::visit` returns
/// nothing, so the first ceiling that refuses is held here and every later
/// visit stands down.
///
/// The parsed source rides beside the index because the two answer different
/// halves of one question: the index turns a `syn` position into an offset in
/// the text `syn` lexed, and the parsed source turns that offset into one in the
/// text the caller holds.
struct RustStructures<'source, 'walk> {
    parsed: ParsedSource<'source>,
    index: &'walk SourceIndex<'source>,
    builder: &'walk mut InventoryBuilder<'source>,
    owner: Option<u32>,
    depth: usize,
    refusal: Option<StructureError>,
}

impl<'source> RustStructures<'source, '_> {
    /// Retain one declaration spanning `span`, named by `ident`, then walk what
    /// it holds with itself as the owner.
    ///
    /// The depth ceiling is checked before the level is entered and the
    /// structure ceiling before the declaration is retained, so a refusal
    /// leaves nothing behind that a later seal could publish.
    fn enter(
        &mut self,
        kind: StructureKind,
        ident: Option<&Ident>,
        span: Span,
        descend: impl FnOnce(&mut Self),
    ) {
        if self.refusal.is_some() {
            return;
        }
        let level = self.depth.saturating_add(1);
        if let Err(refusal) = self.builder.admit_depth(level) {
            self.refusal = Some(refusal);
            return;
        }
        // An unmappable span says nothing about the declarations inside it, so
        // the walk continues rather than dropping them with it.
        let Some(bytes) = span_range(self.index, span) else {
            descend(self);
            return;
        };
        let name = ident.and_then(|named| span_text(self.index, named.span()));
        // The lines are read before the shift and the bytes after it. A
        // discarded byte-order mark sits on line 1 and opens no line of its own,
        // so it moves every offset and no line number.
        let lines = self.index.line_span(&bytes);
        let span = self.parsed.at(bytes);
        match self.builder.retain(kind, name, span, lines, self.owner) {
            Ok(position) => self.owned_by(position, level, descend),
            Err(refusal) => self.refusal = Some(refusal),
        }
    }

    /// Walk one declaration's body with that declaration as the owner.
    fn owned_by(&mut self, structure: u32, level: usize, descend: impl FnOnce(&mut Self)) {
        let owner = self.owner.replace(structure);
        let outer = std::mem::replace(&mut self.depth, level);
        descend(self);
        self.depth = outer;
        self.owner = owner;
    }
}

/// Write one retaining visit per row of the shared item table.
///
/// Each body retains the declaration, then walks what it holds with itself as
/// the owner. The three groups differ only in where the kind and the name come
/// from.
macro_rules! structure_visits {
    (
        named { $($named:ident($named_item:ty) => $kind:ident named $($field:ident).+;)* }
        callable { $($callable:ident($callable_item:ty);)* }
        unnamed { $($unnamed:ident($unnamed_item:ty) => $unnamed_kind:ident;)* }
    ) => {
        $(
            fn $named(&mut self, node: &'ast $named_item) {
                self.enter(
                    StructureKind::$kind,
                    Some(&node.$($field).+),
                    node.span(),
                    |walk| visit::$named(walk, node),
                );
            }
        )*
        $(
            fn $callable(&mut self, node: &'ast $callable_item) {
                self.enter(
                    callable_kind(&node.sig),
                    Some(&node.sig.ident),
                    node.span(),
                    |walk| visit::$callable(walk, node),
                );
            }
        )*
        $(
            fn $unnamed(&mut self, node: &'ast $unnamed_item) {
                self.enter(
                    StructureKind::$unnamed_kind,
                    None,
                    node.span(),
                    |walk| visit::$unnamed(walk, node),
                );
            }
        )*
    };
}

impl<'ast> Visit<'ast> for RustStructures<'_, '_> {
    rust_items!(structure_visits);
}
