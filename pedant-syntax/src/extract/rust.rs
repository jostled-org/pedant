//! Rust declaration recognition over a `syn` syntax tree.
//!
//! `syn` reports positions as one-based lines and zero-based character
//! columns; the shared source index turns those into byte ranges, so this
//! backend never counts bytes itself.

use std::ops::Range;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Ident, ImplItemFn, ImplItemType, ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait, ItemType,
    ItemUnion, TraitItemFn, TraitItemType,
};

use crate::extract::select::UnitSelector;
use crate::unit::SourceUnitKind;

/// Release the thread-local source map `syn` fills while parsing.
///
/// `proc-macro2`'s `span-locations` feature, which `Spanned` requires, keeps one
/// entry per parsed file for the life of the thread: the whole source text and
/// its line table. Outside a procedural macro nothing frees it, so a process
/// that extracts from Rust in a loop grows without bound. Worse, the entries
/// carry 32-bit positions that accumulate; past four gigabytes of cumulative
/// source they wrap, and a location lookup then answers for the wrong file or
/// panics.
///
/// Extraction keeps no span past the call that made it, so releasing the map is
/// always safe for this crate. It is not safe for an arbitrary caller: this
/// invalidates every `proc_macro2::Span` live on the calling thread, so a caller
/// holding its own `syn` syntax tree must not call it while that tree's
/// locations still matter. That is why extraction does not call it itself — the
/// host that knows whether it holds live spans decides.
///
/// # Panics
///
/// Panics if called from inside a procedural macro, where the source map
/// belongs to the compiler.
pub fn invalidate_parser_cache() {
    proc_macro2::extra::invalidate_current_thread_spans();
}

/// Offer every recognized Rust declaration in `source`.
///
/// A `syn::parse_file` failure is parser failure: nothing is offered, so the
/// caller's extraction is absent rather than partially recovered.
pub(crate) fn collect<'s>(source: &'s str, selector: &mut UnitSelector<'s>) {
    let Ok(file) = syn::parse_file(source) else {
        return;
    };
    RustDeclarations { selector }.visit_file(&file);
}

/// Walks items, impl bodies, and trait bodies, offering each declaration.
///
/// The selector owns the source index, so it is also where this backend reads
/// the text a span covers: the offsets and the slices come from one string.
struct RustDeclarations<'s, 'sel> {
    selector: &'sel mut UnitSelector<'s>,
}

impl<'s> RustDeclarations<'s, '_> {
    /// Offer one declaration spanning `span`, named by `ident`, and report
    /// whether anything inside it can still hold the target.
    ///
    /// A declaration that misses the location prunes its own subtree: `syn`
    /// nests every child's tokens inside its parent's span, so no descendant
    /// can contain a point the parent does not. Pruning also skips resolving
    /// the identifier's text, which only the winning declaration ever needs.
    fn offer(&mut self, kind: SourceUnitKind, ident: Option<&Ident>, span: Span) -> bool {
        let Some(range) = self.range_of(span) else {
            // An unmappable span says nothing about its children, so the walk
            // continues rather than dropping them with it.
            return true;
        };
        if !self.selector.contains(&range) {
            return false;
        }
        let name = ident.and_then(|ident| self.text_of(ident.span()));
        self.selector.keep(kind, name, range);
        true
    }

    /// The source byte range one parser span covers.
    fn range_of(&self, span: Span) -> Option<Range<usize>> {
        let start = span.start();
        let end = span.end();
        let from = self
            .selector
            .offset_at_char_column(start.line, start.column)?;
        let to = self.selector.offset_at_char_column(end.line, end.column)?;
        (from < to).then_some(from..to)
    }

    /// The source text one parser span covers.
    fn text_of(&self, span: Span) -> Option<&'s str> {
        self.selector.source().get(self.range_of(span)?)
    }
}

/// Define one named-declaration visit per row.
///
/// Every row is `visit_fn(SynType) => Kind named field.path`, and every body is
/// the same: offer the declaration under `Kind`, named by the identifier at
/// `field.path`, spanning the whole item, then descend only where the offer says
/// the location can still be inside. Writing the bodies out made the set of
/// recognized declarations a list of eleven three-line copies; the rows keep it
/// a table, and a twelfth declaration is one more row.
///
/// The unnamed [`ItemImpl`] is not a row: it offers `None` and carries the
/// reasoning for why, so it stays written out below.
macro_rules! named_declarations {
    ($($(#[$doc:meta])* $visit:ident($item:ty) => $kind:ident named $($field:ident).+;)*) => {
        $(
            $(#[$doc])*
            fn $visit(&mut self, node: &'ast $item) {
                if self.offer(SourceUnitKind::$kind, Some(&node.$($field).+), node.span()) {
                    visit::$visit(self, node);
                }
            }
        )*
    };
}

impl<'ast> Visit<'ast> for RustDeclarations<'_, '_> {
    named_declarations! {
        visit_item_fn(ItemFn) => Function named sig.ident;
        visit_impl_item_fn(ImplItemFn) => Method named sig.ident;
        visit_trait_item_fn(TraitItemFn) => Method named sig.ident;
        visit_item_struct(ItemStruct) => Struct named ident;
        visit_item_enum(ItemEnum) => Enum named ident;
        visit_item_union(ItemUnion) => Union named ident;
        visit_item_trait(ItemTrait) => Trait named ident;
        visit_item_type(ItemType) => TypeAlias named ident;

        /// An associated type an `impl` block defines.
        ///
        /// `syn` gives a free `type` item, an impl's, and a trait's three item
        /// types, so the alias inside a block needs its own visit for the same
        /// reason a method does — otherwise the whole block answers for it.
        visit_impl_item_type(ImplItemType) => TypeAlias named ident;

        /// An associated type a trait declares, with or without a default.
        visit_trait_item_type(TraitItemType) => TypeAlias named ident;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // An impl block declares no name, and it wins only where no method,
        // type, or nested item inside it contains the location.
        if self.offer(SourceUnitKind::Impl, None, node.span()) {
            visit::visit_item_impl(self, node);
        }
    }
}
