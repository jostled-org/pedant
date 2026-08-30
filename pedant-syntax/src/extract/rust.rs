//! Rust declaration recognition over a `syn` syntax tree.
//!
//! Which `syn` items are recognized, and what each declares, is
//! [`structure::items`](crate::structure::items) — the one table this backend
//! and the structure inventory both read. A unit is that recognition narrowed to
//! the kinds the unit model declares.
//!
//! `syn` reports positions as one-based lines and zero-based character
//! columns; the shared source index turns those into byte ranges, so this
//! backend never counts bytes itself.

use pedant_types::StructureKind;
use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Ident, ImplItemConst, ImplItemFn, ImplItemType, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStatic, ItemStruct, ItemTrait, ItemType, ItemUnion, TraitItemConst, TraitItemFn,
    TraitItemType,
};

use crate::extract::index::{span_range, span_text};
use crate::extract::select::UnitSelector;
use crate::structure::items::{callable_kind, rust_items};
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

impl RustDeclarations<'_, '_> {
    /// Offer one declaration spanning `span`, named by `ident`, and report
    /// whether anything inside it can still hold the target.
    ///
    /// A declaration that misses the location prunes its own subtree: `syn`
    /// nests every child's tokens inside its parent's span, so no descendant
    /// can contain a point the parent does not. Pruning also skips resolving
    /// the identifier's text, which only the winning declaration ever needs.
    ///
    /// A structure the unit model states no kind for is not offered, and its
    /// subtree is still walked. That is the whole of the narrowing: a `mod`
    /// holds the declarations a caller inside it is asking about, and a
    /// constant's initializer may hold one too, so refusing the kind must not
    /// refuse the descent.
    fn offer(&mut self, kind: StructureKind, ident: Option<&Ident>, span: Span) -> bool {
        let index = self.selector.index();
        let Some(range) = span_range(index, span) else {
            // An unmappable span says nothing about its children, so the walk
            // continues rather than dropping them with it.
            return true;
        };
        if !self.selector.contains(&range) {
            return false;
        }
        let Some(kind) = SourceUnitKind::of(kind) else {
            return true;
        };
        let name = ident.and_then(|ident| span_text(self.selector.index(), ident.span()));
        self.selector.keep(kind, name, range);
        true
    }
}

/// Write one offering visit per row of the shared item table.
///
/// Each body offers the declaration and then descends only where the offer says
/// the location can still be inside. The three groups differ only in where the
/// kind and the name come from.
macro_rules! declaration_visits {
    (
        named { $($named:ident($named_item:ty) => $kind:ident named $($field:ident).+;)* }
        callable { $($callable:ident($callable_item:ty);)* }
        unnamed { $($unnamed:ident($unnamed_item:ty) => $unnamed_kind:ident;)* }
    ) => {
        $(
            fn $named(&mut self, node: &'ast $named_item) {
                if self.offer(StructureKind::$kind, Some(&node.$($field).+), node.span()) {
                    visit::$named(self, node);
                }
            }
        )*
        $(
            fn $callable(&mut self, node: &'ast $callable_item) {
                if self.offer(callable_kind(&node.sig), Some(&node.sig.ident), node.span()) {
                    visit::$callable(self, node);
                }
            }
        )*
        $(
            fn $unnamed(&mut self, node: &'ast $unnamed_item) {
                if self.offer(StructureKind::$unnamed_kind, None, node.span()) {
                    visit::$unnamed(self, node);
                }
            }
        )*
    };
}

impl<'ast> Visit<'ast> for RustDeclarations<'_, '_> {
    rust_items!(declaration_visits);
}
