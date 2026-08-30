//! Which `syn` items state a logical structure, and what they state.
//!
//! The Rust half of the crate's one declaration table, beside `recognize` for
//! the grammars tree-sitter reads. Both Rust walks consume it — the structure
//! inventory and the enclosing-unit selector — so no `syn` item type is written
//! down twice and neither walk can answer a kind the other does not.
//!
//! The table speaks [`StructureKind`], which is the wider of the two
//! vocabularies. The unit model is a narrowing of it, and extraction applies
//! that narrowing through
//! [`SourceUnitKind::of`](crate::SourceUnitKind::of): the five rows it refuses
//! — a constant, a static, and a module — are declarations an outline shows and
//! a returned source unit has no kind for. Extraction still visits them, because
//! a module holds the declarations a caller is asking about.
//!
//! Three groups, because three bodies differ:
//!
//! - `named` rows read their kind from the table and their name from a field
//!   path. An associated type and an associated constant are rows of their own
//!   for the reason a method is: without them the whole `impl` or `trait` block
//!   answers for a location inside one.
//! - `callable` rows read their kind from the receiver instead, so
//!   `impl Job { fn new() -> Self }` is a function and `fn id(&self)` is a
//!   method. That is the rule `pedant-core`'s site inventory applies to a
//!   project source, and stating it here is what keeps a loose source and a
//!   resolved one from naming one declaration two things.
//! - `unnamed` rows state no identifier. The `impl` block is the only one.

use pedant_types::StructureKind;
use syn::Signature;

/// What one callable declares, given the signature it writes.
///
/// A receiver is the whole rule: a function an `impl` or a `trait` happens to
/// hold is still a function until it takes `self`.
pub(crate) fn callable_kind(sig: &Signature) -> StructureKind {
    match sig.inputs.first() {
        Some(syn::FnArg::Receiver(_)) => StructureKind::Method,
        _ => StructureKind::Function,
    }
}

/// Hand every recognized `syn` item to `$visits`, which writes one visit body
/// per row.
///
/// A callback rather than a generator, because the two consumers differ in
/// their bodies and not in their rows: one retains a structure and walks what it
/// holds, the other offers a candidate and prunes the subtree that cannot hold
/// the caller's location. Passing the rows to a caller-supplied macro keeps the
/// set of recognized declarations one list, and a sixteenth declaration one more
/// row.
macro_rules! rust_items {
    ($visits:ident) => {
        $visits! {
            named {
                visit_item_struct(ItemStruct) => Struct named ident;
                visit_item_enum(ItemEnum) => Enum named ident;
                visit_item_union(ItemUnion) => Union named ident;
                visit_item_trait(ItemTrait) => Trait named ident;
                visit_item_type(ItemType) => TypeAlias named ident;
                visit_item_const(ItemConst) => Constant named ident;
                visit_item_static(ItemStatic) => Static named ident;
                visit_item_mod(ItemMod) => Module named ident;
                visit_impl_item_type(ImplItemType) => TypeAlias named ident;
                visit_trait_item_type(TraitItemType) => TypeAlias named ident;
                visit_impl_item_const(ImplItemConst) => Constant named ident;
                visit_trait_item_const(TraitItemConst) => Constant named ident;
            }
            callable {
                visit_item_fn(ItemFn);
                visit_impl_item_fn(ImplItemFn);
                visit_trait_item_fn(TraitItemFn);
            }
            unnamed {
                visit_item_impl(ItemImpl) => Impl;
            }
        }
    };
}

pub(crate) use rust_items;
