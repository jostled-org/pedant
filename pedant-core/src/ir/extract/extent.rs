//! The source extent one declaration occupies, read from its boundary tokens.
//!
//! An item's first and last tokens carry the two points needed for its extent.

use proc_macro2::Span;
use syn::{AttrStyle, Attribute, Signature, Visibility};

use crate::ir::sites::IrRange;

use super::paths::range_between;

/// The whole extent one declaration writes, its attributes included.
pub(super) trait DeclarationExtent {
    /// The range from the declaration's first token to its last.
    fn extent(&self) -> IrRange;
}

/// Define one declaration extent per row.
///
/// Every row is `Node => |item| (head, tail)`, where the head is the first
/// token the item prints once its attributes are set aside and the tail is the
/// last. Attributes are common to every row, so the table states only what
/// follows them.
macro_rules! declaration_extents {
    ($($node:ty => |$item:ident| ($head:expr, $tail:expr);)*) => {
        $(
            impl DeclarationExtent for $node {
                fn extent(&self) -> IrRange {
                    let $item = self;
                    range_between(opening(&$item.attrs, $head), $tail)
                }
            }
        )*
    };
}

declaration_extents! {
    syn::ItemFn => |item| (
        visible_head(&item.vis, signature_head(&item.sig)),
        item.block.brace_token.span.close()
    );
    syn::ItemConst => |item| (
        visible_head(&item.vis, item.const_token.span),
        item.semi_token.span
    );
    syn::ItemStatic => |item| (
        visible_head(&item.vis, item.static_token.span),
        item.semi_token.span
    );
    syn::ItemType => |item| (
        visible_head(&item.vis, item.type_token.span),
        item.semi_token.span
    );
    syn::ItemStruct => |item| (
        visible_head(&item.vis, item.struct_token.span),
        struct_tail(item)
    );
    syn::ItemEnum => |item| (
        visible_head(&item.vis, item.enum_token.span),
        item.brace_token.span.close()
    );
    syn::ItemUnion => |item| (
        visible_head(&item.vis, item.union_token.span),
        item.fields.brace_token.span.close()
    );
    syn::ItemTrait => |item| (
        visibility(&item.vis)
            .or_else(|| item.unsafety.map(|token| token.span))
            .or_else(|| item.auto_token.map(|token| token.span))
            .unwrap_or(item.trait_token.span),
        item.brace_token.span.close()
    );
    syn::ItemImpl => |item| (
        item.defaultness
            .map(|token| token.span)
            .or_else(|| item.unsafety.map(|token| token.span))
            .unwrap_or(item.impl_token.span),
        item.brace_token.span.close()
    );
    syn::ItemMod => |item| (
        visibility(&item.vis)
            .or_else(|| item.unsafety.map(|token| token.span))
            .unwrap_or(item.mod_token.span),
        module_tail(item)
    );
    syn::ImplItemFn => |item| (
        associated_head(&item.vis, item.defaultness, signature_head(&item.sig)),
        item.block.brace_token.span.close()
    );
    syn::ImplItemConst => |item| (
        associated_head(&item.vis, item.defaultness, item.const_token.span),
        item.semi_token.span
    );
    syn::ImplItemType => |item| (
        associated_head(&item.vis, item.defaultness, item.type_token.span),
        item.semi_token.span
    );
    syn::TraitItemFn => |item| (signature_head(&item.sig), trait_fn_tail(item));
    syn::TraitItemConst => |item| (item.const_token.span, item.semi_token.span);
    syn::TraitItemType => |item| (item.type_token.span, item.semi_token.span);
}

/// The span of the very first token an item prints.
///
/// Only outer attributes precede the head: an inner attribute is written inside
/// the body and states nothing about where the item starts.
fn opening(attrs: &[Attribute], head: Span) -> Span {
    attrs
        .first()
        .filter(|attr| matches!(attr.style, AttrStyle::Outer))
        .map_or(head, |attr| attr.pound_token.spans[0])
}

/// The span an item's declared visibility occupies, when the source writes one.
fn visibility(vis: &Visibility) -> Option<Span> {
    match vis {
        Visibility::Public(token) => Some(token.span),
        Visibility::Restricted(restricted) => Some(restricted.pub_token.span),
        Visibility::Inherited => None,
    }
}

/// The head of an item whose visibility precedes its keyword.
fn visible_head(vis: &Visibility, keyword: Span) -> Span {
    visibility(vis).unwrap_or(keyword)
}

/// The head of an `impl` item, whose `default` sits between the two.
fn associated_head(
    vis: &Visibility,
    defaultness: Option<syn::token::Default>,
    keyword: Span,
) -> Span {
    visibility(vis)
        .or_else(|| defaultness.map(|token| token.span))
        .unwrap_or(keyword)
}

/// The head of a signature: the first qualifier it carries, or `fn`.
fn signature_head(sig: &Signature) -> Span {
    sig.constness
        .map(|token| token.span)
        .or_else(|| sig.asyncness.map(|token| token.span))
        .or_else(|| sig.unsafety.map(|token| token.span))
        .or_else(|| sig.abi.as_ref().map(|abi| abi.extern_token.span))
        .unwrap_or(sig.fn_token.span)
}

/// The last token a struct prints: its closing brace, or the terminator a
/// tuple or unit form writes.
///
/// A parsed tuple or unit form always carries its terminator. A tree built by
/// hand may omit it; in that case the closing delimiter or identifier is its
/// last located token.
fn struct_tail(item: &syn::ItemStruct) -> Span {
    match &item.fields {
        syn::Fields::Named(fields) => fields.brace_token.span.close(),
        syn::Fields::Unnamed(fields) => item
            .semi_token
            .map_or(fields.paren_token.span.close(), |semi| semi.span),
        syn::Fields::Unit => item.semi_token.map_or(item.ident.span(), |semi| semi.span),
    }
}

/// The last token a `mod` item prints: its closing brace when the body is
/// inline, and otherwise the terminator naming the source it selects.
fn module_tail(item: &syn::ItemMod) -> Span {
    match &item.content {
        Some((brace, _)) => brace.span.close(),
        None => item.semi.map_or(item.ident.span(), |semi| semi.span),
    }
}

/// The last token a trait method prints: the closing brace of the default body
/// it supplies, and otherwise the terminator a bodiless declaration writes.
fn trait_fn_tail(item: &syn::TraitItemFn) -> Span {
    match &item.default {
        Some(body) => body.brace_token.span.close(),
        None => item
            .semi_token
            .map_or(item.sig.ident.span(), |semi| semi.span),
    }
}
