//! Which source a `mod` item selects, read from its own attributes.

use crate::ir::cfg::conditional_attribute;

/// Every `#[path = "…"]` override a `mod` item selects.
///
/// A bare `#[path]` contributes one. A `cfg_attr` contributes the overrides it
/// would apply, because mutually exclusive predicates are the ordinary way one
/// module names a source per platform or feature, and nothing here evaluates a
/// predicate.
pub(super) fn declared_paths(attrs: &[syn::Attribute]) -> Box<[Box<str>]> {
    attrs.iter().flat_map(path_overrides).collect()
}

fn path_overrides(attr: &syn::Attribute) -> Vec<Box<str>> {
    match (
        attr.path().is_ident("path"),
        attr.path().is_ident("cfg_attr"),
    ) {
        (true, _) => literal_value(&attr.meta).into_iter().collect(),
        (_, true) => conditional_overrides(attr),
        _ => Vec::new(),
    }
}

/// The `path = "…"` overrides one `cfg_attr` applies.
///
/// The split between the predicate and the attributes it applies belongs to
/// [`conditional_attribute`], which the condition reader takes too: one
/// `cfg_attr` on a `mod` is read by both, and only the question asked of the
/// applied attributes differs. The predicate itself is ignored here, because
/// nothing at this tier evaluates one.
fn conditional_overrides(attr: &syn::Attribute) -> Vec<Box<str>> {
    let Some((_, applied)) = conditional_attribute(attr) else {
        return Vec::new();
    };
    applied
        .iter()
        .filter(|meta| meta.path().is_ident("path"))
        .filter_map(literal_value)
        .collect()
}

fn literal_value(meta: &syn::Meta) -> Option<Box<str>> {
    let syn::Meta::NameValue(pair) = meta else {
        return None;
    };
    match &pair.value {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => Some(text.value().into_boxed_str()),
        _ => None,
    }
}
