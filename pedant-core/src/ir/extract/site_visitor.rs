//! The site-recording half of the traversal.
//!
//! Each function here turns one `syn` node into definition or reference sites
//! and leaves the surrounding nesting state to the collector. The `syn` dispatch
//! that calls them stays in [`super::visitor`], so neither file owns two jobs.

use std::rc::Rc;

use pedant_types::{ReferenceKind, SymbolKind};

use crate::ir::facts::TypeDefKind;
use crate::ir::sites::ReferenceOrigin;
use crate::observe::{self, Observation};

use super::extractor::IrExtractor;
use super::imports::use_tree_leaves;
use super::paths::{path_range, path_segments, path_text, range_between, range_of};
use super::sites::{LocalReceivers, ModuleEntry, ReferenceEntry, SavedPosition};

/// The path segment `impl` blocks give a name to.
const SELF_SEGMENT: &str = "Self";

/// The nesting state one function body replaced.
pub(super) struct FunctionEntry {
    position: SavedPosition,
    receivers: LocalReceivers,
}

/// Record a function or method definition and enter its body.
pub(super) fn enter_function(
    extractor: &mut IrExtractor,
    sig: &syn::Signature,
    associated_with: Option<Rc<str>>,
) -> FunctionEntry {
    let kind = match sig.inputs.first() {
        Some(syn::FnArg::Receiver(_)) => SymbolKind::Method,
        _ => SymbolKind::Function,
    };
    let definition = extractor.sites.push_definition(
        kind,
        sig.ident.to_string().into_boxed_str(),
        range_of(sig.ident.span()),
        owner_name(associated_with),
    );
    FunctionEntry {
        position: extractor.sites.enter_owner(definition),
        receivers: extractor.sites.enter_receivers(),
    }
}

/// Leave a function body, restoring the enclosing owner and bindings.
pub(super) fn leave_function(extractor: &mut IrExtractor, entry: FunctionEntry) {
    extractor.sites.leave_receivers(entry.receivers);
    extractor.sites.restore(entry.position);
}

/// The `impl` self type the traversal is inside, when it is inside one.
pub(super) fn current_self_type(extractor: &IrExtractor) -> Option<Rc<str>> {
    extractor
        .current_impl
        .as_ref()
        .map(|(self_type, _)| Rc::clone(self_type))
}

/// The trait the traversal is inside, when it is inside one.
pub(super) fn current_trait(extractor: &IrExtractor) -> Option<Rc<str>> {
    extractor.current_trait.clone()
}

/// The owner name a definition site stores, copied out of the traversal state
/// it is shared from.
fn owner_name(associated_with: Option<Rc<str>>) -> Option<Box<str>> {
    associated_with.map(|name| Box::from(&*name))
}

/// Record a struct, enum, union, or trait definition and enter its body.
pub(super) fn enter_type_definition(
    extractor: &mut IrExtractor,
    ident: &syn::Ident,
    kind: TypeDefKind,
) -> SavedPosition {
    let definition = extractor.sites.push_definition(
        symbol_kind(kind),
        ident.to_string().into_boxed_str(),
        range_of(ident.span()),
        None,
    );
    extractor.sites.enter_owner(definition)
}

/// Record a constant, static, or type-alias definition.
///
/// The caller states the owner, because the syntax decides it: an `impl` or
/// trait body names one, and a free item names none even where a surrounding
/// method body sits inside an `impl`.
pub(super) fn record_value_item(
    extractor: &mut IrExtractor,
    ident: &syn::Ident,
    kind: SymbolKind,
    associated_with: Option<Rc<str>>,
) -> SavedPosition {
    let definition = extractor.sites.push_definition(
        kind,
        ident.to_string().into_boxed_str(),
        range_of(ident.span()),
        owner_name(associated_with),
    );
    extractor.sites.enter_owner(definition)
}

/// Record a `mod` item, plus the module reference an external one carries, and
/// enter the body it owns.
///
/// The visitor enters under the item's own `#[cfg(…)]` gates, so the active
/// condition already states them and neither site re-applies them.
pub(super) fn enter_module(extractor: &mut IrExtractor, node: &syn::ItemMod) -> SavedPosition {
    let name = node.ident.to_string().into_boxed_str();
    let range = range_between(node.mod_token.span, node.ident.span());
    if node.content.is_none() {
        extractor.sites.push_reference(ReferenceEntry::path(
            ReferenceKind::Module,
            ReferenceOrigin::ModuleDeclaration,
            name.clone(),
            range,
            Box::from([name.clone()]),
        ));
    }
    extractor.sites.push_module(ModuleEntry {
        name,
        range,
        declared_paths: declared_paths(&node.attrs),
        inline: node.content.is_some(),
    })
}

/// Every `#[path = "…"]` override a `mod` item selects.
///
/// A bare `#[path]` contributes one. A `cfg_attr` contributes the overrides it
/// would apply, because mutually exclusive predicates are the ordinary way one
/// module names a source per platform or feature, and nothing here evaluates a
/// predicate.
fn declared_paths(attrs: &[syn::Attribute]) -> Box<[Box<str>]> {
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

/// The `path = "…"` overrides one `cfg_attr` applies. Its first element is the
/// predicate rather than an attribute, so it is skipped.
fn conditional_overrides(attr: &syn::Attribute) -> Vec<Box<str>> {
    let parsed = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    );
    let Ok(items) = parsed else {
        return Vec::new();
    };
    items
        .iter()
        .skip(1)
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

/// Record every path one `use` item declares, from the single tree walk.
pub(super) fn record_import(extractor: &mut IrExtractor, node: &syn::ItemUse) {
    observe::record(Observation::ImportWalk(&extractor.file_path));
    let condition = extractor.sites.condition().with(&node.attrs);
    let range = range_between(node.use_token.span, node.semi_token.span);
    for leaf in use_tree_leaves(&node.tree).into_vec() {
        extractor.sites.push_conditional_reference(
            ReferenceEntry {
                kind: ReferenceKind::Import,
                origin: ReferenceOrigin::Import,
                text: path_text(&leaf.segments),
                range,
                segments: leaf.segments,
                alias: leaf.alias,
                glob: leaf.glob,
                receiver: None,
            },
            &condition,
        );
    }
}

/// Record a path in expression position, whether or not it is a callee.
///
/// A path with no segments has no range, so the walk stops before the match and
/// every arm below reads at least one segment.
pub(super) fn record_expression_path(extractor: &mut IrExtractor, path: &syn::Path, callee: bool) {
    let Some(range) = path_range(path) else {
        return;
    };
    let raw = path_segments(path);
    let text = path_text(&raw);
    let segments = qualified(extractor, raw);
    let classified = match (segments.len(), callee) {
        // A one-segment value path is a tier boundary, not an omission: without
        // types nothing here separates a unit struct from a local binding.
        (1, false) => return,
        (1, true) => (ReferenceKind::Call, ReferenceOrigin::CallPath),
        (_, true) => (ReferenceKind::Call, ReferenceOrigin::ExpressionPath),
        (_, false) => (ReferenceKind::Type, ReferenceOrigin::ExpressionPath),
    };
    extractor.sites.push_reference(ReferenceEntry::path(
        classified.0,
        classified.1,
        text,
        range,
        segments,
    ));
}

/// Record a method call, with the receiver type when one is established.
pub(super) fn record_method_call(extractor: &mut IrExtractor, node: &syn::ExprMethodCall) {
    let receiver = receiver_type(extractor, &node.receiver);
    let name: Box<str> = node.method.to_string().into_boxed_str();
    extractor.sites.push_reference(ReferenceEntry {
        kind: ReferenceKind::Call,
        origin: ReferenceOrigin::MethodCall,
        segments: Box::from([name.clone()]),
        text: name,
        range: range_of(node.method.span()),
        alias: None,
        glob: false,
        receiver,
    });
}

/// Record a type named anywhere in the source.
pub(super) fn record_type_path(extractor: &mut IrExtractor, node: &syn::TypePath) {
    let Some(range) = path_range(&node.path) else {
        return;
    };
    let raw = path_segments(&node.path);
    let text = path_text(&raw);
    let segments = qualified(extractor, raw);
    extractor.sites.push_reference(ReferenceEntry::path(
        ReferenceKind::Type,
        ReferenceOrigin::TypeMention,
        text,
        range,
        segments,
    ));
}

/// Replace a leading `Self` with the type the enclosing `impl` block names.
///
/// Inside a trait, `Self` is whatever implements it, so the segment is left
/// alone and the reference resolves to nothing in this corpus. The enclosing
/// type name is read only once a path actually leads with `Self`, so an
/// ordinary path costs no lookup.
fn qualified(extractor: &IrExtractor, mut segments: Box<[Box<str>]>) -> Box<[Box<str>]> {
    let leads_with_self = segments
        .first()
        .is_some_and(|first| &**first == SELF_SEGMENT);
    let named = leads_with_self
        .then(|| current_self_type(extractor))
        .flatten();
    match named {
        Some(self_type) => {
            segments[0] = Box::from(&*self_type);
            segments
        }
        None => segments,
    }
}

/// Record a struct literal as a mention of the type it constructs.
pub(super) fn record_struct_literal(extractor: &mut IrExtractor, node: &syn::ExprStruct) {
    let Some(range) = path_range(&node.path) else {
        return;
    };
    let segments = path_segments(&node.path);
    extractor.sites.push_reference(ReferenceEntry::path(
        ReferenceKind::Type,
        ReferenceOrigin::TypeMention,
        path_text(&segments),
        range,
        segments,
    ));
}

/// Record the trait an `impl` block implements.
pub(super) fn record_implementation(extractor: &mut IrExtractor, node: &syn::ItemImpl) {
    let Some((_, path, _)) = node.trait_.as_ref() else {
        return;
    };
    let Some(range) = path_range(path) else {
        return;
    };
    let segments = path_segments(path);
    extractor.sites.push_reference(ReferenceEntry::path(
        ReferenceKind::Implementation,
        ReferenceOrigin::Implementation,
        path_text(&segments),
        range,
        segments,
    ));
}

/// Record a macro invocation, whose target this tier never expands.
pub(super) fn record_macro(extractor: &mut IrExtractor, node: &syn::Macro) {
    let Some(range) = path_range(&node.path) else {
        return;
    };
    let segments = path_segments(&node.path);
    extractor.sites.push_reference(ReferenceEntry::path(
        ReferenceKind::Call,
        ReferenceOrigin::MacroInvocation,
        path_text(&segments),
        range,
        segments,
    ));
}

/// Record the type a `let` binding is known to hold.
pub(super) fn record_local_receiver(extractor: &mut IrExtractor, node: &syn::Local) {
    let stated = annotated_binding(&node.pat)
        .or_else(|| inferred_binding(node))
        .filter(|(_, type_name)| !type_name.is_empty());
    if let Some((name, type_name)) = stated {
        extractor.sites.record_receiver(name, type_name);
    }
}

fn annotated_binding(pat: &syn::Pat) -> Option<(Box<str>, Rc<str>)> {
    let syn::Pat::Type(typed) = pat else {
        return None;
    };
    let syn::Pat::Ident(ident) = typed.pat.as_ref() else {
        return None;
    };
    let named = type_name(&typed.ty)?;
    Some((ident.ident.to_string().into_boxed_str(), named))
}

fn inferred_binding(node: &syn::Local) -> Option<(Box<str>, Rc<str>)> {
    let syn::Pat::Ident(ident) = &node.pat else {
        return None;
    };
    let init = node.init.as_ref()?;
    let named = initializer_type(&init.expr)?;
    Some((ident.ident.to_string().into_boxed_str(), named))
}

/// The type a struct literal or an obvious constructor call establishes.
fn initializer_type(expr: &syn::Expr) -> Option<Rc<str>> {
    match expr {
        syn::Expr::Struct(literal) => last_segment(&literal.path),
        syn::Expr::Call(call) => constructor_type(&call.func),
        _ => None,
    }
}

fn constructor_type(func: &syn::Expr) -> Option<Rc<str>> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let segments = path_segments(&path.path);
    segments
        .len()
        .checked_sub(2)
        .and_then(|index| segments.get(index))
        .map(|named| Rc::from(&**named))
}

fn last_segment(path: &syn::Path) -> Option<Rc<str>> {
    path.segments
        .last()
        .map(|segment| Rc::from(segment.ident.to_string().as_str()))
}

fn type_name(ty: &syn::Type) -> Option<Rc<str>> {
    match ty {
        syn::Type::Path(path) => last_segment(&path.path),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        _ => None,
    }
}

fn receiver_type(extractor: &IrExtractor, receiver: &syn::Expr) -> Option<Rc<str>> {
    let syn::Expr::Path(path) = receiver else {
        return None;
    };
    let named = path.path.get_ident()?.to_string();
    match named.as_str() {
        "self" | SELF_SEGMENT => current_self_type(extractor),
        binding => extractor.sites.receiver_type(binding),
    }
}

fn symbol_kind(kind: TypeDefKind) -> SymbolKind {
    match kind {
        TypeDefKind::Struct => SymbolKind::Struct,
        TypeDefKind::Enum => SymbolKind::Enum,
        TypeDefKind::Trait => SymbolKind::Trait,
        TypeDefKind::Union => SymbolKind::Union,
    }
}

/// The trait name the traversal should carry while visiting a trait's items.
pub(super) fn trait_scope(ident: &syn::Ident) -> Rc<str> {
    Rc::from(ident.to_string().as_str())
}
