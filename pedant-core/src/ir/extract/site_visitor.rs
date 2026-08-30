//! The site-recording half of the traversal.
//!
//! Each function here turns one `syn` node into definition or reference sites
//! and leaves the surrounding nesting state to the collector. The `syn` dispatch
//! that calls them stays in [`super::visitor`], so neither file owns two jobs.

use std::sync::Arc;

use pedant_types::{ReferenceKind, StructureKind, SymbolKind};

use crate::ir::cfg::RustCfgCondition;
use crate::ir::sites::{IrRange, ReferenceOrigin};
use crate::observe::{self, Observation};

use super::extractor::{IrExtractor, ValueItem};
use super::imports::use_tree_leaves;
use super::module_paths::declared_paths;
use super::paths::{path_range, path_segments, path_text, range_between, range_of};
use super::receivers::Bindings;
use super::sites::{DeclarationEntry, ModuleEntry, ReferenceEntry, SavedPosition};

/// The path segment `impl` blocks give a name to.
const SELF_SEGMENT: &str = "Self";

/// Record one reference site, stamped with the callable body under traversal.
///
/// The function scope is the single owner of that index, so every recorder here
/// routes through this pair rather than reading the scope itself.
fn push_reference(extractor: &mut IrExtractor, entry: ReferenceEntry) {
    let containing_fn = extractor.fn_scope.current();
    extractor.sites.push_reference(entry, containing_fn);
}

/// [`push_reference`] for a reference whose own attributes widen the condition.
///
/// One `use` item states one condition and records a site per leaf, so the
/// shared condition is borrowed here and copied once into the site it lands in.
fn push_conditional_reference(
    extractor: &mut IrExtractor,
    entry: ReferenceEntry,
    condition: &RustCfgCondition,
) {
    let containing_fn = extractor.fn_scope.current();
    extractor
        .sites
        .push_conditional_reference(entry, condition.clone(), containing_fn);
}

/// The nesting state one function body replaced.
pub(super) struct FunctionEntry {
    position: SavedPosition,
    receivers: Bindings,
}

/// Record a function or method definition and enter its body.
pub(super) fn enter_function(
    extractor: &mut IrExtractor,
    sig: &syn::Signature,
    associated_with: Option<Arc<str>>,
    declaration: IrRange,
) -> FunctionEntry {
    let kind = match sig.inputs.first() {
        Some(syn::FnArg::Receiver(_)) => SymbolKind::Method,
        _ => SymbolKind::Function,
    };
    FunctionEntry {
        position: extractor.sites.push_declaration(declared(
            kind,
            &sig.ident,
            declaration,
            associated_with,
        )),
        receivers: extractor.receivers.enter(),
    }
}

/// One named declaration: the symbol it states, the identifier that names it,
/// and the extent that writes it.
///
/// Every named route here builds its entry through this one function, so the
/// name range, the declaration range, and the structure kind cannot be paired
/// differently in one route than in another.
fn declared(
    kind: SymbolKind,
    ident: &syn::Ident,
    declaration: IrRange,
    associated_with: Option<Arc<str>>,
) -> DeclarationEntry {
    DeclarationEntry {
        kind,
        name: ident.to_string().into_boxed_str(),
        name_range: range_of(ident.span()),
        declaration_range: declaration,
        associated_with,
    }
}

/// Leave a function body, restoring the enclosing owner and bindings.
pub(super) fn leave_function(extractor: &mut IrExtractor, entry: FunctionEntry) {
    extractor.receivers.leave(entry.receivers);
    extractor.sites.restore(entry.position);
}

/// The `impl` self type the traversal is inside, when it is inside one.
pub(super) fn current_self_type(extractor: &IrExtractor) -> Option<Arc<str>> {
    extractor
        .current_impl
        .as_ref()
        .map(|(self_type, _)| Arc::clone(self_type))
}

/// The trait the traversal is inside, when it is inside one.
pub(super) fn current_trait(extractor: &IrExtractor) -> Option<Arc<str>> {
    extractor.current_trait.clone()
}

/// Record an `impl` block and enter the body it owns.
///
/// A block declares no name, so it states a physical declaration and no
/// definition. Minting one would put an entry in the resolution report that no
/// reference can denote; leaving the block out of the structure table instead
/// would give every associated item inside it the enclosing module as its
/// owner, which is not where the source writes them.
pub(super) fn enter_impl_block(extractor: &mut IrExtractor, declaration: IrRange) -> SavedPosition {
    extractor
        .sites
        .push_unnamed_structure(StructureKind::Impl, declaration)
}

/// Record one named declaration and enter the body it owns.
///
/// The item states its own owner, because the syntax decides it: an `impl` or
/// trait body names one, and a free item names none even where a surrounding
/// method body sits inside an `impl`.
pub(super) fn record_value_item(extractor: &mut IrExtractor, item: ValueItem<'_>) -> SavedPosition {
    extractor.sites.push_declaration(declared(
        item.kind,
        item.ident,
        item.declaration,
        item.associated_with,
    ))
}

/// Record a `mod` item, plus the module reference an external one carries, and
/// enter the body it owns.
///
/// The definition takes the same route every other named declaration takes, so
/// a module's definition covers its bare identifier rather than the `mod foo`
/// the item opens with — the extent a report points at and the one a graph node
/// joins on. The wider `mod foo` range belongs to the reference an external
/// module states, which is a mention of the source it selects and not a name
/// site.
///
/// The visitor enters under the item's own `#[cfg(…)]` gates, so the active
/// condition already states them and neither site re-applies them.
pub(super) fn enter_module(
    extractor: &mut IrExtractor,
    node: &syn::ItemMod,
    declaration: IrRange,
) -> SavedPosition {
    let entry = declared(SymbolKind::Module, &node.ident, declaration, None);
    if node.content.is_none() {
        push_reference(
            extractor,
            ReferenceEntry::path(
                ReferenceKind::Module,
                ReferenceOrigin::ModuleDeclaration,
                entry.name.clone(),
                range_between(node.mod_token.span, node.ident.span()),
                Box::from([entry.name.clone()]),
            ),
        );
    }
    extractor.sites.push_module(ModuleEntry {
        declared: entry,
        declared_paths: declared_paths(&node.attrs),
        inline: node.content.is_some(),
    })
}

/// Record every path one `use` item declares, from the single tree walk.
pub(super) fn record_import(extractor: &mut IrExtractor, node: &syn::ItemUse) {
    observe::record(Observation::ImportWalk(&extractor.file_path));
    let condition = extractor.sites.condition().with(&node.attrs);
    let range = range_between(node.use_token.span, node.semi_token.span);
    for leaf in use_tree_leaves(&node.tree).into_vec() {
        push_conditional_reference(
            extractor,
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
    push_reference(
        extractor,
        ReferenceEntry::path(classified.0, classified.1, text, range, segments),
    );
}

/// Record a method call, with the receiver type when one is established.
pub(super) fn record_method_call(extractor: &mut IrExtractor, node: &syn::ExprMethodCall) {
    let receiver = receiver_type(extractor, &node.receiver);
    let name: Box<str> = node.method.to_string().into_boxed_str();
    push_reference(
        extractor,
        ReferenceEntry {
            kind: ReferenceKind::Call,
            origin: ReferenceOrigin::MethodCall,
            segments: Box::from([name.clone()]),
            text: name,
            range: range_of(node.method.span()),
            alias: None,
            glob: false,
            receiver,
        },
    );
}

/// Record a type named anywhere in the source.
pub(super) fn record_type_path(extractor: &mut IrExtractor, node: &syn::TypePath) {
    let Some(range) = path_range(&node.path) else {
        return;
    };
    let raw = path_segments(&node.path);
    let text = path_text(&raw);
    let segments = qualified(extractor, raw);
    push_reference(
        extractor,
        ReferenceEntry::path(
            ReferenceKind::Type,
            ReferenceOrigin::TypeMention,
            text,
            range,
            segments,
        ),
    );
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
    push_reference(
        extractor,
        ReferenceEntry::path(
            ReferenceKind::Type,
            ReferenceOrigin::TypeMention,
            path_text(&segments),
            range,
            segments,
        ),
    );
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
    push_reference(
        extractor,
        ReferenceEntry::path(
            ReferenceKind::Implementation,
            ReferenceOrigin::Implementation,
            path_text(&segments),
            range,
            segments,
        ),
    );
}

/// Record a macro invocation, whose target this tier never expands.
pub(super) fn record_macro(extractor: &mut IrExtractor, node: &syn::Macro) {
    let Some(range) = path_range(&node.path) else {
        return;
    };
    let segments = path_segments(&node.path);
    push_reference(
        extractor,
        ReferenceEntry::path(
            ReferenceKind::Call,
            ReferenceOrigin::MacroInvocation,
            path_text(&segments),
            range,
            segments,
        ),
    );
}

/// Record the type a `let` binding is known to hold.
pub(super) fn record_local_receiver(extractor: &mut IrExtractor, node: &syn::Local) {
    let stated = annotated_binding(&node.pat)
        .or_else(|| inferred_binding(node))
        .filter(|(_, type_name)| !type_name.is_empty());
    if let Some((name, type_name)) = stated {
        extractor.receivers.record(name, type_name);
    }
}

fn annotated_binding(pat: &syn::Pat) -> Option<(Box<str>, Arc<str>)> {
    let syn::Pat::Type(typed) = pat else {
        return None;
    };
    let syn::Pat::Ident(ident) = typed.pat.as_ref() else {
        return None;
    };
    let named = type_name(&typed.ty)?;
    Some((ident.ident.to_string().into_boxed_str(), named))
}

fn inferred_binding(node: &syn::Local) -> Option<(Box<str>, Arc<str>)> {
    let syn::Pat::Ident(ident) = &node.pat else {
        return None;
    };
    let init = node.init.as_ref()?;
    let named = initializer_type(&init.expr)?;
    Some((ident.ident.to_string().into_boxed_str(), named))
}

/// The type a struct literal or an obvious constructor call establishes.
fn initializer_type(expr: &syn::Expr) -> Option<Arc<str>> {
    match expr {
        syn::Expr::Struct(literal) => last_segment(&literal.path),
        syn::Expr::Call(call) => constructor_type(&call.func),
        _ => None,
    }
}

fn constructor_type(func: &syn::Expr) -> Option<Arc<str>> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let segments = path_segments(&path.path);
    segments
        .len()
        .checked_sub(2)
        .and_then(|index| segments.get(index))
        .map(|named| Arc::from(&**named))
}

fn last_segment(path: &syn::Path) -> Option<Arc<str>> {
    path.segments
        .last()
        .map(|segment| Arc::from(segment.ident.to_string().as_str()))
}

fn type_name(ty: &syn::Type) -> Option<Arc<str>> {
    match ty {
        syn::Type::Path(path) => last_segment(&path.path),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        _ => None,
    }
}

/// The type a method call's receiver is known to hold.
///
/// `self` and `Self` name the type stated by the enclosing `impl` block. Other
/// identifiers are resolved through the local binding environment.
fn receiver_type(extractor: &IrExtractor, receiver: &syn::Expr) -> Option<Arc<str>> {
    let syn::Expr::Path(path) = receiver else {
        return None;
    };
    let named = path.path.get_ident()?;
    match path.path.is_ident("self") || path.path.is_ident(SELF_SEGMENT) {
        true => current_self_type(extractor),
        false => extractor.receivers.lookup(&named.to_string()),
    }
}

/// The shared handle for one type definition's name.
///
/// The fact table, relationship edges, and trait-item owner share this handle.
pub(super) fn type_scope(ident: &syn::Ident) -> Arc<str> {
    Arc::from(ident.to_string().as_str())
}
