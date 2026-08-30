//! The one checked walk that turns a bound Go tree into facts.
//!
//! One ceiling is spent here, and it is checked before the state it would pay
//! for is retained: [`descend`] proves syntax depth before it moves the cursor
//! a level deeper, and it is the sole descent site, so a refusal cannot be
//! routed around. The other ceiling belongs to the inventory this walk fills,
//! which refuses its own excess the same way; either refusal returns no
//! inventory at all rather than a truncated one.
//!
//! The walk is a cursor rather than recursion, so a deeply nested source costs
//! heap rather than stack and the depth ceiling is the only thing that stops
//! it. Every recognizer it calls holds to the same rule: a reader that followed
//! a type chain by recursion would run before [`descend`] had paid for that
//! chain, and would take the stack down beneath any ceiling at all.

use ::tree_sitter::TreeCursor;

use crate::go::binding::{GoBindingKind, bindings_at};
use crate::go::condition::condition_at;
use crate::go::context::{FactContext, text};
use crate::go::declaration::{GoDeclarationKind, declarations_at};
use crate::go::error::GoFactError;
use crate::go::frame::Frames;
use crate::go::import::import_at;
use crate::go::inventory::Inventory;
use crate::go::limits::GoFactLimits;
use crate::go::reference::reference_at;
use crate::go::retention::GoFactScope;
use crate::go::scope::{GoScopeFact, GoScopeKind, scope_kind_at};
use crate::go::signature::signature_terms_at;
use crate::go::span::GoFactSpan;
use crate::structure::limits::admits_depth;
use crate::tree_sitter::{Node, advance};

/// Move one level deeper, refusing before the walk would pass its ceiling.
///
/// The sole descent site, for the same reason the inventory's own admission is
/// the sole insertion site.
fn descend(
    cursor: &mut TreeCursor<'_>,
    depth: usize,
    limits: GoFactLimits,
) -> Result<bool, GoFactError> {
    check_depth(depth + 1, limits.max_syntax_depth())?;
    Ok(cursor.goto_first_child())
}

/// Whether one more level fits.
///
/// The comparison is [`admits_depth`], the crate's one depth predicate, which
/// the structure builder asks as well; what is stated here is the Go refusal,
/// because a refusal names the walk that made it. Two copies of the comparison
/// meant one could be widened and leave the other walk bounded differently.
fn check_depth(deeper: usize, limit: u32) -> Result<(), GoFactError> {
    match admits_depth(deeper, limit) {
        true => Ok(()),
        false => Err(GoFactError::SyntaxDepthExceeded { limit }),
    }
}

/// Walk one bound Go tree once, retaining every fact `retained` names.
///
/// The file scope is opened here rather than recognized at a node kind, so the
/// context stack's base names a scope this inventory holds and index zero is a
/// fact rather than an assumption.
pub(super) fn extract<'source>(
    root: Node<'_>,
    source: &'source str,
    limits: GoFactLimits,
    retained: GoFactScope,
) -> Result<Inventory<'source>, GoFactError> {
    let mut inventory = Inventory::new(limits.max_facts(), retained);
    let file = inventory.open(GoScopeFact::new(GoScopeKind::File, root, None))?;
    let mut frames = Frames::new(file);
    let mut cursor = root.walk();
    let mut depth = 0_usize;
    loop {
        let node = cursor.node();
        enter(
            &mut inventory,
            &mut frames,
            node,
            cursor.field_name(),
            source,
        )?;
        if node.child_count() > 0 && descend(&mut cursor, depth, limits)? {
            depth += 1;
            inventory.entered(depth);
            continue;
        }
        // The ascent is the crate's shared one; what this walk adds is closing
        // each context the nodes it leaves had opened.
        if !advance(&mut cursor, &mut depth, |node| frames.close(node)) {
            return Ok(inventory);
        }
    }
}

/// Retain every fact one node states, then open the context its children read.
///
/// The node's kind is asked once and handed to every recognizer. Tree-sitter
/// answers `kind` with an FFI call and a fresh UTF-8 validation of the result,
/// and ten recognizers each asking for themselves paid that per node in the
/// tree.
fn enter<'source>(
    inventory: &mut Inventory<'source>,
    frames: &mut Frames,
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
) -> Result<(), GoFactError> {
    let kind = node.kind();
    let context = frames.context();
    let opened = admit_declarations(inventory, node, kind, source, context)?;
    let scope = admit_scope(inventory, node, kind, context)?;
    let next = advanced(context, node, (kind, field), opened, scope);
    admit_surroundings(inventory, node, (kind, field), source, next)?;
    frames.open(node, context, next);
    Ok(())
}

/// Every fact beside the declarations and the scopes that place them: the
/// prelude a file opens with, the names a node binds, and the reference it
/// states.
///
/// Each scope calls only the recognizers it retains from. A declarations-only
/// walk calls none of them; a structure walk calls the package recognizer
/// alone, because the package clause is the one part of the prelude a structure
/// inventory states.
fn admit_surroundings<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    written: (&str, Option<&str>),
    source: &'source str,
    context: FactContext,
) -> Result<(), GoFactError> {
    let (kind, field) = written;
    match inventory.retained() {
        GoFactScope::DeclarationsOnly => Ok(()),
        GoFactScope::DeclaredStructures => admit_package(inventory, node, kind, source),
        GoFactScope::Everything => {
            admit_prelude(inventory, node, kind, source)?;
            admit_bindings(inventory, node, kind, source, context)?;
            admit_reference(inventory, node, kind, field, source, context)
        }
    }
}

/// The build predicates, package clause, and imports one node states.
fn admit_prelude<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    kind: &str,
    source: &'source str,
) -> Result<(), GoFactError> {
    if let Some(condition) = condition_at(node, kind, source, !inventory.packages.is_empty()) {
        inventory.condition(condition)?;
    }
    admit_package(inventory, node, kind, source)?;
    if let Some(import) = import_at(node, kind, source) {
        inventory.import(import)?;
    }
    Ok(())
}

/// The package clause one node states, retained on its own.
///
/// A site of its own rather than a line inside [`admit_prelude`], because two
/// scopes retain the clause and only one of them retains the prelude around it.
fn admit_package<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    kind: &str,
    source: &'source str,
) -> Result<(), GoFactError> {
    if let Some(named) = package_at(node, kind, source) {
        inventory.name_package(named)?;
    }
    Ok(())
}

/// The package clause `node` states, if it states one.
fn package_at<'source>(
    node: Node<'_>,
    kind: &str,
    source: &'source str,
) -> Option<(&'source str, GoFactSpan)> {
    match kind {
        "package_clause" => {
            let named = node.named_child(0)?;
            Some((text(named, source), GoFactSpan::of_node(named)))
        }
        _ => None,
    }
}

/// Every declaration one node states, and the last of them.
fn admit_declarations<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    kind: &str,
    source: &'source str,
    context: FactContext,
) -> Result<Option<(u32, GoDeclarationKind)>, GoFactError> {
    let mut opened = None;
    for fact in declarations_at(node, kind, source, context).iter().copied() {
        let index = inventory.declare(fact)?;
        admit_signature(inventory, node, source, (index, fact.kind()))?;
        opened = Some((index, fact.kind()));
    }
    Ok(opened)
}

/// Every signature term one callable declaration states.
///
/// A declaration that is no callable states none: a type, a constant, a
/// variable, a field, and an embedded element all write no parameter list, and
/// asking a node for one it does not have would state a signature of nothing.
/// Only a whole-inventory walk states them at all, because a signature term is
/// evidence for a method set rather than for a source unit or a structure.
fn admit_signature<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    source: &'source str,
    declared: (u32, GoDeclarationKind),
) -> Result<(), GoFactError> {
    let (index, kind) = declared;
    let stating = matches!(inventory.retained(), GoFactScope::Everything) && is_callable(kind);
    if !stating {
        return Ok(());
    }
    for fact in signature_terms_at(node, source, index).iter().copied() {
        inventory.sign(fact)?;
    }
    Ok(())
}

/// Whether one declaration kind writes a signature.
///
/// Every variant is named. Go interface relations are proved from signature
/// terms, so a twelfth kind that quietly fell through would state a method set
/// missing one method and prove a relation the corpus does not hold.
fn is_callable(kind: GoDeclarationKind) -> bool {
    match kind {
        GoDeclarationKind::Function
        | GoDeclarationKind::Method
        | GoDeclarationKind::InterfaceMethod => true,
        GoDeclarationKind::Struct
        | GoDeclarationKind::Interface
        | GoDeclarationKind::DefinedType
        | GoDeclarationKind::TypeAlias
        | GoDeclarationKind::Constant
        | GoDeclarationKind::Variable
        | GoDeclarationKind::Field
        | GoDeclarationKind::EmbeddedField => false,
    }
}

/// The scope one node opens, if it opens one.
fn admit_scope(
    inventory: &mut Inventory<'_>,
    node: Node<'_>,
    kind: &str,
    context: FactContext,
) -> Result<Option<(u32, GoScopeKind)>, GoFactError> {
    let Some(opened) = scope_kind_at(kind) else {
        return Ok(None);
    };
    let parent = match opened {
        // The file scope is the walk's own, opened before the first node, so
        // nothing recognized here can hold it.
        GoScopeKind::File => None,
        GoScopeKind::Declaration | GoScopeKind::Block => Some(context.scope),
    };
    let index = inventory.open(GoScopeFact::new(opened, node, parent))?;
    Ok(Some((index, opened)))
}

/// Every name one node binds, naming the receiver its declaration states.
fn admit_bindings<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    kind: &str,
    source: &'source str,
    context: FactContext,
) -> Result<(), GoFactError> {
    for fact in bindings_at(node, kind, source, context).iter().copied() {
        let index = inventory.bind(fact)?;
        let receiving = (fact.kind() == GoBindingKind::Receiver)
            .then_some(context.declaration)
            .flatten();
        if let Some(declaration) = receiving {
            name_receiver(inventory, declaration, index)?;
        }
    }
    Ok(())
}

/// Name a method's receiver binding on the declaration that states it.
///
/// Filled after the fact is retained, because a receiver is a binding of its
/// own and the walk reaches it inside the declaration it belongs to.
///
/// Refuses rather than passing over a miss. `declaration` is an index [`admit`]
/// minted against this same inventory, so nothing here should fail — but the
/// lookup is fallible in the type system, and a dropped link leaves a method
/// answering "no receiver", which reads exactly like a plain function and
/// states no failure at all.
fn name_receiver(
    inventory: &mut Inventory<'_>,
    declaration: u32,
    binding: u32,
) -> Result<(), GoFactError> {
    let held = usize::try_from(declaration)
        .ok()
        .and_then(|index| inventory.declarations.get_mut(index))
        .ok_or(GoFactError::DeclarationMapping { declaration })?;
    held.bind_receiver(binding);
    Ok(())
}

/// The reference one node states, if it states one.
fn admit_reference<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    kind: &str,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Result<(), GoFactError> {
    if let Some(fact) = reference_at(node, kind, field, source, context) {
        inventory.refer(fact)?;
    }
    Ok(())
}

/// The context one node's children read.
fn advanced(
    context: FactContext,
    node: Node<'_>,
    written: (&str, Option<&str>),
    opened: Option<(u32, GoDeclarationKind)>,
    scope: Option<(u32, GoScopeKind)>,
) -> FactContext {
    let (kind, field) = written;
    let role = parameter_role(kind, field);
    let mut next = context;
    next.binds_names = context.binds_names || binds_names(node, kind, field);
    next.parameter_role = match scope {
        // A callable resets the role, so a function type written inside a
        // result list does not label its own parameters as results.
        Some(_) => role,
        None => role.or(context.parameter_role),
    };
    if let Some((index, kind)) = opened {
        next.declaration = Some(index);
        next.declaration_kind = Some(kind);
    }
    if let Some((index, kind)) = scope {
        next.scope = index;
        next.scope_kind = kind;
    }
    if anonymous_composite(node, kind) {
        next.declaration_kind = None;
    }
    next
}

/// The role a parameter list gives the names it holds.
fn parameter_role(kind: &str, field: Option<&str>) -> Option<GoBindingKind> {
    match (kind, field) {
        ("parameter_list", Some("receiver")) => Some(GoBindingKind::Receiver),
        ("parameter_list", Some("parameters")) => Some(GoBindingKind::Parameter),
        ("parameter_list", Some("result")) => Some(GoBindingKind::Result),
        _ => None,
    }
}

/// Whether the identifiers beneath one node are names being bound.
fn binds_names(node: Node<'_>, kind: &str, field: Option<&str>) -> bool {
    kind == "expression_list"
        && field == Some("left")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "short_var_declaration")
}

/// Whether a struct or interface body belongs to no named type.
///
/// An anonymous composite written inside a field, a parameter, or a variable
/// states members of nothing this model names, so its own members must not be
/// attributed to the named type that happens to hold it.
fn anonymous_composite(node: Node<'_>, kind: &str) -> bool {
    matches!(kind, "struct_type" | "interface_type")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() != "type_spec")
}
