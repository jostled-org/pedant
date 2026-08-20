//! The one checked walk that turns a bound Go tree into facts.
//!
//! Two ceilings are spent here, and each is checked before the state it would
//! pay for is retained: [`descend`] checks syntax depth before moving the
//! cursor a level deeper, and [`admit`] checks fact capacity before pushing a
//! record. Neither has a second site, so a refusal cannot be routed around, and
//! a refusal returns no inventory at all rather than a truncated one.
//!
//! The walk is a cursor rather than recursion, so a deeply nested source costs
//! heap rather than stack and the depth ceiling is the only thing that stops
//! it.

use ::tree_sitter::TreeCursor;

use crate::go::binding::{GoBindingFact, GoBindingKind, bindings_at};
use crate::go::condition::{GoBuildConditionFact, condition_at};
use crate::go::context::{FactContext, text};
use crate::go::declaration::{GoDeclarationFact, GoDeclarationKind, declarations_at};
use crate::go::error::GoFactError;
use crate::go::frame::Frames;
use crate::go::import::{GoImportFact, import_at};
use crate::go::limits::GoFactLimits;
use crate::go::reference::{GoReferenceFact, reference_at};
use crate::go::scope::{GoScopeFact, GoScopeKind, scope_kind_at};
use crate::go::span::GoFactSpan;
use crate::tree_sitter::Node;

/// Every fact one walk retained, before it is sealed into an inventory.
pub(super) struct Inventory<'source> {
    /// Every package clause the source states. A well-formed file states one;
    /// a recovery tree can state more, and the first is the file's own.
    ///
    /// A list rather than an option so the capacity check has one site: a
    /// scalar exempt from the ceiling would be a second retention rule.
    pub(super) packages: Vec<(&'source str, GoFactSpan)>,
    pub(super) conditions: Vec<GoBuildConditionFact<'source>>,
    pub(super) imports: Vec<GoImportFact<'source>>,
    pub(super) declarations: Vec<GoDeclarationFact<'source>>,
    pub(super) references: Vec<GoReferenceFact<'source>>,
    pub(super) scopes: Vec<GoScopeFact>,
    pub(super) bindings: Vec<GoBindingFact<'source>>,
    counted: u32,
    limit: u32,
}

impl<'source> Inventory<'source> {
    fn new(limit: u32) -> Self {
        Self {
            packages: Vec::new(),
            conditions: Vec::new(),
            imports: Vec::new(),
            declarations: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            counted: 0,
            limit,
        }
    }

    fn name_package(&mut self, named: (&'source str, GoFactSpan)) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.packages, named)
    }

    fn condition(&mut self, fact: GoBuildConditionFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.conditions, fact)
    }

    fn import(&mut self, fact: GoImportFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.imports, fact)
    }

    fn declare(&mut self, fact: GoDeclarationFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.declarations, fact)
    }

    fn refer(&mut self, fact: GoReferenceFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.references, fact)
    }

    fn open(&mut self, fact: GoScopeFact) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.scopes, fact)
    }

    fn bind(&mut self, fact: GoBindingFact<'source>) -> Result<u32, GoFactError> {
        admit(&mut self.counted, self.limit, &mut self.bindings, fact)
    }
}

/// Retain one fact, refusing before the inventory would exceed its ceiling.
///
/// The sole insertion site. Every category routes through it, so the capacity
/// check cannot be skipped by adding a seventh kind of fact.
fn admit<T>(counted: &mut u32, limit: u32, into: &mut Vec<T>, fact: T) -> Result<u32, GoFactError> {
    check_capacity(*counted, limit)?;
    *counted += 1;
    let index = u32::try_from(into.len()).unwrap_or(u32::MAX);
    into.push(fact);
    Ok(index)
}

/// Move one level deeper, refusing before the walk would pass its ceiling.
///
/// The sole descent site, for the same reason [`admit`] is the sole insertion
/// site.
fn descend(
    cursor: &mut TreeCursor<'_>,
    depth: usize,
    limits: GoFactLimits,
) -> Result<bool, GoFactError> {
    check_depth(depth + 1, limits.max_syntax_depth())?;
    Ok(cursor.goto_first_child())
}

/// Whether one more fact fits.
fn check_capacity(counted: u32, limit: u32) -> Result<(), GoFactError> {
    match counted < limit {
        true => Ok(()),
        false => Err(GoFactError::FactCapacityExceeded { limit }),
    }
}

/// Whether one more level fits.
fn check_depth(deeper: usize, limit: u32) -> Result<(), GoFactError> {
    match u64::from(u32::try_from(deeper).unwrap_or(u32::MAX)) <= u64::from(limit) {
        true => Ok(()),
        false => Err(GoFactError::SyntaxDepthExceeded { limit }),
    }
}

/// Walk one bound Go tree once, retaining every fact it states.
pub(super) fn extract<'source>(
    root: Node<'_>,
    source: &'source str,
    limits: GoFactLimits,
) -> Result<Inventory<'source>, GoFactError> {
    let mut inventory = Inventory::new(limits.max_facts());
    let mut frames = Frames::new();
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
            continue;
        }
        if !ascend(&mut frames, &mut cursor, &mut depth) {
            return Ok(inventory);
        }
    }
}

/// Move to the next node after a leaf, closing every context the walk leaves.
fn ascend(frames: &mut Frames, cursor: &mut TreeCursor<'_>, depth: &mut usize) -> bool {
    loop {
        frames.close(cursor.node());
        if cursor.goto_next_sibling() {
            return true;
        }
        if !cursor.goto_parent() {
            return false;
        }
        *depth -= 1;
    }
}

/// Retain every fact one node states, then open the context its children read.
fn enter<'source>(
    inventory: &mut Inventory<'source>,
    frames: &mut Frames,
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
) -> Result<(), GoFactError> {
    let context = frames.context();
    admit_prelude(inventory, node, source)?;
    let opened = admit_declarations(inventory, node, source, context)?;
    let scope = admit_scope(inventory, node, context)?;
    let next = advanced(context, node, field, opened, scope);
    admit_bindings(inventory, node, source, next)?;
    admit_reference(inventory, node, field, source, next)?;
    frames.open(node, context, next);
    Ok(())
}

/// The build predicates, package clause, and imports one node states.
fn admit_prelude<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    source: &'source str,
) -> Result<(), GoFactError> {
    if let Some(condition) = condition_at(node, source, !inventory.packages.is_empty()) {
        inventory.condition(condition)?;
    }
    if let Some(named) = package_at(node, source) {
        inventory.name_package(named)?;
    }
    if let Some(import) = import_at(node, source) {
        inventory.import(import)?;
    }
    Ok(())
}

/// The package clause `node` states, if it states one.
fn package_at<'source>(node: Node<'_>, source: &'source str) -> Option<(&'source str, GoFactSpan)> {
    match node.kind() {
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
    source: &'source str,
    context: FactContext,
) -> Result<Option<(u32, GoDeclarationKind)>, GoFactError> {
    let mut opened = None;
    for fact in declarations_at(node, source, context).iter().copied() {
        opened = Some((inventory.declare(fact)?, fact.kind()));
    }
    Ok(opened)
}

/// The scope one node opens, if it opens one.
fn admit_scope(
    inventory: &mut Inventory<'_>,
    node: Node<'_>,
    context: FactContext,
) -> Result<Option<(u32, GoScopeKind)>, GoFactError> {
    let Some(kind) = scope_kind_at(node) else {
        return Ok(None);
    };
    let parent = match kind {
        GoScopeKind::File => None,
        _ => Some(context.scope),
    };
    let index = inventory.open(GoScopeFact::new(kind, node, parent))?;
    Ok(Some((index, kind)))
}

/// Every name one node binds, naming the receiver its declaration states.
fn admit_bindings<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    source: &'source str,
    context: FactContext,
) -> Result<(), GoFactError> {
    for fact in bindings_at(node, source, context).iter().copied() {
        let index = inventory.bind(fact)?;
        let receiving = (fact.kind() == GoBindingKind::Receiver)
            .then_some(context.declaration)
            .flatten();
        if let Some(declaration) = receiving.and_then(|held| held.try_into().ok()) {
            name_receiver(inventory, declaration, index);
        }
    }
    Ok(())
}

/// Name a method's receiver binding on the declaration that states it.
fn name_receiver(inventory: &mut Inventory<'_>, declaration: usize, binding: u32) {
    if let Some(held) = inventory.declarations.get_mut(declaration) {
        held.bind_receiver(binding);
    }
}

/// The reference one node states, if it states one.
fn admit_reference<'source>(
    inventory: &mut Inventory<'source>,
    node: Node<'_>,
    field: Option<&str>,
    source: &'source str,
    context: FactContext,
) -> Result<(), GoFactError> {
    if let Some(fact) = reference_at(node, field, source, context) {
        inventory.refer(fact)?;
    }
    Ok(())
}

/// The context one node's children read.
fn advanced(
    context: FactContext,
    node: Node<'_>,
    field: Option<&str>,
    opened: Option<(u32, GoDeclarationKind)>,
    scope: Option<(u32, GoScopeKind)>,
) -> FactContext {
    let mut next = context;
    next.binds_names = context.binds_names || binds_names(node, field);
    next.parameter_role = match scope {
        // A callable resets the role, so a function type written inside a
        // result list does not label its own parameters as results.
        Some(_) => parameter_role(node, field),
        None => parameter_role(node, field).or(context.parameter_role),
    };
    if let Some((index, kind)) = opened {
        next.declaration = Some(index);
        next.declaration_kind = Some(kind);
    }
    if let Some((index, kind)) = scope {
        next.scope = index;
        next.scope_kind = kind;
    }
    if anonymous_composite(node) {
        next.declaration_kind = None;
    }
    next
}

/// The role a parameter list gives the names it holds.
fn parameter_role(node: Node<'_>, field: Option<&str>) -> Option<GoBindingKind> {
    match (node.kind(), field) {
        ("parameter_list", Some("receiver")) => Some(GoBindingKind::Receiver),
        ("parameter_list", Some("parameters")) => Some(GoBindingKind::Parameter),
        ("parameter_list", Some("result")) => Some(GoBindingKind::Result),
        _ => None,
    }
}

/// Whether the identifiers beneath one node are names being bound.
fn binds_names(node: Node<'_>, field: Option<&str>) -> bool {
    node.kind() == "expression_list"
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
fn anonymous_composite(node: Node<'_>) -> bool {
    matches!(node.kind(), "struct_type" | "interface_type")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() != "type_spec")
}
