//! The definition inventory one snapshot produces, and the tables name lookup
//! reads it through.
//!
//! Every definition site of every module instance becomes one report
//! definition, so one physical source instantiated under two units yields two
//! independent identities from one parse.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{DefinitionHandle, ResolutionReportBuilder, ResolutionUnitHandle, SourceSpan};

use crate::ir::cfg::RustCfgCondition;
use crate::ir::sites::DefinitionSite;
use crate::resolution::rust::snapshot::{RustResolutionSnapshot, RustSource};

use super::coordinates::LineIndex;
use super::error::RustResolutionError;
use super::graph::Graph;
#[cfg(feature = "semantic")]
use super::promotion::PromotionSite;
use super::units::Units;

/// The answer a lookup with no entry returns.
const EMPTY: &[usize] = &[];

/// A name table scoped by node or by owning type.
type Scoped<K> = BTreeMap<K, BTreeMap<Box<str>, Box<[usize]>>>;

/// A name table under construction.
type ScopedDraft<K> = BTreeMap<K, BTreeMap<Box<str>, Vec<usize>>>;

/// One definition as the report holds it.
pub(super) struct DefinitionSlot {
    pub(super) node: usize,
    pub(super) name: Box<str>,
    pub(super) handle: DefinitionHandle,
    pub(super) condition: RustCfgCondition,
    /// Where the definition sits, as a later tier addresses it.
    ///
    /// Recorded here rather than re-derived, so the site Tier 2 joins on is
    /// the one this pass stated. Deriving it a second time meant a second copy
    /// of the scope filter below, and a definition the two copies disagreed
    /// about would silently promote nothing.
    #[cfg(feature = "semantic")]
    pub(super) site: PromotionSite,
}

/// Everything name lookup needs about the snapshot's definitions.
pub(super) struct Index {
    slots: Box<[DefinitionSlot]>,
    positions: BTreeMap<(usize, usize), usize>,
    names: Scoped<usize>,
    modules: Scoped<usize>,
    associated: Scoped<Box<str>>,
    module_slots: Box<[Option<usize>]>,
}

impl Index {
    /// One definition slot.
    pub(super) fn slot(&self, slot: usize) -> Option<&DefinitionSlot> {
        self.slots.get(slot)
    }

    /// Every definition slot, in the order the report states them.
    #[cfg(feature = "semantic")]
    pub(super) fn slots(&self) -> &[DefinitionSlot] {
        &self.slots
    }

    /// The slot one definition site of one node produced.
    pub(super) fn at(&self, node: usize, site: usize) -> Option<usize> {
        self.positions.get(&(node, site)).copied()
    }

    /// Every definition `name` selects directly inside `node`.
    pub(super) fn names_in(&self, node: usize, name: &str) -> &[usize] {
        select(&self.names, &node, name)
    }

    /// Every child module node `name` selects inside `node`.
    pub(super) fn modules_in(&self, node: usize, name: &str) -> &[usize] {
        select(&self.modules, &node, name)
    }

    /// Every associated item `member` selects on the type named `owner`.
    pub(super) fn associated(&self, owner: &str, member: &str) -> &[usize] {
        self.associated
            .get(owner)
            .and_then(|table| table.get(member))
            .map_or(EMPTY, |found| found)
    }

    /// The definition of the `mod` item that selected `node`.
    pub(super) fn module_slot(&self, node: usize) -> Option<usize> {
        self.module_slots.get(node).copied().flatten()
    }
}

/// Accumulating tables, before they are frozen into an [`Index`].
struct Draft {
    slots: Vec<DefinitionSlot>,
    positions: BTreeMap<(usize, usize), usize>,
    names: ScopedDraft<usize>,
    associated: ScopedDraft<Box<str>>,
}

/// What one node contributes: its unit handle and the conditions its
/// definitions inherit.
struct NodeContext<'a> {
    node: usize,
    unit: &'a ResolutionUnitHandle,
    /// The snapshot-local unit index, which is how a later tier names a site.
    #[cfg(feature = "semantic")]
    unit_index: usize,
    /// The node's source position in the snapshot's sorted store.
    #[cfg(feature = "semantic")]
    file: usize,
    condition: RustCfgCondition,
    source: &'a RustSource,
    lines: &'a LineIndex,
}

/// Add every definition to `builder` and index what it produced.
pub(super) fn build(
    builder: &mut ResolutionReportBuilder,
    snapshot: &RustResolutionSnapshot,
    corpus: (&Graph, &Units, &[LineIndex]),
) -> Result<Index, RustResolutionError> {
    let (graph, units, lines) = corpus;
    let mut draft = Draft {
        slots: Vec::new(),
        positions: BTreeMap::new(),
        names: ScopedDraft::new(),
        associated: ScopedDraft::new(),
    };
    for node in 0..graph.nodes.len() {
        add_node(builder, (snapshot, graph, units, lines), &mut draft, node)?;
    }
    Ok(freeze(draft, graph))
}

fn add_node(
    builder: &mut ResolutionReportBuilder,
    corpus: (&RustResolutionSnapshot, &Graph, &Units, &[LineIndex]),
    draft: &mut Draft,
    node: usize,
) -> Result<(), RustResolutionError> {
    let (snapshot, graph, units, lines) = corpus;
    let Some(entry) = graph.nodes.get(node) else {
        return Ok(());
    };
    let (Some(source), Some(unit), Some(activation), Some(indexed)) = (
        graph.source(snapshot, node),
        units.handles.get(entry.unit),
        units.conditions.get(entry.unit),
        lines.get(entry.file),
    ) else {
        return Ok(());
    };
    let context = NodeContext {
        node,
        unit,
        #[cfg(feature = "semantic")]
        unit_index: entry.unit,
        #[cfg(feature = "semantic")]
        file: entry.file,
        condition: entry.condition.and(activation),
        lines: indexed,
        source,
    };
    for (site, definition) in source.ir().definition_sites.iter().enumerate() {
        if definition.scope == entry.scope {
            add_definition(builder, graph, draft, (&context, site, definition))?;
        }
    }
    Ok(())
}

fn add_definition(
    builder: &mut ResolutionReportBuilder,
    graph: &Graph,
    draft: &mut Draft,
    stated: (&NodeContext<'_>, usize, &DefinitionSite),
) -> Result<(), RustResolutionError> {
    let (context, site, definition) = stated;
    let Some(span) = span_of(context, definition) else {
        return Ok(());
    };
    let parent = parent_slot(graph, draft, (context, definition));
    let owner = parent.and_then(|slot| draft.slots.get(slot));
    #[cfg(feature = "semantic")]
    let promotion = PromotionSite::new(context.unit_index, context.file, &span);
    let handle = builder.add_definition(
        context.unit,
        definition.kind,
        Arc::from(&*definition.name),
        span,
        owner.map(|slot| &slot.handle),
    )?;
    let slot = draft.slots.len();
    draft.slots.push(DefinitionSlot {
        node: context.node,
        name: definition.name.clone(),
        handle,
        condition: context.condition.and(definition.condition()),
        #[cfg(feature = "semantic")]
        site: promotion,
    });
    record(draft, (context.node, site, slot), definition);
    Ok(())
}

fn record(draft: &mut Draft, position: (usize, usize, usize), definition: &DefinitionSite) {
    let (node, site, slot) = position;
    draft.positions.insert((node, site), slot);
    push(&mut draft.names, node, &definition.name, slot);
    if let Some(owner) = definition.associated_with.as_ref() {
        push(&mut draft.associated, owner.clone(), &definition.name, slot);
    }
}

/// Record one slot under `name`, allocating the boxed key only when the name
/// is new to this scope rather than on every site.
fn push<K: Ord>(table: &mut ScopedDraft<K>, key: K, name: &str, slot: usize) {
    let scope = table.entry(key).or_default();
    match scope.get_mut(name) {
        Some(slots) => slots.push(slot),
        None => {
            scope.insert(Box::from(name), vec![slot]);
        }
    }
}

/// The definition that owns one site: its lexical owner when the source states
/// one, and otherwise the `mod` item that selected this node.
fn parent_slot(
    graph: &Graph,
    draft: &Draft,
    stated: (&NodeContext<'_>, &DefinitionSite),
) -> Option<usize> {
    let (context, definition) = stated;
    match definition.parent {
        Some(parent) => lexical_owner(graph, draft, (context, parent)),
        None => declaring_slot(graph, draft, context.node),
    }
}

fn lexical_owner(graph: &Graph, draft: &Draft, stated: (&NodeContext<'_>, usize)) -> Option<usize> {
    let (context, parent) = stated;
    let entry = graph.nodes.get(context.node)?;
    let scope = context.source.ir().definition_sites.get(parent)?.scope;
    let owner = graph.node_for_scope(context.node, entry.file, scope)?;
    draft.positions.get(&(owner, parent)).copied()
}

fn declaring_slot(graph: &Graph, draft: &Draft, node: usize) -> Option<usize> {
    let declaration = graph.nodes.get(node)?.declaration?;
    draft
        .positions
        .get(&(declaration.node, declaration.definition))
        .copied()
}

fn span_of(context: &NodeContext<'_>, definition: &DefinitionSite) -> Option<SourceSpan> {
    context.lines.span(
        context.source.text(),
        context.source.shared_path(),
        definition.range,
    )
}

fn freeze(draft: Draft, graph: &Graph) -> Index {
    let mut modules: ScopedDraft<usize> = ScopedDraft::new();
    let module_slots: Box<[Option<usize>]> = (0..graph.nodes.len())
        .map(|node| register_module(&draft, &mut modules, graph, node))
        .collect();
    Index {
        slots: draft.slots.into_boxed_slice(),
        positions: draft.positions,
        names: sealed(draft.names),
        modules: sealed(modules),
        associated: sealed(draft.associated),
        module_slots,
    }
}

/// Bind one node to the `mod` definition that selected it, and make that
/// definition's name select this node inside the declaring module.
fn register_module(
    draft: &Draft,
    modules: &mut ScopedDraft<usize>,
    graph: &Graph,
    node: usize,
) -> Option<usize> {
    let declaration = graph.nodes.get(node)?.declaration?;
    let slot = draft
        .positions
        .get(&(declaration.node, declaration.definition))
        .copied()?;
    let named = draft.slots.get(slot)?;
    push(modules, declaration.node, &named.name, node);
    Some(slot)
}

fn select<'a, K: Ord>(table: &'a Scoped<K>, key: &K, name: &str) -> &'a [usize] {
    table
        .get(key)
        .and_then(|scope| scope.get(name))
        .map_or(EMPTY, |found| found)
}

fn sealed<K: Ord>(entries: ScopedDraft<K>) -> Scoped<K> {
    entries
        .into_iter()
        .map(|(key, table)| (key, freeze_names(table)))
        .collect()
}

fn freeze_names(table: BTreeMap<Box<str>, Vec<usize>>) -> BTreeMap<Box<str>, Box<[usize]>> {
    table
        .into_iter()
        .map(|(name, slots)| (name, slots.into_boxed_slice()))
        .collect()
}
