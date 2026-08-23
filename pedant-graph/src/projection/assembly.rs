//! The one checked assembler every graph this crate returns is minted by.
//!
//! Identifiers are assigned in fixed passes — unit containers, each unit's
//! sorted sources, report definitions, report references, snapshot dependency
//! edges, then reference candidate edges — so equal plans produce byte-identical
//! output. Every symbolic join the plan states is resolved to an identity this
//! assembly minted, and every record is sealed through the one checked
//! insertion owner, so a reused projection reaches the graph by exactly the path
//! a freshly planned one does.
//!
//! One assembler answers for every language. What an adapter states is a plan;
//! which identity each record takes, whether containment is a forest, and which
//! ceiling refuses are decided here and nowhere else.

use crate::error::GraphBuildError;
use crate::graph::CodeGraph;
use crate::id::{GraphNodeId, GraphReferenceId, position};
use crate::limits::GraphLimits;

use super::draft::{FragmentSlot, ProjectionPlan, ReferenceProjection};
use super::forest;
use super::state::ProjectionState;
use super::validation;

/// One assembled reference record, beside what its candidates pass needs.
///
/// The record travels with the identity it produced and with the projection it
/// was minted from, so the pairing between a reference and its answer is proved
/// once and never derived a second time.
struct AssembledReference<'plan> {
    id: GraphReferenceId,
    source: GraphNodeId,
    projection: &'plan ReferenceProjection,
}

/// Mint one complete graph from one plan.
pub(crate) fn assemble(
    plan: &ProjectionPlan,
    limits: GraphLimits,
) -> Result<CodeGraph, GraphBuildError> {
    let mut state = ProjectionState::new(limits, plan.capacity);
    assemble_containers(&mut state, plan)?;
    assemble_sources(&mut state, plan)?;
    assemble_definitions(&mut state, plan)?;
    assemble_declared_containers(&mut state, plan)?;
    let roots = assemble_containment(&mut state, plan)?;
    forest::check_containment_forest(&state, &roots)?;
    let references = assemble_references(&mut state, plan)?;
    assemble_dependencies(&mut state, plan)?;
    assemble_candidates(&mut state, &references)?;
    Ok(state.finish(plan.tier))
}

/// One container node per planned unit that states one, in plan order.
///
/// This is the first pass, so a stated container takes an identity ahead of
/// every source and every definition. A unit whose container is one of its own
/// declarations mints nothing here: that node is minted with the definitions,
/// and bound by the pass beside them.
fn assemble_containers(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for (index, unit) in plan.units.iter().enumerate() {
        let Some(draft) = unit.container_draft() else {
            continue;
        };
        let container = state.insert_node(draft)?;
        state.bind_container(position(index), container)?;
    }
    Ok(())
}

/// One file node per source the planned unit instantiates, in snapshot order.
///
/// One node per entry, because the placement that made this plan refused a unit
/// stating one path twice. A repeat reaching here would mint a second file node
/// the plan holds no records for and move every dense identity after it.
fn assemble_sources(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for (index, unit) in plan.units.iter().enumerate() {
        let reported = position(index);
        for path in &unit.sources {
            let node = state.insert_node(unit.file_draft(path))?;
            state.bind_file(reported, path, node)?;
        }
    }
    Ok(())
}

/// One node per report definition, in report order.
fn assemble_definitions(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for (index, at) in plan.definitions.iter().enumerate() {
        let stated = position(index);
        let projection = validation::planned_definition(plan, *at, stated)?;
        let unit = validation::fragment_unit(plan, at.fragment)?;
        let source = validation::fragment_source(plan, at.fragment, stated)?;
        let file = validation::source_node(state, unit, source.path())?;
        let node = state.insert_node(projection.draft(file))?;
        state.bind_definition(&projection.identity, node);
    }
    Ok(())
}

/// The container of every unit named by one of its own declarations.
///
/// Run after the definitions pass, because the node this unit is rooted at is
/// one the definitions pass minted. Nothing is minted here: the binding is what
/// lets the containment pass beside it read one container per planned unit,
/// however that container was named.
fn assemble_declared_containers(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for declared in &plan.declarations {
        let definition = declared.definition;
        let at = validation::stated_definition(plan, definition)?;
        let projection = validation::planned_definition(plan, at, definition)?;
        let node = validation::definition_node(state, &projection.identity, definition)?;
        state.bind_container(declared.unit, node)?;
    }
    Ok(())
}

/// The whole containment relation, and the roots it must be a forest over.
///
/// Three statements in one relation: a nested unit sits under the unit that
/// owns it, every instantiated source sits under the unit that reads it, and
/// every definition sits under the definition that owns it or under its unit.
/// Source location never becomes a containment parent.
fn assemble_containment(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<Box<[GraphNodeId]>, GraphBuildError> {
    let roots = contain_units(state, plan)?;
    contain_sources(state, plan)?;
    contain_definitions(state, plan)?;
    Ok(roots)
}

/// Every nested unit under the unit that owns it, answering with the containers
/// no unit owns.
fn contain_units(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<Box<[GraphNodeId]>, GraphBuildError> {
    let mut roots = Vec::new();
    for (index, unit) in plan.units.iter().enumerate() {
        let child = validation::unit_container(state, position(index))?;
        match unit.parent {
            None => roots.push(child),
            Some(owner) => {
                let parent = validation::unit_container(state, owner)?;
                state.contain(parent, child);
            }
        }
    }
    Ok(roots.into_boxed_slice())
}

/// Every instantiated source under the unit-qualified container that reads it.
fn contain_sources(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for (index, unit) in plan.units.iter().enumerate() {
        let reported = position(index);
        let container = validation::unit_container(state, reported)?;
        for path in &unit.sources {
            let node = validation::source_node(state, reported, path)?;
            state.contain(container, node);
        }
    }
    Ok(())
}

/// Logical ownership: a stated parent when there is one, the unit container
/// otherwise.
///
/// The one definition that names its unit's container is skipped: its place in
/// the relation was stated by [`contain_units`], and a node cannot contain
/// itself.
fn contain_definitions(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for (index, at) in plan.definitions.iter().enumerate() {
        let stated = position(index);
        let projection = validation::planned_definition(plan, *at, stated)?;
        let unit = validation::fragment_unit(plan, at.fragment)?;
        let child = validation::definition_node(state, &projection.identity, stated)?;
        let container = validation::unit_container(state, unit)?;
        let parent = match (child == container, &projection.parent) {
            (true, _) => continue,
            (false, Some(owner)) => validation::definition_node(state, owner, stated)?,
            (false, None) => container,
        };
        state.contain(parent, child);
    }
    Ok(())
}

/// One reference record per report reference, in report order.
fn assemble_references<'plan>(
    state: &mut ProjectionState,
    plan: &'plan ProjectionPlan,
) -> Result<Box<[AssembledReference<'plan>]>, GraphBuildError> {
    let mut assembled = Vec::with_capacity(plan.references.len());
    for (index, at) in plan.references.iter().enumerate() {
        let stated = position(index);
        let projection = validation::planned_reference(plan, *at, stated)?;
        let source = reference_source(state, (plan, projection), (*at, stated))?;
        let id = state.insert_reference(projection.draft(source))?;
        assembled.push(AssembledReference {
            id,
            source,
            projection,
        });
    }
    Ok(assembled.into_boxed_slice())
}

/// The enclosing definition when the plan states one, otherwise the
/// unit-qualified file node the site sits in.
///
/// The span is joined to its unit-qualified file node either way. A site whose
/// span names a source only another unit instantiates was refused while the
/// plan was made, so this pass reads a node the assembly has already minted.
fn reference_source(
    state: &ProjectionState,
    planned: (&ProjectionPlan, &ReferenceProjection),
    stated: (FragmentSlot, u32),
) -> Result<GraphNodeId, GraphBuildError> {
    let (plan, projection) = planned;
    let (at, reference) = stated;
    let unit = validation::fragment_unit(plan, at.fragment)?;
    match &projection.enclosing {
        Some(enclosing) => validation::definition_node(state, enclosing, reference),
        None => validation::source_node(state, unit, projection.span.file()),
    }
}

/// One `DependsOn` edge per planned dependency, in snapshot order.
fn assemble_dependencies(
    state: &mut ProjectionState,
    plan: &ProjectionPlan,
) -> Result<(), GraphBuildError> {
    for dependency in &plan.dependencies {
        let source = validation::unit_container(state, dependency.source)?;
        let target = validation::unit_container(state, dependency.target)?;
        state.insert_edge(dependency.draft(source, target))?;
    }
    Ok(())
}

/// One edge per planned candidate, in reference then candidate order.
///
/// Each edge names the record that produced it, and the store links the two in
/// the same step it mints the identity, so no record can claim an edge the
/// graph does not hold.
fn assemble_candidates(
    state: &mut ProjectionState,
    references: &[AssembledReference<'_>],
) -> Result<(), GraphBuildError> {
    for (index, assembled) in references.iter().enumerate() {
        let stated = position(index);
        for candidate in &assembled.projection.candidates {
            let target = validation::definition_node(state, &candidate.target, stated)?;
            state.insert_edge(candidate.draft((assembled.source, assembled.id), target))?;
        }
    }
    Ok(())
}
