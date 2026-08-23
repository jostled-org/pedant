//! Containment is one acyclic forest whose roots are exactly the unit
//! containers.
//!
//! Split from the join validators beside it because it is a different subject:
//! every other refusal answers one stated join in isolation, and these four
//! rules answer the shape of the whole containment relation at once. The
//! reasoning [`super::validation`] gives for checking a producer's own
//! invariants applies here unchanged — a graph that silently accepted a cycle
//! would be indistinguishable from a repository that has none.

use crate::containment::ContainmentEdge;
use crate::error::GraphBuildError;
use crate::id::{GraphNodeId, index_of, position};

use super::state::ProjectionState;

/// Where one node stands in the containment ancestor walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    /// Not yet reached.
    Pending,
    /// On the chain currently being walked.
    Active,
    /// Proved acyclic by an earlier walk.
    Done,
}

/// Containment must be one forest whose roots are exactly the unit containers.
///
/// Four rules over the stated edges: every edge names nodes this graph holds,
/// no node is contained twice, every node below the unit containers is
/// contained once, and no chain returns to itself. The unit containers are the
/// first `units` nodes the assembly minted, so a node is a root exactly when
/// its position is below that count.
pub(crate) fn check_containment_forest(
    state: &ProjectionState,
    units: usize,
) -> Result<(), GraphBuildError> {
    let parents = stated_parents(state)?;
    check_every_node_is_parented(&parents, units)?;
    check_no_unit_root_is_contained(&parents, units)?;
    check_acyclic(&parents)
}

/// One parent slot per node, refusing the second edge that claims a child.
fn stated_parents(state: &ProjectionState) -> Result<Box<[Option<GraphNodeId>]>, GraphBuildError> {
    let mut parents: Vec<Option<GraphNodeId>> = vec![None; state.node_count()];
    for edge in state.containment() {
        let slot = parent_slot(&mut parents, edge)?;
        match slot {
            Some(existing) => {
                return Err(GraphBuildError::MultiplyContained {
                    parent: existing.index(),
                    child: edge.child().index(),
                });
            }
            None => *slot = Some(edge.parent()),
        }
    }
    Ok(parents.into_boxed_slice())
}

/// The slot one containment edge's child owns.
fn parent_slot<'a>(
    parents: &'a mut [Option<GraphNodeId>],
    edge: &ContainmentEdge,
) -> Result<&'a mut Option<GraphNodeId>, GraphBuildError> {
    let child = edge.child();
    parents
        .get_mut(index_of(child.index()))
        .ok_or(GraphBuildError::UnknownContainmentNode {
            node: child.index(),
        })
}

/// Every node below the unit containers states a parent.
fn check_every_node_is_parented(
    parents: &[Option<GraphNodeId>],
    units: usize,
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .enumerate()
        .skip(units)
        .find(|(_, parent)| parent.is_none())
        .map_or(Ok(()), |(index, _)| {
            Err(GraphBuildError::UnparentedNode {
                node: position(index),
            })
        })
}

/// No unit container is contained by anything.
fn check_no_unit_root_is_contained(
    parents: &[Option<GraphNodeId>],
    units: usize,
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .enumerate()
        .take(units)
        .find_map(|(index, parent)| parent.map(|held| (index, held)))
        .map_or(Ok(()), |(index, parent)| {
            Err(GraphBuildError::RootHasParent {
                root: position(index),
                parent: parent.index(),
            })
        })
}

/// No containment chain returns to a node it already visited.
fn check_acyclic(parents: &[Option<GraphNodeId>]) -> Result<(), GraphBuildError> {
    let mut visits = vec![Visit::Pending; parents.len()];
    let mut chain: Vec<usize> = Vec::new();
    for start in 0..parents.len() {
        walk_ancestors(parents, &mut visits, &mut chain, start)?;
    }
    Ok(())
}

fn walk_ancestors(
    parents: &[Option<GraphNodeId>],
    visits: &mut [Visit],
    chain: &mut Vec<usize>,
    start: usize,
) -> Result<(), GraphBuildError> {
    match visit_of(visits, start)? {
        Visit::Pending => (),
        Visit::Active | Visit::Done => return Ok(()),
    }
    chain.clear();
    let mut current = Some(start);
    let mut cycle = None;
    while let Some(index) = current {
        let visit = visit_of(visits, index)?;
        cycle = (visit == Visit::Active).then_some(index);
        match visit {
            Visit::Pending => (),
            Visit::Active | Visit::Done => break,
        }
        mark(visits, index, Visit::Active)?;
        chain.push(index);
        current = parents
            .get(index)
            .and_then(|parent| *parent)
            .map(|parent| index_of(parent.index()));
    }
    for index in chain.drain(..) {
        mark(visits, index, Visit::Done)?;
    }
    match cycle {
        Some(index) => Err(GraphBuildError::ContainmentCycle {
            node: position(index),
        }),
        None => Ok(()),
    }
}

/// Where the walk left one node.
///
/// A position outside the node set is a stated parent this graph holds no node
/// for, which is the one join a walk that answered `Done` would accept in
/// silence.
fn visit_of(visits: &[Visit], index: usize) -> Result<Visit, GraphBuildError> {
    visits
        .get(index)
        .copied()
        .ok_or(GraphBuildError::UnknownContainmentNode {
            node: position(index),
        })
}

/// Record where the walk left one node.
fn mark(visits: &mut [Visit], index: usize, visit: Visit) -> Result<(), GraphBuildError> {
    match visits.get_mut(index) {
        Some(slot) => {
            *slot = visit;
            Ok(())
        }
        None => Err(GraphBuildError::UnknownContainmentNode {
            node: position(index),
        }),
    }
}
