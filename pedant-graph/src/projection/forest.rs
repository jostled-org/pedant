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

/// Containment must be one forest whose roots are exactly the stated ones.
///
/// Four rules over the stated edges: every edge names nodes this graph holds,
/// no node is contained twice, every node that is not a stated root is
/// contained once, and no chain returns to itself. The roots are the containers
/// of the units no other unit owns, so rootness is read from what the plan
/// stated rather than from where a node happened to be minted.
pub(crate) fn check_containment_forest(
    state: &ProjectionState,
    roots: &[GraphNodeId],
) -> Result<(), GraphBuildError> {
    let parents = stated_parents(state)?;
    let rooted = stated_roots(roots, parents.len())?;
    check_every_node_is_parented(&parents, &rooted)?;
    check_no_unit_root_is_contained(&parents, &rooted)?;
    check_acyclic(&parents)
}

/// One flag per node, raised for each stated root.
///
/// A root this graph holds no node for names nothing, and a node stated as the
/// root of two units would root both of their trees at one container while each
/// unit believed it owned it.
fn stated_roots(roots: &[GraphNodeId], nodes: usize) -> Result<Box<[bool]>, GraphBuildError> {
    let mut rooted = vec![false; nodes];
    for root in roots {
        let index = index_of(root.index());
        let slot = rooted
            .get_mut(index)
            .ok_or(GraphBuildError::UnknownContainmentNode { node: root.index() })?;
        match slot {
            true => return Err(GraphBuildError::SharedUnitRoot { root: root.index() }),
            false => *slot = true,
        }
    }
    Ok(rooted.into_boxed_slice())
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

/// Every node that is not a stated root states a parent.
fn check_every_node_is_parented(
    parents: &[Option<GraphNodeId>],
    rooted: &[bool],
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .zip(rooted)
        .enumerate()
        .find(|(_, (parent, root))| parent.is_none() && !**root)
        .map_or(Ok(()), |(index, _)| {
            Err(GraphBuildError::UnparentedNode {
                node: position(index),
            })
        })
}

/// No stated root is contained by anything.
fn check_no_unit_root_is_contained(
    parents: &[Option<GraphNodeId>],
    rooted: &[bool],
) -> Result<(), GraphBuildError> {
    parents
        .iter()
        .zip(rooted)
        .enumerate()
        .find_map(|(index, (parent, root))| match root {
            true => parent.map(|held| (index, held)),
            false => None,
        })
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
