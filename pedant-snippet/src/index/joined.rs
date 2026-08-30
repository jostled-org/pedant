//! Every retained structure, sealed with the project graphs that state it.
//!
//! The join runs after the slices resolve rather than while the sources were
//! read, because a membership is a position in a graph that was still being
//! built then: a slice that refused would otherwise have left instances
//! pointing into a graph the index never retained.
//!
//! Both directions of the same fact are sealed here. A structure carries the
//! graphs it appears in; the index carries the declaration each graph node
//! states. Minting them together is what keeps the two from disagreeing.

use super::project::ProjectSlice;
use super::state::FileRecord;
use super::structure::CodeStructure;

/// One physical pass over the store, as the join reads it.
///
/// The two collections are index-aligned by construction: the pass that seals a
/// structure records that structure's definition site in the same step. Handing
/// them over together is what makes the alignment structural rather than a
/// promise two traversals of one store are separately expected to keep.
pub(super) struct StatedStructures {
    /// Every structure, grouped by file and in source order inside each group.
    pub(super) structures: Box<[CodeStructure]>,
    /// Where the definition each structure states sits, in report coordinates,
    /// absent for a declaration that states none.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(super) definitions: Box<[Option<pedant_types::StructureSpan>]>,
}

/// Every retained structure, and both directions of its graph memberships.
pub(super) struct Joined {
    /// The structures, each carrying its own graph memberships.
    pub(super) structures: Box<[CodeStructure]>,
    /// The same memberships, keyed by the graph node that states them.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(super) nodes: Box<[super::membership::NodeMembership]>,
}

/// Seal each structure with the project graphs that state it.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
pub(super) fn of(
    files: &[FileRecord],
    stated: StatedStructures,
    projects: &[ProjectSlice],
) -> Joined {
    let found = super::join::memberships(files, &stated.definitions, projects);
    Joined {
        structures: stated
            .structures
            .into_iter()
            .zip(found.of_structure)
            .map(|(structure, instances)| structure.instanced(instances))
            .collect(),
        nodes: found.of_node,
    }
}

/// No graph producer is linked, so no structure states a graph membership.
#[cfg(not(any(feature = "graph-rust", feature = "graph-go")))]
pub(super) fn of(_: &[FileRecord], stated: StatedStructures, _: &[ProjectSlice]) -> Joined {
    Joined {
        structures: stated.structures,
    }
}
