//! Where one physical structure appears as a node of one project graph.
//!
//! A graph node identity means nothing on its own: position 7 exists in every
//! graph this index holds, and in each of them it names a different entity. So
//! an instance always carries the project whose graph issued it, and no
//! operation in this crate hands one out without that project beside it.
//!
//! One physical declaration may state several instances. A Cargo library
//! compiled into its own target and linked by a binary is two graphs over the
//! same source, and both of them state the same function. Coalescing those into
//! one entity would throw away the only thing that tells the two answers apart.

use pedant_graph::GraphNodeId;

use super::project::ProjectId;

/// One physical structure's membership in one project graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructureInstance {
    project: ProjectId,
    node: GraphNodeId,
}

impl StructureInstance {
    /// The membership one project's graph states at `node`.
    pub(crate) fn stated(project: ProjectId, node: GraphNodeId) -> Self {
        Self { project, node }
    }

    /// The project whose graph issued this identity.
    pub fn project(self) -> ProjectId {
        self.project
    }

    /// The node this structure is, inside that project's graph.
    pub fn node(self) -> GraphNodeId {
        self.node
    }
}
