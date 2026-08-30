//! What a graph answer says about one node it reached.
//!
//! Every node projects, and every projection keeps its graph identity beside
//! the project that issued it. A node this index joined to a physical
//! declaration is that declaration, described exactly as search and outline
//! describe it. A file node, a container, or a declaration whose source states
//! no structure is still a member of the answer, carried as the typed graph
//! entity it is.
//!
//! Nothing is dropped for lacking a structure, and nothing loses its identity
//! for having one. An answer that left out the nodes it could not name would
//! report a smaller topology than the graph states; one that dropped the node
//! identity of the nodes it could name would leave a caller holding edges whose
//! endpoints match nothing in the same answer.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_graph::{GraphNodeId, GraphNodeKind, GraphNodeLocation};
use pedant_types::Language;
use serde::Serialize;

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceIndex, ProjectHandle, ProjectId, ProjectSlice,
};

use super::super::describe::Describer;
use super::super::record::StructureDescriptor;

/// One graph node this index joined to a physical declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StructureEntity {
    project: ProjectHandle,
    node: GraphNodeId,
    structure: StructureDescriptor,
}

impl StructureEntity {
    /// The project graph that issued this identity.
    pub fn project(&self) -> ProjectHandle {
        self.project
    }

    /// This declaration's identity inside that graph.
    pub fn node(&self) -> GraphNodeId {
        self.node
    }

    /// What every navigation answer says about the declaration.
    pub fn structure(&self) -> &StructureDescriptor {
        &self.structure
    }
}

/// One graph node this index states no physical declaration for.
///
/// The name is the graph's own handle on it rather than a copy. A file node's
/// name is its whole normalized path, and every unjoined node of every answer
/// carries one — beside a kind and a location that are already refcount bumps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GraphEntity {
    project: ProjectHandle,
    node: GraphNodeId,
    language: Language,
    name: Arc<str>,
    kind: GraphNodeKind,
    location: Option<GraphNodeLocation>,
}

impl GraphEntity {
    /// The project graph that issued this identity.
    pub fn project(&self) -> ProjectHandle {
        self.project
    }

    /// This entity's identity inside that graph.
    pub fn node(&self) -> GraphNodeId {
        self.node
    }

    /// The language of the unit the node belongs to.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The declared name, or the normalized path for a file node.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What kind of entity the graph states it is.
    pub fn kind(&self) -> &GraphNodeKind {
        &self.kind
    }

    /// Where its bytes sit, when it has any.
    pub fn location(&self) -> Option<&GraphNodeLocation> {
        self.location.as_ref()
    }
}

/// One member of a graph answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "entity", rename_all = "snake_case")]
pub enum NavigationEntity {
    /// A physical declaration this index retained.
    Structure(Box<StructureEntity>),
    /// A graph member this index retained no declaration for.
    GraphNode(Box<GraphEntity>),
}

impl NavigationEntity {
    /// The project graph that issued this member's identity.
    pub fn project(&self) -> ProjectHandle {
        match self {
            Self::Structure(held) => held.project(),
            Self::GraphNode(held) => held.project(),
        }
    }

    /// The member's identity inside that graph.
    pub fn node(&self) -> GraphNodeId {
        match self {
            Self::Structure(held) => held.node(),
            Self::GraphNode(held) => held.node(),
        }
    }

    /// The declaration this member is, where this index retained one.
    pub fn structure(&self) -> Option<&StructureDescriptor> {
        match self {
            Self::Structure(held) => Some(held.structure()),
            Self::GraphNode(_) => None,
        }
    }
}

/// A projector that describes each reached node once per answer.
///
/// The memo is what makes that true. An analysis answer names one node many
/// times over — a misplacement candidate states its declared and its proposed
/// partition, and one partition root is proposed for every symbol that should
/// move into it — and each restatement would otherwise cost a `structure_of`
/// binary search and a walk of the whole owner chain to requalify the name. It
/// is keyed by project and node because a node identity is a position into one
/// graph and two graphs state different nodes at one position.
///
/// It saves the lookup and the walk, not the copy. A memo hit clones the held
/// entity, so each mention still deep-copies the descriptor's three `Box<str>`:
/// the name, the qualified name, and the path. An answer holding borrows into
/// the memo instead would tie every record it carries to the projector that
/// built it, and the records outlive it.
///
/// It holds the describer rather than making one per node, because a page of an
/// answer is mostly one file's declarations and the describer's own memo is
/// what keeps that file's shared facts from being recomputed per row. That memo
/// is keyed by path and does not cover this one: two nodes of one file are one
/// file's facts and two different entities.
pub(super) struct Projector<'index> {
    index: &'index CodeIntelligenceIndex,
    describer: Describer<'index>,
    described: BTreeMap<(ProjectId, GraphNodeId), NavigationEntity>,
}

impl<'index> Projector<'index> {
    /// A projector over one immutable index.
    pub(super) fn new(index: &'index CodeIntelligenceIndex) -> Self {
        Self {
            index,
            describer: Describer::new(index),
            described: BTreeMap::new(),
        }
    }

    /// The revision-bound identity one slice carries out of its index.
    pub(super) fn handle(&self, project: &ProjectSlice) -> ProjectHandle {
        ProjectHandle::new(self.index.revision(), project.id().position())
    }

    /// What one answer says about every node in one selection.
    ///
    /// Stated once here rather than at each call site, because every graph
    /// answer projects a slice of node identities and a second copy of the walk
    /// is a second place for one of them to be dropped.
    pub(super) fn entities(
        &mut self,
        project: &ProjectSlice,
        nodes: &[GraphNodeId],
    ) -> Result<Box<[NavigationEntity]>, CodeIntelligenceError> {
        nodes
            .iter()
            .map(|node| self.entity(project, *node))
            .collect()
    }

    /// What one answer says about `node` in `project`'s graph.
    ///
    /// Described on first sight and read from the memo afterwards, so a node an
    /// answer names ten times is looked up and described once.
    pub(super) fn entity(
        &mut self,
        project: &ProjectSlice,
        node: GraphNodeId,
    ) -> Result<NavigationEntity, CodeIntelligenceError> {
        let key = (project.id(), node);
        match self.described.get(&key).cloned() {
            Some(held) => Ok(held),
            None => {
                let stated = self.projected(project, node)?;
                self.described.insert(key, stated.clone());
                Ok(stated)
            }
        }
    }

    /// What one answer says about a node the memo has not seen yet.
    fn projected(
        &mut self,
        project: &ProjectSlice,
        node: GraphNodeId,
    ) -> Result<NavigationEntity, CodeIntelligenceError> {
        let handle = self.handle(project);
        match self.index.structure_of(project.id(), node) {
            Some(structure) => Ok(NavigationEntity::Structure(Box::new(StructureEntity {
                project: handle,
                node,
                structure: self.describer.describe(structure),
            }))),
            None => stated(handle, project, node)
                .map(Box::new)
                .map(NavigationEntity::GraphNode),
        }
    }
}

/// The typed graph entity one unjoined node states.
///
/// A node the graph itself holds no record for is an internal graph invariant
/// failure. It is refused rather than rendered as an empty file entity, because
/// that entity would be evidence the graph never contained.
///
/// The graph is the slice's own rather than a second parameter beside it. Two
/// ways to reach one value is one way to hand a graph from one slice beside
/// another's authority, and the refusal below would then name the wrong graph.
fn stated(
    handle: ProjectHandle,
    project: &ProjectSlice,
    node: GraphNodeId,
) -> Result<GraphEntity, CodeIntelligenceError> {
    match project.graph().node(node) {
        Some(held) => Ok(GraphEntity {
            project: handle,
            node,
            language: held.language(),
            name: Arc::from(held.name()),
            kind: held.kind().clone(),
            location: held.location().cloned(),
        }),
        None => Err(CodeIntelligenceError::Graph {
            authority: Box::from(project.key().authority()),
            reason: format!(
                "node {} is selected by a graph that records no such node",
                node.index()
            )
            .into_boxed_str(),
        }),
    }
}
