//! A graph node: one structural entity, its language, and where its bytes sit.

use std::sync::Arc;

use pedant_types::{Language, SourceSpan};
use serde::Serialize;

use crate::id::GraphNodeId;

/// What kind of entity a node is.
///
/// The categories are stable graph concepts. The attribute strings are
/// language-declared vocabulary, so another producer may add a level or a
/// declaration name without changing the schema. A producer emits a non-empty
/// lower-snake-case value.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum GraphNodeKind {
    /// One source artifact, qualified by the unit that instantiates it.
    File,
    /// A namespace that owns other entities.
    Container {
        /// The language's name for this container level.
        level: Arc<str>,
    },
    /// A callable entity.
    Function {
        /// The language's name for this callable declaration.
        declaration: Arc<str>,
    },
    /// A type entity.
    Type {
        /// The language's name for this type declaration.
        declaration: Arc<str>,
    },
    /// A named value entity.
    Value {
        /// The language's name for this value declaration.
        declaration: Arc<str>,
    },
}

/// Where a node's bytes sit, when it has any.
///
/// A span identifies the unit-qualified file node that holds the bytes. That is
/// a source association, never a containment parent.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphNodeLocation {
    /// The node is the source artifact itself.
    File {
        /// The normalized repository-relative path.
        path: Arc<str>,
    },
    /// The node is declared at one range of one file node's bytes.
    Span {
        /// The unit-qualified file node holding the declaration.
        file: GraphNodeId,
        /// The exact declaration range.
        span: SourceSpan,
    },
}

/// One structural entity of a code graph.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct GraphNode {
    id: GraphNodeId,
    language: Language,
    name: Arc<str>,
    kind: GraphNodeKind,
    location: Option<GraphNodeLocation>,
}

/// Everything a projection states about one node before it has an identity.
pub(crate) struct NodeDraft {
    /// The language of the unit the node belongs to.
    pub(crate) language: Language,
    /// The declared name, or the normalized path for a file node.
    pub(crate) name: Arc<str>,
    /// What kind of entity the node is.
    pub(crate) kind: GraphNodeKind,
    /// Where the node's bytes sit, when it has any.
    pub(crate) location: Option<GraphNodeLocation>,
}

impl GraphNode {
    pub(crate) fn new(id: GraphNodeId, draft: NodeDraft) -> Self {
        Self {
            id,
            language: draft.language,
            name: draft.name,
            kind: draft.kind,
            location: draft.location,
        }
    }

    /// This node's dense identity, equal to its position in the graph.
    pub fn id(&self) -> GraphNodeId {
        self.id
    }

    /// The language of the unit this node belongs to.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The declared name, or the normalized path for a file node.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What kind of entity this node is.
    pub fn kind(&self) -> &GraphNodeKind {
        &self.kind
    }

    /// Where this node's bytes sit, when it has any.
    pub fn location(&self) -> Option<&GraphNodeLocation> {
        self.location.as_ref()
    }
}
