//! A reference record: one naming site, its evidence, and what it produced.

use std::sync::Arc;

use pedant_types::{Language, ResolutionGap, SourceSpan};
use serde::Serialize;

use crate::id::{GraphEdgeId, GraphNodeId, GraphReferenceId};

/// What a naming site denotes at the graph layer.
///
/// A language's finer reference vocabulary collapses into these four: a module
/// declaration and a type mention are both general source relations here.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GraphReferenceKind {
    /// A call site.
    Call,
    /// An import site, including a rename, a group member, or a re-export.
    Import,
    /// An implementation naming its type or its trait.
    Implementation,
    /// Any other source relation between a site and a definition.
    Reference,
}

/// One naming site, its copied evidence, and the edges its candidates produced.
///
/// A site with no candidate keeps its record and its gaps, so unresolved
/// evidence never disappears from the graph.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct GraphReference {
    id: GraphReferenceId,
    source: GraphNodeId,
    language: Language,
    kind: GraphReferenceKind,
    text: Arc<str>,
    span: SourceSpan,
    gaps: Arc<[ResolutionGap]>,
    edges: Box<[GraphEdgeId]>,
}

/// Everything a projection states about one site before it has an identity.
pub(crate) struct ReferenceDraft {
    /// The enclosing definition node, or the unit-qualified span file node.
    pub(crate) source: GraphNodeId,
    /// The language of the unit the site sits in.
    pub(crate) language: Language,
    /// What the site denotes at the graph layer.
    pub(crate) kind: GraphReferenceKind,
    /// The exact source text of the site.
    pub(crate) text: Arc<str>,
    /// Where the site sits.
    pub(crate) span: SourceSpan,
    /// Why the answer is incomplete, shared with the projection that stated it.
    ///
    /// A retained projection drafts its records again on every build that
    /// reuses it, so the answer travels as one allocation rather than a copy
    /// per build.
    pub(crate) gaps: Arc<[ResolutionGap]>,
}

impl GraphReference {
    pub(crate) fn new(
        id: GraphReferenceId,
        draft: ReferenceDraft,
        edges: Box<[GraphEdgeId]>,
    ) -> Self {
        Self {
            id,
            source: draft.source,
            language: draft.language,
            kind: draft.kind,
            text: draft.text,
            span: draft.span,
            gaps: draft.gaps,
            edges,
        }
    }

    /// This record's dense identity, equal to its position in the graph.
    pub fn id(&self) -> GraphReferenceId {
        self.id
    }

    /// The node every edge this record produced starts at.
    pub fn source(&self) -> GraphNodeId {
        self.source
    }

    /// The language of the unit this site sits in.
    pub fn language(&self) -> Language {
        self.language
    }

    /// What this site denotes at the graph layer.
    pub fn kind(&self) -> GraphReferenceKind {
        self.kind
    }

    /// The exact source text of the site.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where the site sits.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// Why the answer is incomplete, in report order.
    pub fn gaps(&self) -> &[ResolutionGap] {
        &self.gaps
    }

    /// The edges this record's candidates produced, in candidate order.
    pub fn edges(&self) -> &[GraphEdgeId] {
        &self.edges
    }
}
