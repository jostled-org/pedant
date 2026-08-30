//! One physical logical structure, its dense identity, and the handle that
//! carries that identity out of the revision that minted it.
//!
//! A dense position is the cheapest identity an immutable collection can have
//! and the most dangerous one to publish: position 7 exists in every revision,
//! and in each of them it is a different structure. So [`StructureId`] has no
//! public constructor, and the value that leaves this crate is a
//! [`StructureHandle`] carrying the revision that issued it. Every operation
//! compares revisions before it reads a position, which is what makes a handle
//! from an older index a refusal rather than a wrong answer.

use std::sync::Arc;

use pedant_types::{Language, StructureKind, StructureSpan};
use serde::{Deserialize, Serialize};

use super::revision::IndexRevision;

/// The position of one physical structure in one index revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StructureId {
    position: u32,
}

impl StructureId {
    /// The identity of the structure retained at `position`.
    pub(crate) fn at(position: u32) -> Self {
        Self { position }
    }

    /// The position this identity names.
    pub fn position(self) -> u32 {
        self.position
    }
}

/// One structure identity, together with the revision that issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StructureHandle {
    revision: IndexRevision,
    id: StructureId,
}

impl StructureHandle {
    /// A handle naming `position` inside `revision`.
    ///
    /// Public because a transport receives both halves as text and has to
    /// reassemble them. It is not a way to reach a structure: the revision is
    /// compared before the position is read, so a handle assembled against the
    /// wrong index refuses.
    pub fn new(revision: IndexRevision, position: u32) -> Self {
        Self {
            revision,
            id: StructureId::at(position),
        }
    }

    /// The revision that issued this handle.
    pub fn revision(self) -> IndexRevision {
        self.revision
    }

    /// The identity this handle carries.
    pub fn id(self) -> StructureId {
        self.id
    }
}

/// One logical structure exactly one physical source declares.
///
/// The path and the name are shared handles rather than copies: one file states
/// many structures and one index answers many queries about them, so the
/// alternative is one allocation of the same path per structure.
///
/// The owner is an identity in the same revision and always inside the same
/// file. It points at a strictly containing span, so owner links form a forest
/// rather than a cycle, and an outline is that forest read in source order.
///
/// The instances are where this one declaration appears as a node of a project
/// graph. There may be several: a Cargo library compiled into its own target
/// and linked by a binary is two graphs over the same source, and both of them
/// state the same function. There may be none, because a syntax-only source has
/// a complete outline and no graph behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeStructure {
    id: StructureId,
    language: Language,
    kind: StructureKind,
    name: Option<Arc<str>>,
    owner: Option<StructureId>,
    path: Arc<str>,
    span: StructureSpan,
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    instances: Box<[super::instance::StructureInstance]>,
}

impl CodeStructure {
    /// Seal one recognized structure into its revision.
    pub(crate) fn sealed(
        id: StructureId,
        language: Language,
        kind: StructureKind,
        name: Option<Arc<str>>,
        owner: Option<StructureId>,
        path: Arc<str>,
        span: StructureSpan,
    ) -> Self {
        Self {
            id,
            language,
            kind,
            name,
            owner,
            path,
            span,
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            instances: Box::new([]),
        }
    }

    /// The same structure, sealed with the graph memberships it states.
    ///
    /// Taken by value rather than written into a published record: the join
    /// runs after every slice has resolved, because a membership is a position
    /// in a graph that was still being built while the sources were read.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    pub(crate) fn instanced(self, instances: Box<[super::instance::StructureInstance]>) -> Self {
        Self { instances, ..self }
    }

    /// This structure's identity in the revision that indexed it.
    pub fn id(&self) -> StructureId {
        self.id
    }

    /// The language its source was recognized as.
    pub fn language(&self) -> Language {
        self.language
    }

    /// What it declares.
    pub fn kind(&self) -> StructureKind {
        self.kind
    }

    /// The declared name, absent for a structure its grammar leaves unnamed.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The nearest indexed structure that lexically owns this one.
    pub fn owner(&self) -> Option<StructureId> {
        self.owner
    }

    /// The normalized repository path of the source that declares it.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The extent of the whole declaration in that source.
    pub fn span(&self) -> StructureSpan {
        self.span
    }

    /// Every project graph this declaration appears as a node of, in project
    /// then node order.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "graph-rust", feature = "graph-go"))))]
    pub fn instances(&self) -> &[super::instance::StructureInstance] {
        &self.instances
    }
}
