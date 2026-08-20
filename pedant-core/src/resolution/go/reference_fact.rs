//! One reference site a snapshotted Go source states.

use pedant_syntax::go::{GoFactSpan, GoReferenceFact, GoReferenceKind};

/// One Go reference site, exactly as its source wrote it.
///
/// The same claim [`GoReferenceFact`] makes, with its borrowed text owned so
/// the inventory outlives the bound tree it was walked from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoReferenceRecord {
    kind: GoReferenceKind,
    qualifier: Option<Box<str>>,
    name: Box<str>,
    span: GoFactSpan,
    name_span: GoFactSpan,
    declaration: Option<u32>,
    scope: u32,
}

impl GoReferenceRecord {
    /// Retain one extracted reference.
    pub(super) fn of(fact: &GoReferenceFact<'_>) -> Self {
        Self {
            kind: fact.kind(),
            qualifier: fact.qualifier().map(Box::from),
            name: Box::from(fact.name()),
            span: fact.span(),
            name_span: fact.name_span(),
            declaration: fact.declaration(),
            scope: fact.scope(),
        }
    }

    /// What this site refers to.
    pub fn kind(&self) -> GoReferenceKind {
        self.kind
    }

    /// The receiver or package written before the name, when the site is
    /// qualified.
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The referenced name, in its source spelling.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The extent of the whole site.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The extent of the referenced name alone.
    pub fn name_span(&self) -> GoFactSpan {
        self.name_span
    }

    /// The index of the declaration whose text holds this site.
    pub fn declaration(&self) -> Option<u32> {
        self.declaration
    }

    /// The index of the scope this site is written in.
    pub fn scope(&self) -> u32 {
        self.scope
    }
}
