//! One declaration a snapshotted Go source states, retained by the snapshot
//! rather than borrowed from the parse it came from.

use pedant_syntax::go::{GoDeclarationFact, GoDeclarationKind, GoFactSpan};

/// One Go declaration, exactly as its source wrote it.
///
/// The same claim [`GoDeclarationFact`] makes, with its borrowed name owned so
/// the inventory outlives the bound tree it was walked from. The grammar
/// mapping stays in `pedant-syntax`: nothing here inspects a node, so this
/// record cannot state a declaration the one Go grammar authority did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoDeclarationRecord {
    kind: GoDeclarationKind,
    name: Box<str>,
    span: GoFactSpan,
    name_span: GoFactSpan,
    parent: Option<u32>,
    receiver: Option<u32>,
    scope: u32,
}

impl GoDeclarationRecord {
    /// Retain one extracted declaration.
    pub(super) fn of(fact: &GoDeclarationFact<'_>) -> Self {
        Self {
            kind: fact.kind(),
            name: Box::from(fact.name()),
            span: fact.span(),
            name_span: fact.name_span(),
            parent: fact.parent(),
            receiver: fact.receiver(),
            scope: fact.scope(),
        }
    }

    /// What this declaration declares.
    pub fn kind(&self) -> GoDeclarationKind {
        self.kind
    }

    /// The declared name, in its source spelling.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The extent of the whole declaration.
    pub fn span(&self) -> GoFactSpan {
        self.span
    }

    /// The extent of the declared name alone.
    pub fn name_span(&self) -> GoFactSpan {
        self.name_span
    }

    /// The index of the declaration that holds this one: a struct for its
    /// fields, and an interface for its methods and embedded elements.
    pub fn parent(&self) -> Option<u32> {
        self.parent
    }

    /// The index of the receiver binding a method declaration states.
    pub fn receiver(&self) -> Option<u32> {
        self.receiver
    }

    /// The index of the scope this declaration is stated in.
    pub fn scope(&self) -> u32 {
        self.scope
    }
}
