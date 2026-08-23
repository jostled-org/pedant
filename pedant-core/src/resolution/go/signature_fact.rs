//! One term of a snapshotted Go callable's signature, retained by the snapshot
//! rather than borrowed from the parse it came from.

use pedant_syntax::go::{GoSignatureRole, GoSignatureTermFact};

/// One type a snapshotted callable's signature states.
///
/// The same claim [`GoSignatureTermFact`] makes, with its borrowed names owned
/// so the inventory outlives the bound tree it was walked from. A term whose
/// shape names no single type states none here too: the grammar mapping stays in
/// `pedant-syntax`, so this record cannot name a type that authority did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoSignatureTermRecord {
    declaration: u32,
    role: GoSignatureRole,
    position: u32,
    qualifier: Option<Box<str>>,
    name: Option<Box<str>>,
    pointer: bool,
    variadic: bool,
}

impl GoSignatureTermRecord {
    /// Retain one extracted signature term.
    pub(super) fn of(fact: &GoSignatureTermFact<'_>) -> Self {
        Self {
            declaration: fact.declaration(),
            role: fact.role(),
            position: fact.position(),
            qualifier: fact.type_qualifier().map(Box::from),
            name: fact.type_name().map(Box::from),
            pointer: fact.pointer(),
            variadic: fact.variadic(),
        }
    }

    /// The index of the declaration whose signature states this term.
    pub fn declaration(&self) -> u32 {
        self.declaration
    }

    /// Whether the term is a parameter or a result.
    pub fn role(&self) -> GoSignatureRole {
        self.role
    }

    /// The term's place in its own role, counted from zero.
    pub fn position(&self) -> u32 {
        self.position
    }

    /// The package qualifier of the written type, for a type another package
    /// declares.
    pub fn type_qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The written type's own name, absent whenever the term's shape names no
    /// single type.
    pub fn type_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Whether the written type is a pointer form.
    pub fn pointer(&self) -> bool {
        self.pointer
    }

    /// Whether the term is the variadic parameter its callable ends with.
    pub fn variadic(&self) -> bool {
        self.variadic
    }
}
