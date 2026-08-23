//! One declaration a snapshotted Go source states, retained by the snapshot
//! rather than borrowed from the parse it came from.

use pedant_syntax::go::{GoDeclarationFact, GoDeclarationKind, GoFactSpan};

use super::written_type_fact::GoWrittenTypeRecord;

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
    general_terms: bool,
    result: GoWrittenTypeRecord,
    embedded: GoWrittenTypeRecord,
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
            general_terms: fact.states_general_terms(),
            result: GoWrittenTypeRecord::of(
                fact.result_qualifier(),
                fact.result_name(),
                fact.result_pointer(),
            ),
            embedded: GoWrittenTypeRecord::of(
                fact.embedded_qualifier(),
                fact.embedded_name(),
                fact.embedded_pointer(),
            ),
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

    /// Whether an interface states an element that is a type set rather than a
    /// method or an embedded interface.
    ///
    /// A constraint's members are types rather than methods, so a structural
    /// reader states what it cannot compare instead of comparing the methods it
    /// happens to see.
    pub fn states_general_terms(&self) -> bool {
        self.general_terms
    }

    /// The single result this callable declares, as its source spells it.
    pub fn result_type(&self) -> &GoWrittenTypeRecord {
        &self.result
    }

    /// The type this field embeds, as its source spells it.
    pub fn embedded_type(&self) -> &GoWrittenTypeRecord {
        &self.embedded
    }

    /// The package qualifier of the single result this callable declares.
    pub fn result_qualifier(&self) -> Option<&str> {
        self.result.qualifier()
    }

    /// The name of the single result this callable declares, absent whenever
    /// the source states no single named result.
    pub fn result_name(&self) -> Option<&str> {
        self.result.name()
    }

    /// Whether the single declared result is a pointer form.
    pub fn result_pointer(&self) -> bool {
        self.result.pointer()
    }

    /// The package qualifier of the type this field embeds.
    pub fn embedded_qualifier(&self) -> Option<&str> {
        self.embedded.qualifier()
    }

    /// The name of the type this field embeds.
    pub fn embedded_name(&self) -> Option<&str> {
        self.embedded.name()
    }

    /// Whether the embedded type is written in pointer form.
    ///
    /// Embedding `T` and embedding `*T` promote members of one type identity,
    /// but not the same members: a value embedding `*T` carries every method
    /// `T` has, while one embedding `T` carries only those a value receives.
    pub fn embedded_pointer(&self) -> bool {
        self.embedded.pointer()
    }
}
