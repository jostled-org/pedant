//! The definition inventory, and the tables Go name lookup reads it through.
//!
//! Every definition a report states is recorded here once, beside the answers
//! lookup needs about it: which unit declares it, which name it takes at
//! package scope, which type holds it, which types it embeds, and whether an
//! unevaluated build predicate governs it. A stage asking one of those
//! questions reads a table rather than rescanning the corpus.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_syntax::go::{GoDeclarationKind, GoFactSpan};
use pedant_types::{
    DefinitionHandle, ResolutionUnitHandle, SourcePosition, SourceSpan, SymbolKind,
};

use crate::resolution::identity::position;

use super::error::GoResolutionError;

/// A named type, as the source that mentioned it wrote it.
///
/// The pointer form the source wrote is not carried: a call's value selects the
/// same method set whether the callable returns `T` or `*T`, so the two answer
/// this tier's question identically. What turns on pointerness is an interface's
/// method set, and the embedding that carries it states the written form beside
/// this identity rather than inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TypeName {
    pub(super) qualifier: Option<Box<str>>,
    pub(super) name: Box<str>,
}

/// One named type an in-snapshot package embeds.
///
/// The name is shared across embedding-level method-set walks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EmbeddedType {
    pub(super) unit: usize,
    pub(super) name: Arc<str>,
}

/// One embedding, as the type it names and the form the source wrote.
///
/// The form is what decides which method set a promotion reaches: embedding
/// `*T` gives the embedding type every method `T` has, while embedding `T`
/// gives it only those a value receives.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Embedding {
    pub(super) embedded: EmbeddedType,
    pub(super) pointer: bool,
}

/// One definition the report states, and what lookup must know about it.
pub(super) struct Slot {
    pub(super) handle: DefinitionHandle,
    pub(super) kind: SymbolKind,
    /// What the Go grammar called this declaration, absent for the package
    /// definition, which no declaration states.
    pub(super) declared: Option<GoDeclarationKind>,
    pub(super) unit: usize,
    /// The declared name, shared with the report handle and with every
    /// embedding identity that reaches it, so one name is allocated once.
    pub(super) name: Arc<str>,
    /// Where the declared name itself is written, which is the site a relation
    /// stated about this definition is reported at.
    pub(super) site: SourceSpan,
    /// The definition this one is a child of.
    pub(super) holder: Option<usize>,
    /// Whether an unevaluated build predicate governs the source declaring it.
    pub(super) conditional: bool,
    /// Whether a method receives its type by pointer, which decides whether a
    /// value of that type carries the method at all.
    pub(super) pointer_receiver: bool,
    /// Whether an interface states a type set rather than methods alone.
    pub(super) general_terms: bool,
    /// The single result a callable declares, which is what a call's value is
    /// known to be.
    pub(super) result: Option<TypeName>,
}

impl Slot {
    /// Whether this definition names a type a value can have.
    pub(super) fn is_type(&self) -> bool {
        matches!(
            self.kind,
            SymbolKind::Struct
                | SymbolKind::Interface
                | SymbolKind::DefinedType
                | SymbolKind::TypeAlias
        )
    }

    /// Whether this definition names an interface.
    pub(super) fn is_interface(&self) -> bool {
        matches!(self.kind, SymbolKind::Interface)
    }

    /// Whether this definition names a concrete type a method may receive.
    ///
    /// An alias is not one: it names the same type its target does, so a
    /// relation stated about both would state one fact twice.
    pub(super) fn is_concrete_type(&self) -> bool {
        matches!(self.kind, SymbolKind::Struct | SymbolKind::DefinedType)
    }

    /// Whether this definition is a method an interface declares.
    pub(super) fn is_interface_method(&self) -> bool {
        self.declared == Some(GoDeclarationKind::InterfaceMethod)
    }

    /// Whether this definition is a method a concrete type receives.
    pub(super) fn is_concrete_method(&self) -> bool {
        self.declared == Some(GoDeclarationKind::Method)
    }

    /// Whether this definition is an element written as a bare type, which
    /// embeds that type's own members.
    pub(super) fn is_embedded_field(&self) -> bool {
        self.declared == Some(GoDeclarationKind::EmbeddedField)
    }
}

/// The report span one grammar span occupies in its own file.
///
/// One owner for every stage that writes a site: the definition pass, the
/// reference pass, and the package clause all state the same four coordinates
/// against the same path, and a copy per stage is one conversion a later fix
/// reaches only part of. The path is shared rather than copied, because every
/// caller already holds the snapshot's own handle on it.
pub(super) fn site(path: &Arc<str>, span: GoFactSpan) -> SourceSpan {
    SourceSpan::new(
        Arc::clone(path),
        SourcePosition::new(position(span.start_line()), position(span.start_column())),
        SourcePosition::new(position(span.end_line()), position(span.end_column())),
    )
}

/// One package context's own tables.
///
/// The member and declaration tables nest rather than key on a tuple: a tuple
/// key has no borrowed form, so every read of one would allocate its key parts
/// only to drop them again, and the member table is the hottest read in the
/// stage. Nested, both levels probe with a borrowed name and allocate nothing.
pub(super) struct UnitIndex {
    pub(super) handle: ResolutionUnitHandle,
    /// The slot of this unit's one package definition.
    pub(super) package: usize,
    names: BTreeMap<Box<str>, Vec<usize>>,
    holders: BTreeMap<Box<str>, Vec<usize>>,
    embeds: BTreeMap<Box<str>, Vec<Embedding>>,
    declarations: BTreeMap<Box<str>, BTreeMap<u32, usize>>,
}

impl UnitIndex {
    /// An empty index for the unit `handle` names, whose package definition
    /// took `package`.
    pub(super) fn new(handle: ResolutionUnitHandle, package: usize) -> Self {
        Self {
            handle,
            package,
            names: BTreeMap::new(),
            holders: BTreeMap::new(),
            embeds: BTreeMap::new(),
            declarations: BTreeMap::new(),
        }
    }

    /// Record one package-scope name.
    pub(super) fn declare(&mut self, name: &str, slot: usize) {
        self.names.entry(Box::from(name)).or_default().push(slot);
    }

    /// Record one member of a named type.
    pub(super) fn hold(&mut self, owner: &str, slot: usize) {
        self.holders.entry(Box::from(owner)).or_default().push(slot);
    }

    /// Record one type a named type embeds.
    pub(super) fn embed(&mut self, owner: &str, embedding: Embedding) {
        self.embeds
            .entry(Box::from(owner))
            .or_default()
            .push(embedding);
    }

    /// Record which slot one source's declaration became.
    pub(super) fn state(&mut self, source: &str, declaration: u32, slot: usize) {
        self.declarations
            .entry(Box::from(source))
            .or_default()
            .insert(declaration, slot);
    }

    /// Every definition one package-scope name selects.
    pub(super) fn named(&self, name: &str) -> &[usize] {
        self.names.get(name).map(Vec::as_slice).unwrap_or_default()
    }

    /// Every member one named type declares directly, whatever it is called.
    pub(super) fn held(&self, owner: &str) -> &[usize] {
        self.holders
            .get(owner)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Every type one named type embeds, in source order.
    pub(super) fn embedded(&self, owner: &str) -> &[Embedding] {
        self.embeds
            .get(owner)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The definition one source's declaration became.
    pub(super) fn declared(&self, source: &str, declaration: u32) -> Option<usize> {
        self.declarations.get(source)?.get(&declaration).copied()
    }
}

/// Every definition the report states, and every unit's tables over them.
#[derive(Default)]
pub(super) struct Index {
    slots: Vec<Slot>,
    units: Vec<UnitIndex>,
}

impl Index {
    /// Retain one definition and answer with the position it took.
    pub(super) fn push(&mut self, slot: Slot) -> usize {
        self.slots.push(slot);
        self.slots.len() - 1
    }

    /// Retain one unit's tables.
    pub(super) fn open(&mut self, unit: UnitIndex) {
        self.units.push(unit);
    }

    /// The tables of the unit at one snapshot-local position.
    pub(super) fn unit(&self, unit: usize) -> Option<&UnitIndex> {
        self.units.get(unit)
    }

    /// The tables of the unit at one snapshot-local position, refusing an
    /// absence rather than passing over it.
    ///
    /// A stage filling a unit's tables was handed the position the same walk
    /// opened the index at, so an absence here is a hole in this resolution's
    /// own inventory. Ignoring it costs the join every later stage reads
    /// through, with nothing said; refusing states which context is missing.
    pub(super) fn tables_mut(&mut self, unit: usize) -> Result<&mut UnitIndex, GoResolutionError> {
        self.units.get_mut(unit).ok_or_else(|| unopened(unit))
    }

    /// The handle of the unit at one snapshot-local position.
    pub(super) fn unit_handle(
        &self,
        unit: usize,
    ) -> Result<ResolutionUnitHandle, GoResolutionError> {
        self.unit(unit)
            .map(|found| found.handle.clone())
            .ok_or_else(|| unopened(unit))
    }

    /// The definition at one position.
    pub(super) fn slot(&self, slot: usize) -> Option<&Slot> {
        self.slots.get(slot)
    }

    /// Every definition the report states, in the order they were stated.
    pub(super) fn stated(&self) -> &[Slot] {
        &self.slots
    }
}

/// The refusal one unopened package context earns.
fn unopened(unit: usize) -> GoResolutionError {
    GoResolutionError::UnitMapping {
        unit: position(unit),
        reason: Box::from("no index was opened for this package context"),
    }
}
