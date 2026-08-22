//! The definition inventory, and the tables Go name lookup reads it through.
//!
//! Every definition a report states is recorded here once, beside the answers
//! lookup needs about it: which unit declares it, which name it takes at
//! package scope, which type holds it, which types it embeds, and whether an
//! unevaluated build predicate governs it. A stage asking one of those
//! questions reads a table rather than rescanning the corpus.

use std::collections::BTreeMap;

use pedant_types::{DefinitionHandle, ResolutionUnitHandle, SymbolKind};

/// A named type, as the source that mentioned it wrote it.
///
/// The pointer form the source wrote is not carried: a call's value selects the
/// same method set whether the callable returns `T` or `*T`, so the two answer
/// this tier's question identically. What turns on pointerness is an interface's
/// method set, and the binding record the structural resolver reads states the
/// written form there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TypeName {
    pub(super) qualifier: Option<Box<str>>,
    pub(super) name: Box<str>,
}

/// One named type an in-snapshot package embeds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EmbeddedType {
    pub(super) unit: usize,
    pub(super) name: Box<str>,
}

/// One definition the report states, and what lookup must know about it.
pub(super) struct Slot {
    pub(super) handle: DefinitionHandle,
    pub(super) kind: SymbolKind,
    pub(super) unit: usize,
    pub(super) name: Box<str>,
    /// Whether an unevaluated build predicate governs the source declaring it.
    pub(super) conditional: bool,
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
}

/// One package context's own tables.
pub(super) struct UnitIndex {
    pub(super) handle: ResolutionUnitHandle,
    /// The slot of this unit's one package definition.
    pub(super) package: usize,
    names: BTreeMap<Box<str>, Vec<usize>>,
    members: BTreeMap<(Box<str>, Box<str>), Vec<usize>>,
    embeds: BTreeMap<Box<str>, Vec<EmbeddedType>>,
    declarations: BTreeMap<(Box<str>, u32), usize>,
}

impl UnitIndex {
    /// An empty index for the unit `handle` names, whose package definition
    /// took `package`.
    pub(super) fn new(handle: ResolutionUnitHandle, package: usize) -> Self {
        Self {
            handle,
            package,
            names: BTreeMap::new(),
            members: BTreeMap::new(),
            embeds: BTreeMap::new(),
            declarations: BTreeMap::new(),
        }
    }

    /// Record one package-scope name.
    pub(super) fn declare(&mut self, name: &str, slot: usize) {
        self.names.entry(Box::from(name)).or_default().push(slot);
    }

    /// Record one member of a named type.
    pub(super) fn hold(&mut self, owner: &str, member: &str, slot: usize) {
        self.members
            .entry((Box::from(owner), Box::from(member)))
            .or_default()
            .push(slot);
    }

    /// Record one type a named type embeds.
    pub(super) fn embed(&mut self, owner: &str, embedded: EmbeddedType) {
        self.embeds
            .entry(Box::from(owner))
            .or_default()
            .push(embedded);
    }

    /// Record which slot one source's declaration became.
    pub(super) fn state(&mut self, source: &str, declaration: u32, slot: usize) {
        self.declarations
            .insert((Box::from(source), declaration), slot);
    }

    /// Every definition one package-scope name selects.
    pub(super) fn named(&self, name: &str) -> &[usize] {
        self.names.get(name).map(Vec::as_slice).unwrap_or_default()
    }

    /// Every member one named type declares directly.
    pub(super) fn member(&self, owner: &str, member: &str) -> &[usize] {
        self.members
            .get(&(Box::from(owner), Box::from(member)))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Every type one named type embeds, in source order.
    pub(super) fn embedded(&self, owner: &str) -> &[EmbeddedType] {
        self.embeds
            .get(owner)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The definition one source's declaration became.
    pub(super) fn declared(&self, source: &str, declaration: u32) -> Option<usize> {
        self.declarations
            .get(&(Box::from(source), declaration))
            .copied()
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

    /// The tables of the unit at one snapshot-local position, for a stage still
    /// filling them.
    pub(super) fn unit_mut(&mut self, unit: usize) -> Option<&mut UnitIndex> {
        self.units.get_mut(unit)
    }

    /// The definition at one position.
    pub(super) fn slot(&self, slot: usize) -> Option<&Slot> {
        self.slots.get(slot)
    }
}
