//! A definition site: what a name in one unit declares.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Language;

use super::id::{DefinitionId, ResolutionUnitId};
use super::span::SourceSpan;

/// The closed vocabulary of definitions a report emits.
///
/// The set is shared by every language a report can carry, and no variant is
/// admitted by all of them. A consumer bound to one language proves the subset
/// it accepts at its own validation boundary; nothing here widens what a
/// language may state.
///
/// New variants are appended rather than inserted. The derived order is what
/// the validator's sorted collections and a consumer's comparisons read, so a
/// variant placed among the published ones would reorder reports nothing else
/// changed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A module.
    Module,
    /// A free or associated function.
    Function,
    /// A method reached through a receiver.
    Method,
    /// A struct.
    Struct,
    /// An enum.
    Enum,
    /// A union.
    Union,
    /// A trait.
    Trait,
    /// A type alias.
    TypeAlias,
    /// A constant.
    Constant,
    /// A static.
    Static,
    /// A package: the namespace a group of sources compile into together.
    Package,
    /// An interface: a named method set a concrete type may satisfy
    /// structurally.
    Interface,
    /// A defined type: a named type declared over an underlying one.
    DefinedType,
    /// A variable: a named, mutable binding at package or local scope.
    Variable,
    /// A field: a named member declared inside a type.
    Field,
}

/// One definition site inside one resolution unit.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymbolDefinition {
    id: DefinitionId,
    unit: ResolutionUnitId,
    language: Language,
    kind: SymbolKind,
    name: Arc<str>,
    span: SourceSpan,
    parent: Option<DefinitionId>,
}

impl SymbolDefinition {
    pub(crate) fn new(
        id: DefinitionId,
        unit: ResolutionUnitId,
        language: Language,
        kind: SymbolKind,
        name: Arc<str>,
        span: SourceSpan,
        parent: Option<DefinitionId>,
    ) -> Self {
        Self {
            id,
            unit,
            language,
            kind,
            name,
            span,
            parent,
        }
    }

    /// This definition's identifier.
    pub fn id(&self) -> DefinitionId {
        self.id
    }

    /// The unit this definition is declared in.
    pub fn unit(&self) -> ResolutionUnitId {
        self.unit
    }

    /// The language of the unit this definition belongs to.
    pub fn language(&self) -> Language {
        self.language
    }

    /// What kind of definition this is.
    pub fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// The declared name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the definition sits in the snapshotted source.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// The span, for a decoder interning the paths it just allocated.
    pub(super) fn span_mut(&mut self) -> &mut SourceSpan {
        &mut self.span
    }

    /// The definition that lexically owns this one, in the same unit.
    pub fn parent(&self) -> Option<DefinitionId> {
        self.parent
    }
}
