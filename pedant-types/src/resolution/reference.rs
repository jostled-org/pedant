//! A reference site: where a unit names something.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Language;

use super::id::{DefinitionId, ReferenceId, ResolutionUnitId};
use super::span::SourceSpan;

/// The closed vocabulary of references a report emits.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    /// A module declaration naming another source.
    Module,
    /// An import, including a rename, a group member, a glob, or a re-export.
    Import,
    /// A call.
    Call,
    /// A type mentioned in a signature, a body, or a bound.
    Type,
    /// An implementation naming its type or its trait.
    Implementation,
}

/// One reference site inside one resolution unit.
///
/// Two identical path texts at two locations are two references: the span, not
/// the text, is the site's identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SymbolReference {
    id: ReferenceId,
    unit: ResolutionUnitId,
    language: Language,
    kind: ReferenceKind,
    text: Arc<str>,
    span: SourceSpan,
    enclosing_definition: Option<DefinitionId>,
}

impl SymbolReference {
    pub(crate) fn new(
        id: ReferenceId,
        unit: ResolutionUnitId,
        language: Language,
        kind: ReferenceKind,
        text: Arc<str>,
        span: SourceSpan,
        enclosing_definition: Option<DefinitionId>,
    ) -> Self {
        Self {
            id,
            unit,
            language,
            kind,
            text,
            span,
            enclosing_definition,
        }
    }

    /// This reference's identifier.
    pub fn id(&self) -> ReferenceId {
        self.id
    }

    /// The unit this reference occurs in.
    pub fn unit(&self) -> ResolutionUnitId {
        self.unit
    }

    /// The language of the unit this reference belongs to.
    pub fn language(&self) -> Language {
        self.language
    }

    /// What kind of reference this is.
    pub fn kind(&self) -> ReferenceKind {
        self.kind
    }

    /// The source text of the reference, alias and all.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where the reference sits in the snapshotted source.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// The span, for a decoder interning the paths it just allocated.
    pub(super) fn span_mut(&mut self) -> &mut SourceSpan {
        &mut self.span
    }

    /// The definition this reference occurs inside, in the same unit.
    pub fn enclosing_definition(&self) -> Option<DefinitionId> {
        self.enclosing_definition
    }
}
