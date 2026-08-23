//! The retained fact inventory one snapshotted Go source states.
//!
//! `pedant-syntax` extracts one [`GoFileFacts`] bound to the exact string its
//! tree indexes. A snapshot outlives that string's parse, so it retains the
//! same claims with their names owned. Nothing here reads a grammar node: the
//! whole inventory is a projection of the one Go grammar authority, so a fact
//! this crate states is a fact that crate extracted.

use pedant_syntax::go::{GoFactSpan, GoFileFacts, GoScopeFact};

use super::binding_fact::GoBindingRecord;
use super::declaration_fact::GoDeclarationRecord;
use super::import_fact::GoImportRecord;
use super::reference_fact::GoReferenceRecord;
use super::signature_fact::GoSignatureTermRecord;

/// Every structured Go grammar fact one snapshotted source states.
///
/// Sealed on construction and read through borrows, so a consumer reads what
/// the extraction claimed and cannot restate it as something the walk never
/// saw. Every list keeps the source order the extraction produced, because the
/// indexes records carry — parents, receivers, scopes, declarations — select
/// positions inside these lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoSourceFacts {
    package: Option<(Box<str>, GoFactSpan)>,
    imports: Box<[GoImportRecord]>,
    declarations: Box<[GoDeclarationRecord]>,
    signatures: Box<[GoSignatureTermRecord]>,
    references: Box<[GoReferenceRecord]>,
    scopes: Box<[GoScopeFact]>,
    bindings: Box<[GoBindingRecord]>,
}

impl GoSourceFacts {
    /// Retain one extracted inventory.
    pub(super) fn of(facts: &GoFileFacts<'_>) -> Self {
        Self {
            package: facts
                .package_name()
                .zip(facts.package_span())
                .map(|(name, span)| (Box::from(name), span)),
            imports: facts.imports().iter().map(GoImportRecord::of).collect(),
            declarations: facts
                .declarations()
                .iter()
                .map(GoDeclarationRecord::of)
                .collect(),
            signatures: facts
                .signature_terms()
                .iter()
                .map(GoSignatureTermRecord::of)
                .collect(),
            references: facts
                .references()
                .iter()
                .map(GoReferenceRecord::of)
                .collect(),
            scopes: Box::from(facts.scopes()),
            bindings: facts.bindings().iter().map(GoBindingRecord::of).collect(),
        }
    }

    /// The declared package name, absent when the source states no clause.
    pub fn package_name(&self) -> Option<&str> {
        self.package.as_ref().map(|(name, _)| &**name)
    }

    /// The extent of the declared package name.
    pub fn package_span(&self) -> Option<GoFactSpan> {
        self.package.as_ref().map(|(_, span)| *span)
    }

    /// Every import specification, in source order.
    pub fn imports(&self) -> &[GoImportRecord] {
        &self.imports
    }

    /// Every declaration, in source order.
    pub fn declarations(&self) -> &[GoDeclarationRecord] {
        &self.declarations
    }

    /// Every signature term, in the order the callables that state them are
    /// declared.
    pub fn signature_terms(&self) -> &[GoSignatureTermRecord] {
        &self.signatures
    }

    /// Every reference site, in source order.
    pub fn references(&self) -> &[GoReferenceRecord] {
        &self.references
    }

    /// Every lexical scope, in source order, opening with the file scope.
    pub fn scopes(&self) -> &[GoScopeFact] {
        &self.scopes
    }

    /// Every bound name, in source order.
    pub fn bindings(&self) -> &[GoBindingRecord] {
        &self.bindings
    }
}
