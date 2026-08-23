//! The bounded inventory one Go source states.

use crate::extract::select::UnitSelector;
use crate::go::binding::GoBindingFact;
use crate::go::condition::GoBuildConditionFact;
use crate::go::declaration::{GoDeclarationFact, GoDeclarationKind};
use crate::go::error::GoFactError;
use crate::go::import::GoImportFact;
use crate::go::limits::GoFactLimits;
use crate::go::reference::GoReferenceFact;
use crate::go::retention::GoFactScope;
use crate::go::scope::GoScopeFact;
use crate::go::signature::GoSignatureTermFact;
use crate::go::span::GoFactSpan;
use crate::go::walk::{self, Inventory};
use crate::location::Location;
use crate::tree_sitter::{Node, SourceUnitAnchor};
use crate::unit::SourceUnitKind;

/// Every structured Go grammar fact one source states.
///
/// The sole Go grammar authority in this workspace. Capability attribution and
/// Go resolution both read this inventory, so neither owns a second import,
/// call, selector, binding, reference, or declaration mapping that could drift
/// from the other.
///
/// Bound to the source it was extracted from, the way a parse session is bound
/// to the source its tree indexes: every span here slices that exact string,
/// and every name is a borrowed slice of it rather than a copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoFileFacts<'source> {
    source: &'source str,
    has_errors: bool,
    package: Option<(&'source str, GoFactSpan)>,
    conditions: Box<[GoBuildConditionFact<'source>]>,
    imports: Box<[GoImportFact<'source>]>,
    declarations: Box<[GoDeclarationFact<'source>]>,
    signatures: Box<[GoSignatureTermFact<'source>]>,
    references: Box<[GoReferenceFact<'source>]>,
    scopes: Box<[GoScopeFact]>,
    bindings: Box<[GoBindingFact<'source>]>,
}

impl<'source> GoFileFacts<'source> {
    /// Walk one bound Go tree once and seal what it states.
    pub(crate) fn extract(
        root: Node<'_>,
        source: &'source str,
        has_errors: bool,
        limits: GoFactLimits,
    ) -> Result<Self, GoFactError> {
        Ok(Self::seal(
            walk::extract(root, source, limits, GoFactScope::Everything)?,
            source,
            has_errors,
        ))
    }

    /// Seal one completed walk.
    fn seal(inventory: Inventory<'source>, source: &'source str, has_errors: bool) -> Self {
        Self {
            source,
            has_errors,
            package: inventory.packages.first().copied(),
            conditions: inventory.conditions.into_boxed_slice(),
            imports: inventory.imports.into_boxed_slice(),
            declarations: inventory.declarations.into_boxed_slice(),
            signatures: inventory.signatures.into_boxed_slice(),
            references: inventory.references.into_boxed_slice(),
            scopes: inventory.scopes.into_boxed_slice(),
            bindings: inventory.bindings.into_boxed_slice(),
        }
    }

    /// Whether the tree these facts came from carries recovery errors.
    ///
    /// A recovery tree still states facts, and capability detection keeps them
    /// beside an unavailable attribution status. A resolution snapshot refuses
    /// the source instead, so the answer travels with the inventory rather than
    /// being decided here.
    pub fn has_errors(&self) -> bool {
        self.has_errors
    }

    /// The declared package name, absent when the source states no clause.
    pub fn package_name(&self) -> Option<&'source str> {
        self.package.map(|(name, _)| name)
    }

    /// The extent of the declared package name.
    pub fn package_span(&self) -> Option<GoFactSpan> {
        self.package.map(|(_, span)| span)
    }

    /// The build predicates stated above the package clause, in source order.
    pub fn build_conditions(&self) -> &[GoBuildConditionFact<'source>] {
        &self.conditions
    }

    /// Every import specification, in source order.
    pub fn imports(&self) -> &[GoImportFact<'source>] {
        &self.imports
    }

    /// Every declaration, in source order.
    pub fn declarations(&self) -> &[GoDeclarationFact<'source>] {
        &self.declarations
    }

    /// Every signature term, in the order the callables that state them are
    /// declared.
    pub fn signature_terms(&self) -> &[GoSignatureTermFact<'source>] {
        &self.signatures
    }

    /// Every reference site, in source order.
    pub fn references(&self) -> &[GoReferenceFact<'source>] {
        &self.references
    }

    /// Every lexical scope, in source order, opening with the file scope.
    pub fn scopes(&self) -> &[GoScopeFact] {
        &self.scopes
    }

    /// Every bound name, in source order.
    pub fn bindings(&self) -> &[GoBindingFact<'source>] {
        &self.bindings
    }

    /// The narrowest declaration containing each location in `at`, answered in
    /// one pass and returned in the caller's order.
    ///
    /// This inventory is the sole Go declaration index, so the enclosing-unit
    /// answer is read from it rather than from a second walk of the tree. Every
    /// slot is `None` when the tree carried recovery errors, because an
    /// incomplete inventory states no complete declaration set to select from.
    pub fn enclosing_unit_anchors(&self, at: &[Location]) -> Box<[Option<SourceUnitAnchor>]> {
        match self.has_errors {
            true => at.iter().map(|_| None).collect(),
            false => {
                let mut selector = UnitSelector::over(self.source, at);
                offer_units(&self.declarations, &mut selector);
                selector.finish_anchors()
            }
        }
    }
}

/// Offer every declaration that carries a source unit to `selector`.
///
/// A function over the slice rather than a method, because two routes read the
/// same declarations: a sealed inventory answers its own enclosing-unit
/// question, and the extraction boundary walks for declarations alone and seals
/// nothing.
fn offer_units<'source>(
    declarations: &[GoDeclarationFact<'source>],
    selector: &mut UnitSelector<'source>,
) {
    for declaration in declarations {
        let Some(kind) = unit_kind(declaration.kind()) else {
            continue;
        };
        let range = declaration.span().byte_range();
        if !selector.contains(&range) {
            continue;
        }
        selector.keep(kind, Some(declaration.name()), range);
    }
}

/// Offer one Go source's units without keeping its inventory.
///
/// The route the generic extraction boundary takes. Go declarations come from
/// this crate's fact inventory in every configuration, so the shared
/// declaration recognizer states no Go grammar of its own.
///
/// Declarations alone. This answers the enclosing-unit question, which reads no
/// import, no reference, no binding, and no signature term, so a host that also
/// asks for the inventory pays for one whole-tree walk of each rather than two
/// of the same one.
///
/// A refusal travels rather than reading as absence. Both ceilings are
/// unbounded here, so nothing but a source past the representable ceiling can
/// refuse — and turning that into "this file declares nothing" is exactly the
/// collapse `LanguageMismatch` exists to prevent one seam away.
pub(crate) fn offer_unit_declarations<'source>(
    root: Node<'_>,
    source: &'source str,
    selector: &mut UnitSelector<'source>,
) -> Result<(), GoFactError> {
    let inventory = walk::extract(
        root,
        source,
        GoFactLimits::UNBOUNDED,
        GoFactScope::DeclarationsOnly,
    )?;
    offer_units(&inventory.declarations, selector);
    Ok(())
}

/// The source unit one declaration carries, if it carries one.
///
/// Only a function, a method, and a named struct type return their own text.
/// An interface, an alias, a defined type, a constant, a variable, and a member
/// are declarations the unit model states no kind for, and a caller asking
/// inside one reads the declaration that holds it instead.
fn unit_kind(kind: GoDeclarationKind) -> Option<SourceUnitKind> {
    match kind {
        GoDeclarationKind::Function => Some(SourceUnitKind::Function),
        GoDeclarationKind::Method => Some(SourceUnitKind::Method),
        GoDeclarationKind::Struct => Some(SourceUnitKind::Struct),
        GoDeclarationKind::Interface
        | GoDeclarationKind::DefinedType
        | GoDeclarationKind::TypeAlias
        | GoDeclarationKind::Constant
        | GoDeclarationKind::Variable
        | GoDeclarationKind::Field
        | GoDeclarationKind::EmbeddedField
        | GoDeclarationKind::InterfaceMethod => None,
    }
}
