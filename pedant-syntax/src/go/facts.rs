//! The bounded inventory one Go source states.

use crate::extract::select::UnitSelector;
use crate::go::binding::GoBindingFact;
use crate::go::condition::GoBuildConditionFact;
use crate::go::declaration::{GoDeclarationFact, GoDeclarationKind};
use crate::go::error::GoFactError;
use crate::go::import::GoImportFact;
use crate::go::inventory::Inventory;
use crate::go::limits::GoFactLimits;
use crate::go::reference::GoReferenceFact;
use crate::go::retention::GoFactScope;
use crate::go::scope::GoScopeFact;
use crate::go::signature::GoSignatureTermFact;
use crate::go::span::GoFactSpan;
use crate::go::walk;
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
    facts: u32,
    depth: u32,
}

impl<'source> GoFileFacts<'source> {
    /// Walk one bound Go tree once and seal every fact it states.
    pub(crate) fn extract(
        root: Node<'_>,
        source: &'source str,
        has_errors: bool,
        limits: GoFactLimits,
    ) -> Result<Self, GoFactError> {
        walked(root, source, has_errors, limits, GoFactScope::Everything)
    }

    /// Seal one completed walk.
    fn seal(inventory: Inventory<'source>, source: &'source str, has_errors: bool) -> Self {
        // Read before the fields move: `depth` is behind an accessor, so a
        // reading taken in field position borrows an inventory the boxing above
        // it has already partially moved.
        let depth = inventory.depth();
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
            facts: inventory.counted,
            depth,
        }
    }

    /// How many facts the bounded walk retained, as its ceiling counts them.
    ///
    /// Stated so a consumer that shares one extraction across several bounded
    /// corpora can hold it to each corpus's own fact ceiling without walking
    /// the tree again.
    pub fn fact_count(&self) -> u32 {
        self.facts
    }

    /// The deepest grammar level the bounded walk entered, the root counting as
    /// zero.
    pub fn syntax_depth(&self) -> u32 {
        self.depth
    }

    /// The exact source every span here indexes.
    ///
    /// Crate-visible: the structure projection slices this string, and a caller
    /// outside the crate already holds the source it handed the parser.
    pub(crate) fn source(&self) -> &'source str {
        self.source
    }

    /// Every logical structure these facts state, in source order.
    ///
    /// Walks nothing and parses nothing: this inventory is already the sole Go
    /// declaration authority, so the structure set is projected from it rather
    /// than recognized a second time.
    ///
    /// Refuses on a recovery tree and on the structure ceiling in `limits`. The
    /// depth ceiling has no descent left to bound here, so it is compared
    /// against the depth the walk already reported: a caller holding a retained
    /// inventory may state a shallower ceiling than the one that walk ran
    /// beneath, and an inventory deeper than the ceiling stated here is refused
    /// rather than projected whole.
    pub fn structure_inventory(
        &self,
        limits: crate::StructureInventoryLimits,
    ) -> Result<crate::StructureInventory<'source>, crate::StructureError> {
        crate::structure::go_inventory(self, limits)
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

/// Walk one bound Go tree for the facts a structure inventory projects.
///
/// Declarations, the scopes that place them, and the package clause. The
/// projection reads nothing else, and every fact a walk retains is charged
/// against the same ceiling, so a whole-inventory walk here spent the structure
/// route's own ceiling on imports, references, bindings, and signature terms it
/// then dropped.
///
/// The inventory this seals is therefore partial by construction, and the
/// structure router is its one caller: it projects the structures and drops the
/// facts in the same expression. Every other reader asks
/// [`GoFileFacts::extract`].
///
/// A function beside the sealed type rather than a second constructor on it,
/// for the reason [`offer_units`] is one: what a walk retains is a property of
/// the caller that asked for it, not of the inventory it fills.
pub(crate) fn structure_facts<'source>(
    root: Node<'_>,
    source: &'source str,
    has_errors: bool,
    limits: GoFactLimits,
) -> Result<GoFileFacts<'source>, GoFactError> {
    walked(
        root,
        source,
        has_errors,
        limits,
        GoFactScope::DeclaredStructures,
    )
}

/// Walk one bound Go tree once for `retained`, and seal what it held.
///
/// The one body both sealing entry points call. They differ in the scope they
/// name and in nothing else, so a second copy of the walk-then-seal pair was a
/// second place for the tree, the source, and the recovery answer to be bound
/// together — and one of the two could bind them differently.
fn walked<'source>(
    root: Node<'_>,
    source: &'source str,
    has_errors: bool,
    limits: GoFactLimits,
    retained: GoFactScope,
) -> Result<GoFileFacts<'source>, GoFactError> {
    Ok(GoFileFacts::seal(
        walk::extract(root, source, limits, retained)?,
        source,
        has_errors,
    ))
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
/// The Go vocabulary is mapped once — by `structure::go::structure_kind`, the
/// projection's own table — and narrowed here by the unit model, the way the
/// Rust and tree-sitter backends already reach
/// [`SourceUnitKind::of`](crate::SourceUnitKind::of). A second table spelling
/// the same eleven rows is a second place for a declaration kind to be a
/// structure the outline names and a unit the extraction refuses.
///
/// One kind is refused past that narrowing, and [`writes_its_definition`] is
/// where. Every other declaration defers to the unit that contains it because
/// the model states no kind for it.
fn unit_kind(kind: GoDeclarationKind) -> Option<SourceUnitKind> {
    match writes_its_definition(kind) {
        true => SourceUnitKind::of(crate::structure::go_structure_kind(kind)),
        false => None,
    }
}

/// Whether a declaration's own text holds what it defines.
///
/// The Go half of the rule the TypeScript `abstract_method_signature` row
/// states one grammar away: an interface method is a method, and the structure
/// inventory names it one, but its text stops at the signature and whatever
/// type implements it writes the body. A source unit carries the declaration's
/// text, so a reader inside one is handed the interface that declares it.
///
/// Total, so a twelfth declaration kind fails to compile here rather than
/// joining the unit model with a body it does not write.
fn writes_its_definition(kind: GoDeclarationKind) -> bool {
    match kind {
        GoDeclarationKind::InterfaceMethod => false,
        GoDeclarationKind::Function
        | GoDeclarationKind::Method
        | GoDeclarationKind::Struct
        | GoDeclarationKind::Interface
        | GoDeclarationKind::DefinedType
        | GoDeclarationKind::TypeAlias
        | GoDeclarationKind::Constant
        | GoDeclarationKind::Variable
        | GoDeclarationKind::Field
        | GoDeclarationKind::EmbeddedField => true,
    }
}
