//! Go structures, projected from the one Go grammar inventory.
//!
//! Nothing here walks a tree. [`GoFileFacts`] is the sole Go declaration
//! authority in this workspace, so recognizing Go declarations a second time
//! would be a second grammar mapping that could answer differently. The
//! projection is total: every declaration kind the inventory states maps to one
//! structure, so a complete fact inventory yields a complete structure
//! inventory.

use pedant_types::StructureKind;

use crate::go::{GoDeclarationKind, GoFactSpan, GoFileFacts};
use crate::language::SyntaxLanguage;
use crate::span::LineSpan;
use crate::structure::builder::{InventoryBuilder, lines_between};
use crate::structure::error::StructureError;
use crate::structure::inventory::StructureInventory;
use crate::structure::limits::{StructureInventoryLimits, admits};

/// Project every structure `facts` states.
///
/// This projection descends nothing, so the depth ceiling in `limits` bounds no
/// descent here — but it still refuses. The walk that produced `facts` ran
/// beneath a ceiling of its own, and on the public route a caller reaches with a
/// retained inventory the two need not be the same number: an inventory walked
/// deeper than this caller admits would otherwise be projected whole, with the
/// stated ceiling silently waived. The depth that walk reported is put to
/// [`admits`], the crate's one depth comparison, before anything is projected —
/// a comparison rather than a descent check, so the walk's own single descent
/// site is untouched and no third spelling of the ceiling exists to widen.
///
/// A recovery tree refuses: an inventory taken from one states a declaration
/// set the source may not have, and the declarations it dropped look exactly
/// like declarations the source never wrote. Both refusals are read in one
/// match, so the order between them is stated rather than left to two guards.
/// `structure::bound` refuses a recovery tree before it walks, so this is the
/// retained-inventory route's own check rather than the one that route pays.
pub(crate) fn inventory<'source>(
    facts: &GoFileFacts<'source>,
    limits: StructureInventoryLimits,
) -> Result<StructureInventory<'source>, StructureError> {
    let limit = limits.max_syntax_depth();
    match (admits(facts.syntax_depth(), limit), facts.has_errors()) {
        (false, _) => return Err(StructureError::SyntaxDepthExceeded { limit }),
        (true, true) => {
            return Err(StructureError::Recovered {
                language: SyntaxLanguage::Go,
            });
        }
        (true, false) => (),
    }
    // The clause is read once, because two readings decide two things that must
    // agree: how many rows the projection states, and whether the positions
    // behind it shift.
    let clause = facts.package_name().zip(facts.package_span());
    // This projection knows its exact length before it retains anything — one
    // structure per declaration, plus the clause ahead of them — so the table is
    // reserved rather than grown by doubling and copied at `into_boxed_slice`.
    let stated = facts.declarations().len() + usize::from(clause.is_some());
    let mut builder = InventoryBuilder::with_capacity(facts.source(), limits, stated);
    let package = project_package(clause, &mut builder)?;
    // A declaration's owner is a position in the declaration list, so the
    // package clause ahead of it shifts every position by one. Saturating, the
    // way every other narrowing in this module is: the builder already refuses a
    // count no `u32` can hold, so the sum is reachable — but an unchecked one is
    // a panic at a library boundary rather than a refusal.
    let offset = u32::from(package.is_some());
    for declaration in facts.declarations() {
        let span = declaration.span();
        builder.retain(
            structure_kind(declaration.kind()),
            Some(declaration.name()),
            span.byte_range(),
            lines(span),
            declaration
                .parent()
                .map(|owner| owner.saturating_add(offset)),
        )?;
    }
    Ok(builder.seal(SyntaxLanguage::Go))
}

/// Retain the package clause, when the source states one.
///
/// The clause opens the file and owns no declaration: its extent is the
/// declared name, which contains none of the members that name it.
///
/// Takes the clause rather than the facts, because its caller has already read
/// it to size the table it retains into.
fn project_package<'source>(
    clause: Option<(&'source str, GoFactSpan)>,
    builder: &mut InventoryBuilder<'source>,
) -> Result<Option<u32>, StructureError> {
    let Some((name, span)) = clause else {
        return Ok(None);
    };
    builder
        .retain(
            StructureKind::Package,
            Some(name),
            span.byte_range(),
            lines(span),
            None,
        )
        .map(Some)
}

/// The one-based inclusive lines one Go fact span covers.
///
/// A fact already carries the grammar positions its ends fall at, so the lines
/// are read from the same span the bytes are rather than counted a second time
/// over the source.
fn lines(span: GoFactSpan) -> LineSpan {
    lines_between(span.start_line(), span.end_line(), span.end_column())
}

/// The structure one Go declaration states.
///
/// The crate's one mapping from the Go vocabulary into the neutral one, and the
/// unit model is a narrowing of it rather than a second copy: `go::facts` reads
/// this table and puts the answer to
/// [`SourceUnitKind::of`](crate::SourceUnitKind::of), the way the Rust and
/// tree-sitter backends already do. A second table restating these rows is what
/// let one declaration kind be a structure an outline named and a unit
/// extraction refused.
///
/// Total, so a twelfth declaration kind fails to compile here rather than
/// dropping out of an inventory that still claims completeness. An embedded
/// field is a field, and an interface's method is a method: both are members
/// their owner declares, and the model states no narrower kind for either.
pub(crate) fn structure_kind(kind: GoDeclarationKind) -> StructureKind {
    match kind {
        GoDeclarationKind::Function => StructureKind::Function,
        GoDeclarationKind::Method | GoDeclarationKind::InterfaceMethod => StructureKind::Method,
        GoDeclarationKind::Struct => StructureKind::Struct,
        GoDeclarationKind::Interface => StructureKind::Interface,
        GoDeclarationKind::DefinedType => StructureKind::DefinedType,
        GoDeclarationKind::TypeAlias => StructureKind::TypeAlias,
        GoDeclarationKind::Constant => StructureKind::Constant,
        GoDeclarationKind::Variable => StructureKind::Variable,
        GoDeclarationKind::Field | GoDeclarationKind::EmbeddedField => StructureKind::Field,
    }
}
