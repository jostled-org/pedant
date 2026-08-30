//! The loose structure inventory, taken beneath the remaining repository
//! allowance.
//!
//! Every structure a loose inventory emits is a new physical record, so the
//! per-source ceiling this build runs under is clamped to what the repository
//! has left before the walk starts. Clamping before rather than refusing after
//! is the whole point: a walk that recognized a thousand structures the index
//! then had to discard has already spent the work the ceiling exists to bound.

use std::path::Path;
use std::sync::Arc;

use pedant_syntax::{
    Language, StructureInventoryLimits, StructureRecord, SyntaxLanguage, structure_inventory,
    syntax_language,
};

use super::error::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, capacity, first_excess,
};
use super::profile;

/// Every structure one loose source declares, in source order.
///
/// A language this build links no inventory for is a refusal rather than an
/// empty answer: an empty inventory means the source declares nothing, and a
/// build that cannot read Python must not say that about a Python file.
///
/// That refusal is its own variant rather than a parse failure carrying a
/// sentence. A file this build never opened and a file it read and could not
/// parse reach an operator under the same stage, and only the code separates
/// them.
///
/// A path whose grammar the substrate names is refused the same way, and it is
/// the same fact: this build links no inventory that reads it.
pub(crate) fn inventory(
    path: &Arc<str>,
    language: Language,
    text: &str,
    limits: StructureInventoryLimits,
    remaining_structures: u64,
) -> Result<Box<[StructureRecord]>, CodeIntelligenceError> {
    if !profile::reads(language) {
        return Err(unavailable(path));
    }
    let Some(stated) = grammar(path, text) else {
        return Err(unavailable(path));
    };
    let clamped = clamp(limits, remaining_structures)?;
    let walked = structure_inventory(text, stated, clamped)
        .map_err(|error| inventory_fault(path, error, limits, remaining_structures))?;
    Ok(walked.retained())
}

/// This build links no structure inventory for one source's language.
fn unavailable(path: &Arc<str>) -> CodeIntelligenceError {
    CodeIntelligenceError::LanguageUnavailable {
        path: Box::from(&**path),
    }
}

/// One loose inventory refusal, retaining the typed ceiling when it was one.
fn inventory_fault(
    path: &Arc<str>,
    error: pedant_syntax::StructureError,
    limits: StructureInventoryLimits,
    remaining: u64,
) -> CodeIntelligenceError {
    match error {
        pedant_syntax::StructureError::SyntaxDepthExceeded { limit } => capacity(
            CapacityOwner::Syntax,
            CapacityCollection::SyntaxDepth,
            first_excess(limit),
            u64::from(limit),
        ),
        pedant_syntax::StructureError::StructureCapacityExceeded { limit } => capacity(
            structure_owner(limits, remaining),
            CapacityCollection::Structure,
            first_excess(limit),
            u64::from(limit),
        ),
        other => CodeIntelligenceError::Parser {
            path: Box::from(&**path),
            reason: other.to_string().into_boxed_str(),
        },
    }
}

/// The owner of the structure ceiling clamped into one loose inventory.
fn structure_owner(limits: StructureInventoryLimits, remaining: u64) -> CapacityOwner {
    match remaining <= u64::from(limits.max_structures_per_source()) {
        true => CapacityOwner::Repository,
        false => CapacityOwner::Syntax,
    }
}

/// The per-source ceiling, lowered to what the repository still admits.
///
/// The depth is passed through rather than checked. `StructureInventoryLimits`
/// keeps private fields, its constructor refuses a zero depth, its default is
/// 256, and the registry row that writes it floors every value at one — so a
/// zero depth is a value no caller can hand this function, and a branch that
/// minted a refusal for it named a failure no input produces.
fn clamp(
    limits: StructureInventoryLimits,
    remaining: u64,
) -> Result<StructureInventoryLimits, CodeIntelligenceError> {
    let ceiling = u64::from(limits.max_structures_per_source()).min(remaining);
    let narrowed = super::count::narrowed(ceiling);
    StructureInventoryLimits::new(limits.max_syntax_depth(), narrowed).ok_or_else(|| {
        capacity(
            structure_owner(limits, remaining),
            CapacityCollection::Structure,
            first_excess(0_u32),
            0,
        )
    })
}

/// Which grammar reads one recognized source.
///
/// The syntax substrate's own dispatch is asked because it alone distinguishes
/// `.tsx` from `.ts`: the shared [`Language`] token carries `TypeScript` for
/// both spellings, and the two are read by different grammars. Answering from
/// that token instead would hand a `.tsx` file the grammar that cannot parse
/// it.
///
/// Absent where the substrate names no grammar for the path, which the caller
/// states as the refusal it is rather than covering with a second answer.
fn grammar(path: &str, text: &str) -> Option<SyntaxLanguage> {
    syntax_language(Path::new(path), text)
}
