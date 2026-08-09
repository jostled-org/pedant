//! What each reference denotes, and how certain that answer is.
//!
//! Certainty is decided here rather than during lookup, because it depends on
//! the conditions the reference, the definition, the module instances holding
//! them, and their Cargo units all inherit. This tier evaluates no predicate:
//! a non-empty condition anywhere along that chain makes every candidate
//! possible and adds the conditional-compilation gap.

use pedant_types::{CandidateInput, ResolutionCertainty, ResolutionGap, ResolutionReportBuilder};

use crate::ir::cfg::RustCfgCondition;
use crate::ir::sites::{ReferenceOrigin, ReferenceSite};
use crate::resolution::rust::limits::ResolutionLimits;
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use super::corpus::Corpus;
use super::error::RustResolutionError;
use super::imports::Imports;
use super::lookup::{Outcome, Target, resolve_path};
use super::promotion::{Promoted, Promotion, PromotionSite};
use super::references::ReferenceEntry;

/// What one reference denotes, before certainty is applied.
struct Denotation {
    candidates: Box<[usize]>,
    gap: Option<ResolutionGap>,
    /// Whether the candidates are one dispatch set rather than one proved
    /// definition.
    enumerated: bool,
}

/// State one record per reference.
pub(super) fn write<P: Promotion>(
    builder: &mut ResolutionReportBuilder,
    corpus: &Corpus<'_>,
    answers: (&Imports, &P),
    request: (&RustResolutionSnapshot, &[ReferenceEntry], ResolutionLimits),
) -> Result<(), RustResolutionError> {
    let (snapshot, entries, limits) = request;
    for (index, entry) in entries.iter().enumerate() {
        write_one(builder, corpus, answers, (snapshot, (index, entry), limits))?;
    }
    Ok(())
}

fn write_one<P: Promotion>(
    builder: &mut ResolutionReportBuilder,
    corpus: &Corpus<'_>,
    answers: (&Imports, &P),
    request: (
        &RustResolutionSnapshot,
        (usize, &ReferenceEntry),
        ResolutionLimits,
    ),
) -> Result<(), RustResolutionError> {
    let (imports, promotion) = answers;
    let (snapshot, (index, entry), limits) = request;
    let Some(site) = reference_site(corpus, snapshot, entry) else {
        return Ok(());
    };
    let denotation = match promoted_site(corpus, entry).and_then(|at| promotion.promote(at)) {
        Some(proved) => promoted(proved),
        None => denote(corpus, imports, (index, entry), site),
    };
    check_fan_out(&denotation, limits)?;
    let condition = effective(corpus, entry, site);
    let conditional = is_conditional(corpus, &condition, &denotation.candidates);
    let certainty = certainty_of(&denotation.candidates, conditional || denotation.enumerated);
    builder.set_resolution(
        &entry.handle,
        candidates(corpus, &denotation.candidates, certainty),
        gaps(&denotation, conditional),
    )?;
    Ok(())
}

/// Where one reference sits, as a later tier addresses it.
fn promoted_site(corpus: &Corpus<'_>, entry: &ReferenceEntry) -> Option<PromotionSite> {
    let node = corpus.graph.nodes.get(entry.node)?;
    Some(PromotionSite::new(node.unit, node.file, &entry.span))
}

/// What a later tier proved, as this tier's denotation.
fn promoted(proved: Promoted) -> Denotation {
    Denotation {
        candidates: proved.candidates,
        gap: None,
        enumerated: proved.enumerated,
    }
}

fn reference_site<'a>(
    corpus: &Corpus<'_>,
    snapshot: &'a RustResolutionSnapshot,
    entry: &ReferenceEntry,
) -> Option<&'a ReferenceSite> {
    corpus
        .graph
        .file_ir(snapshot, entry.node)?
        .reference_sites
        .get(entry.site)
}

/// The targets one reference names, or the gap that stopped it.
///
/// Every origin is named rather than folded into a catch-all, so a ninth one
/// cannot be resolved as an ordinary path by default.
fn denote(
    corpus: &Corpus<'_>,
    imports: &Imports,
    stated: (usize, &ReferenceEntry),
    site: &ReferenceSite,
) -> Denotation {
    let (index, entry) = stated;
    match site.origin() {
        ReferenceOrigin::MacroInvocation => refused(ResolutionGap::MacroExpansion),
        ReferenceOrigin::MethodCall => method(corpus, entry.node, site),
        ReferenceOrigin::Import => imported(corpus, imports, (index, entry), site),
        ReferenceOrigin::ModuleDeclaration
        | ReferenceOrigin::ExpressionPath
        | ReferenceOrigin::CallPath
        | ReferenceOrigin::TypeMention
        | ReferenceOrigin::Implementation => from_outcome(
            corpus,
            &resolve_path(corpus, imports.bindings(), entry.node, site.segments()),
        ),
    }
}

/// An import's own record reuses what the fixed point already resolved for it.
///
/// That outcome was computed under the bindings this record is written against,
/// so reusing it is the same answer resolving the path again would produce.
fn imported(
    corpus: &Corpus<'_>,
    imports: &Imports,
    stated: (usize, &ReferenceEntry),
    site: &ReferenceSite,
) -> Denotation {
    let (index, entry) = stated;
    match imports.outcome(index) {
        Some(outcome) => from_outcome(corpus, outcome),
        None => from_outcome(
            corpus,
            &resolve_path(corpus, imports.bindings(), entry.node, site.segments()),
        ),
    }
}

/// A method call resolves only when the receiver's type is established.
fn method(corpus: &Corpus<'_>, node: usize, site: &ReferenceSite) -> Denotation {
    let Some(receiver) = site.receiver() else {
        return refused(ResolutionGap::DynamicDispatch);
    };
    let found: Box<[usize]> = corpus
        .index
        .associated(receiver, &site.text)
        .iter()
        .filter(|slot| corpus.holds(node, **slot))
        .copied()
        .collect();
    match found.is_empty() {
        true => refused(ResolutionGap::MissingDefinition),
        false => Denotation {
            candidates: found,
            gap: None,
            enumerated: false,
        },
    }
}

fn from_outcome(corpus: &Corpus<'_>, outcome: &Outcome) -> Denotation {
    match outcome {
        Outcome::External => refused(ResolutionGap::ExternalDefinition),
        Outcome::Missing => refused(ResolutionGap::MissingDefinition),
        Outcome::Unsupported => refused(ResolutionGap::UnsupportedSyntax),
        Outcome::Found(targets) => found(corpus, targets),
    }
}

/// A crate root has no definition site, so a path that ends at one names
/// something outside the report's definition inventory.
fn found(corpus: &Corpus<'_>, targets: &[Target]) -> Denotation {
    let mut candidates: Vec<usize> = targets
        .iter()
        .filter_map(|target| slot_of(corpus, target))
        .collect();
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.is_empty() {
        true => refused(ResolutionGap::ExternalDefinition),
        false => Denotation {
            candidates: candidates.into_boxed_slice(),
            gap: None,
            enumerated: false,
        },
    }
}

fn slot_of(corpus: &Corpus<'_>, target: &Target) -> Option<usize> {
    match target {
        Target::Definition(slot) => Some(*slot),
        Target::Module(node) => corpus.index.module_slot(*node),
    }
}

fn refused(gap: ResolutionGap) -> Denotation {
    Denotation {
        candidates: Box::from([]),
        gap: Some(gap),
        enumerated: false,
    }
}

/// The condition a reference inherits: its own, its module instance's, and its
/// Cargo unit's activation.
fn effective(
    corpus: &Corpus<'_>,
    entry: &ReferenceEntry,
    site: &ReferenceSite,
) -> RustCfgCondition {
    let node = corpus.graph.nodes.get(entry.node);
    let inherited = node
        .map(|found| found.condition.clone())
        .unwrap_or_default();
    let activation = node
        .and_then(|found| corpus.units.conditions.get(found.unit))
        .cloned()
        .unwrap_or_default();
    inherited.and(&activation).and(site.condition())
}

fn is_conditional(corpus: &Corpus<'_>, condition: &RustCfgCondition, candidates: &[usize]) -> bool {
    !condition.is_empty()
        || candidates.iter().any(|slot| {
            corpus
                .index
                .slot(*slot)
                .is_some_and(|found| !found.condition.is_empty())
        })
}

fn certainty_of(candidates: &[usize], conditional: bool) -> ResolutionCertainty {
    match (candidates.len(), conditional) {
        (1, false) => ResolutionCertainty::Resolved,
        _ => ResolutionCertainty::Possible,
    }
}

fn candidates(
    corpus: &Corpus<'_>,
    slots: &[usize],
    certainty: ResolutionCertainty,
) -> Box<[CandidateInput]> {
    slots
        .iter()
        .filter_map(|slot| corpus.index.slot(*slot))
        .map(|slot| CandidateInput::new(slot.handle.clone(), certainty))
        .collect()
}

fn gaps(denotation: &Denotation, conditional: bool) -> Box<[ResolutionGap]> {
    let dynamic = denotation
        .enumerated
        .then_some(ResolutionGap::DynamicDispatch);
    let ambiguous = (denotation.candidates.len() > 1).then_some(ResolutionGap::Ambiguous);
    let stated = conditional.then_some(ResolutionGap::ConditionalCompilation);
    denotation
        .gap
        .into_iter()
        .chain(dynamic)
        .chain(ambiguous)
        .chain(stated)
        .collect()
}

/// Candidate fan-out is never truncated: an overflowing reference refuses the
/// whole resolution instead of reporting a misleadingly complete answer.
fn check_fan_out(
    denotation: &Denotation,
    limits: ResolutionLimits,
) -> Result<(), RustResolutionError> {
    let ceiling = limits.max_candidates_per_reference;
    match u64::try_from(denotation.candidates.len()).unwrap_or(u64::MAX) > u64::from(ceiling) {
        true => Err(RustResolutionError::LimitExceeded { limit: ceiling }),
        false => Ok(()),
    }
}
