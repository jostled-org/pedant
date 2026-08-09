//! Tier 2: promotion bound to a verified semantic snapshot.
//!
//! The handshake runs first and refuses every difference, so no query and no
//! promotion happens against a database that holds other sources than the
//! snapshot. What survives is a set of unit-qualified definition edges, joined
//! to the Tier 1 inventory by unit plus site identity — never by path or name
//! alone. A physical source instantiated under multiple units is refused
//! before this handshake because rust-analyzer cannot provide both unit-local
//! interpretations of one file.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::ResolutionTier;

use crate::ir::semantic::{
    SemanticContext, SemanticDefinitionEdge, SemanticDefinitionTargets, SemanticSite,
};
use crate::observe::{self, Observation};
use crate::resolution::rust::snapshot::RustResolutionSnapshot;

use super::claim;
use super::error::RustResolutionError;
use super::pipeline::{self, Inventory};
use super::promotion::{Promoted, Promotion, PromotionSite};
use super::target::RustTargetResolution;

/// What the database proved about one reference, while it is being collected.
struct Draft {
    candidates: Vec<usize>,
    enumerated: bool,
    path: Arc<str>,
}

/// What the database proved about one reference.
struct Answer {
    candidates: Box<[usize]>,
    enumerated: bool,
    path: Arc<str>,
}

/// Every reference a verified database answered for, addressed the way both
/// tiers name a site.
struct SemanticPromotion {
    answers: BTreeMap<PromotionSite, Answer>,
}

impl Promotion for SemanticPromotion {
    fn promote(&self, site: PromotionSite) -> Option<Promoted> {
        let answer = self.answers.get(&site)?;
        observe::record(Observation::Promotion(&answer.path));
        Some(Promoted {
            candidates: answer.candidates.clone(),
            enumerated: answer.enumerated,
        })
    }
}

/// Resolve `snapshot` against `context`, or refuse the pairing outright.
pub(super) fn resolve(
    snapshot: &RustResolutionSnapshot,
    context: &SemanticContext,
) -> Result<RustTargetResolution, RustResolutionError> {
    if let Some(warning) = snapshot.warnings().first() {
        return Err(RustResolutionError::SemanticSharedSourceMismatch {
            warning: warning.clone(),
        });
    }
    let claim = claim::state(snapshot);
    let verified = context.verify_snapshot(&claim).map_err(|mismatch| {
        RustResolutionError::SemanticContextMismatch {
            reason: mismatch.to_string().into_boxed_str(),
        }
    })?;
    let targets = context.definition_targets(&verified).map_err(|mismatch| {
        RustResolutionError::SemanticContextMismatch {
            reason: mismatch.to_string().into_boxed_str(),
        }
    })?;
    if targets.fingerprint != claim.fingerprint {
        return Err(RustResolutionError::SemanticContextMismatch {
            reason: Box::from("the definition targets answer for another snapshot"),
        });
    }
    let inventory = pipeline::inventory(snapshot, ResolutionTier::Semantic)?;
    let promotion = build(snapshot, &inventory, &targets);
    pipeline::finish(inventory, snapshot, &promotion)
}

/// Join every verified edge to the definition slot it names.
fn build(
    snapshot: &RustResolutionSnapshot,
    inventory: &Inventory,
    targets: &SemanticDefinitionTargets,
) -> SemanticPromotion {
    let definitions = definition_sites(inventory);
    let mut drafts: BTreeMap<PromotionSite, Draft> = BTreeMap::new();
    for edge in &targets.edges {
        join(snapshot, &definitions, &mut drafts, edge);
    }
    SemanticPromotion {
        answers: drafts
            .into_iter()
            .map(|(site, draft)| (site, answer(draft)))
            .collect(),
    }
}

fn answer(draft: Draft) -> Answer {
    let mut candidates = draft.candidates;
    candidates.sort_unstable();
    candidates.dedup();
    Answer {
        candidates: candidates.into_boxed_slice(),
        enumerated: draft.enumerated,
        path: draft.path,
    }
}

fn join(
    snapshot: &RustResolutionSnapshot,
    definitions: &BTreeMap<PromotionSite, usize>,
    drafts: &mut BTreeMap<PromotionSite, Draft>,
    edge: &SemanticDefinitionEdge,
) {
    let (Some(source), Some(target)) = (
        promotion_site(snapshot, &edge.source),
        promotion_site(snapshot, &edge.target),
    ) else {
        return;
    };
    let Some(slot) = definitions.get(&target).copied() else {
        return;
    };
    let draft = drafts.entry(source).or_insert_with(|| Draft {
        candidates: Vec::new(),
        enumerated: edge.enumerated,
        path: Arc::clone(&edge.source.path),
    });
    draft.candidates.push(slot);
    draft.enumerated |= edge.enumerated;
}

/// Where every definition of the inventory sits, as a later tier names it.
///
/// The site is the one the inventory pass already stated, not a second
/// derivation of it: re-deriving meant a second copy of that pass's scope
/// filter and a second line index per node, and a definition the two copies
/// disagreed about would silently promote nothing.
fn definition_sites(inventory: &Inventory) -> BTreeMap<PromotionSite, usize> {
    inventory
        .index
        .slots()
        .iter()
        .enumerate()
        .map(|(slot, definition)| (definition.site, slot))
        .collect()
}

fn promotion_site(snapshot: &RustResolutionSnapshot, site: &SemanticSite) -> Option<PromotionSite> {
    Some(PromotionSite {
        unit: site.unit,
        file: file_index(snapshot, &site.path)?,
        line: site.line,
        column: site.column,
    })
}

/// The position of one normalized path in the snapshot's sorted source store.
fn file_index(snapshot: &RustResolutionSnapshot, path: &str) -> Option<usize> {
    snapshot
        .sources()
        .binary_search_by(|source| source.path().cmp(path))
        .ok()
}
