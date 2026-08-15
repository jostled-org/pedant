//! Sealing one draft into the complete capability analysis envelope.
//!
//! The flat profile keeps detection order exactly as drafted. Symbol profiles
//! follow declaration order, because `FileIr::functions` is filled in traversal
//! order, and each profile keeps its findings in flat detection order.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_types::{
    CapabilityAnalysis, CapabilityFinding, CapabilityProfile, CapabilitySymbol,
    CapabilitySymbolKind, Language, SourceLocation, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

use crate::ir::FileIr;
use crate::ir::facts::FnFact;

use super::draft::{CapabilityDraft, DraftedFinding};

/// Seal `draft` against the callable inventory `ir` states.
///
/// The status is [`SymbolAttributionStatus::Complete`]: every drafted finding
/// was classified against the whole of `FileIr::functions`. That is a claim
/// about the inventory the caller supplied, not about parse provenance.
pub(crate) fn project_analysis(ir: &FileIr, draft: CapabilityDraft) -> CapabilityAnalysis {
    let entries = draft.into_entries();
    let symbols = symbol_profiles(ir, &entries);
    let findings: Box<[CapabilityFinding]> =
        entries.into_iter().map(|entry| entry.finding).collect();
    CapabilityAnalysis {
        profile: CapabilityProfile { findings },
        symbol_attribution: SymbolAttributionStatus::Complete,
        symbols,
    }
}

/// Every callable that owns at least one drafted finding, in declaration order.
fn symbol_profiles(ir: &FileIr, entries: &[DraftedFinding]) -> Box<[SymbolCapabilityProfile]> {
    grouped_by_callable(entries)
        .into_iter()
        .filter_map(|(index, positions)| profile_for(ir, entries, index, &positions))
        .collect()
}

/// Flat positions of the attributed findings, keyed by callable index.
///
/// A `BTreeMap` puts the callables in declaration order, because the extractor
/// fills `FileIr::functions` in traversal order. Module-scope evidence names no
/// index and so contributes no group at all.
fn grouped_by_callable(entries: &[DraftedFinding]) -> BTreeMap<usize, Vec<usize>> {
    let mut grouped: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (position, entry) in entries.iter().enumerate() {
        if let Some(index) = entry.containing_fn {
            grouped.entry(index).or_default().push(position);
        }
    }
    grouped
}

/// One callable's profile, cloning only the finding records it owns.
///
/// The clones are fixed-size records: their file and evidence payloads are
/// `Arc<str>` values shared with the flat profile, so grouping allocates no
/// string. An index naming no declared function states no callable, so its
/// findings stay flat evidence and every emitted profile is non-empty.
fn profile_for(
    ir: &FileIr,
    entries: &[DraftedFinding],
    index: usize,
    positions: &[usize],
) -> Option<SymbolCapabilityProfile> {
    let declared = ir.functions.get(index)?;
    let findings = positions
        .iter()
        .map(|&position| entries[position].finding.clone())
        .collect();
    Some(SymbolCapabilityProfile {
        symbol: symbol(&ir.file_path, declared),
        profile: CapabilityProfile { findings },
    })
}

/// The lexical identity one declared function states.
fn symbol(file: &Arc<str>, declared: &FnFact) -> CapabilitySymbol {
    CapabilitySymbol {
        language: Language::Rust,
        kind: match declared.is_associated {
            true => CapabilitySymbolKind::Method,
            false => CapabilitySymbolKind::Function,
        },
        name: declared.name.clone(),
        declaration: SourceLocation {
            file: Arc::clone(file),
            line: declared.span.line,
            column: declared.span.column + 1,
        },
    }
}
