//! Classifying flat findings against one declaration authority.
//!
//! The authority is the backend's own: it produced the structured findings and
//! it answers the declaration questions here, so one source is parsed once and
//! its declarations are read once.
//!
//! It is also asked once. Every finding's location goes over in a single batch
//! query, so the source is indexed once and read once for the whole file rather
//! than once per finding.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_syntax::tree_sitter::SourceUnitAnchor;
use pedant_syntax::{Location, SourceUnitKind};
use pedant_types::{
    CapabilityAnalysis, CapabilityFinding, CapabilityProfile, CapabilitySymbol,
    CapabilitySymbolKind, Language, SourceLocation, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

use super::anchors::DeclarationAnchors;
use super::envelope::{seal_with, unavailable};

/// Seal one structured analysis against the authority that produced it.
///
/// `authority` is absent when this build links no grammar for the source and
/// when the parser produced no tree. An error-bearing recovery tree is present
/// but incomplete: its findings stay, and attribution does not run. Both report
/// [`SymbolAttributionStatus::Unavailable`].
pub(crate) fn seal<A: DeclarationAnchors>(
    authority: Option<A>,
    language: Language,
    findings: Box<[CapabilityFinding]>,
) -> CapabilityAnalysis {
    match authority.filter(|held| !held.has_errors()) {
        Some(held) => {
            let symbols = symbol_profiles(&held, language, &findings);
            seal_with(findings, SymbolAttributionStatus::Complete, symbols)
        }
        None => unavailable(findings),
    }
}

/// One-based line and UTF-8 byte column of a declaration's first byte.
///
/// The whole identity of a callable within one file: two declarations cannot
/// open at the same byte. Ordering it orders the callables by declaration.
type Declaration = (usize, usize);

/// The callable a finding's anchor names.
struct CallableOwner {
    declaration: Declaration,
    kind: CapabilitySymbolKind,
    name: Box<str>,
}

/// One callable and the flat positions of the findings it owns.
///
/// The kind, the name, and the file ride along from the first finding that
/// named this declaration, because re-asking for them would be a second query
/// answering what the first already did. The file is one `Arc` clone per
/// callable, shared with the flat profile rather than reallocated.
struct Attributed {
    kind: CapabilitySymbolKind,
    name: Box<str>,
    file: Arc<str>,
    /// Flat positions of this callable's findings, in detection order. Never
    /// empty: the entry is created by the same expression that pushes the first
    /// position.
    positions: Vec<usize>,
}

/// Every callable that owns at least one finding, in declaration order.
fn symbol_profiles<A: DeclarationAnchors>(
    authority: &A,
    language: Language,
    findings: &[CapabilityFinding],
) -> Box<[SymbolCapabilityProfile]> {
    grouped_by_callable(authority, findings)
        .into_iter()
        .map(|(declaration, owned)| profile_for(declaration, owned, language, findings))
        .collect()
}

/// Flat positions of the attributed findings, keyed by owning callable.
///
/// One batch query answers for every finding at once, so the authority indexes
/// its source once and reads its declarations once however many findings
/// arrive. The answers come back in the order the locations went over, which is
/// detection order, so a slot's index is its finding's flat position.
///
/// A `BTreeMap` puts the callables in declaration order, because the key opens
/// with the declaration's own position. Evidence at module scope, inside a
/// class body but outside its methods, or inside an anonymous callable names no
/// owner and so contributes no group at all.
fn grouped_by_callable<A: DeclarationAnchors>(
    authority: &A,
    findings: &[CapabilityFinding],
) -> BTreeMap<Declaration, Attributed> {
    let at: Box<[Location]> = findings
        .iter()
        .map(|finding| Location {
            line: finding.location.line,
            column: Some(finding.location.column),
        })
        .collect();
    let mut grouped: BTreeMap<Declaration, Attributed> = BTreeMap::new();
    for (position, anchor) in authority.anchors(&at).into_iter().enumerate() {
        let Some(owner) = anchor.and_then(callable_owner) else {
            continue;
        };
        grouped
            .entry(owner.declaration)
            .or_insert_with(|| Attributed {
                kind: owner.kind,
                name: owner.name,
                file: Arc::clone(&findings[position].location.file),
                positions: Vec::new(),
            })
            .positions
            .push(position);
    }
    grouped
}

/// The named function or method one anchor names, if any.
///
/// Only a named [`SourceUnitKind::Function`] or [`SourceUnitKind::Method`]
/// carries a capability symbol. A class, a type, an enum, and an unnamed
/// declaration are lexical owners the model states no symbol for, so their
/// findings stay flat evidence.
fn callable_owner(anchor: SourceUnitAnchor) -> Option<CallableOwner> {
    let kind = match anchor.kind {
        SourceUnitKind::Function => CapabilitySymbolKind::Function,
        SourceUnitKind::Method => CapabilitySymbolKind::Method,
        SourceUnitKind::Struct
        | SourceUnitKind::Enum
        | SourceUnitKind::Union
        | SourceUnitKind::Trait
        | SourceUnitKind::TypeAlias
        | SourceUnitKind::Impl
        | SourceUnitKind::Class => return None,
    };
    // An absent name is a legitimate answer: an anonymous callable owns its
    // findings lexically and carries no symbol.
    let name = anchor.name?;
    // An absent column is not. An anchor's start comes from a byte offset, so
    // it always carries one; reporting "no callable owner" for a broken
    // invariant would drop the finding while still claiming a complete
    // attribution.
    debug_assert!(
        anchor.start.column.is_some(),
        "an anchor's start carries a column"
    );
    let column = anchor.start.column?;
    Some(CallableOwner {
        declaration: (anchor.start.line, column),
        kind,
        name,
    })
}

/// One callable's profile, cloning only the finding records it owns.
///
/// The clones are fixed-size records: their file and evidence payloads are
/// `Arc<str>` values shared with the flat profile, so grouping allocates no
/// string. The declaration's file is the one its group's first finding named,
/// carried on the group since it was opened.
fn profile_for(
    declaration: Declaration,
    owned: Attributed,
    language: Language,
    findings: &[CapabilityFinding],
) -> SymbolCapabilityProfile {
    let members: Box<[CapabilityFinding]> = owned
        .positions
        .iter()
        .map(|&position| findings[position].clone())
        .collect();
    let (line, column) = declaration;
    SymbolCapabilityProfile {
        symbol: CapabilitySymbol {
            language,
            kind: owned.kind,
            name: owned.name,
            declaration: SourceLocation {
                file: owned.file,
                line,
                column,
            },
        },
        profile: CapabilityProfile { findings: members },
    }
}
