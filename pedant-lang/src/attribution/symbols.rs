//! Classifying flat findings against one bound parse session.
//!
//! The session is the backend's own: it produced the structured findings and it
//! answers the declaration questions here, so one source is parsed once.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_syntax::tree_sitter::ParsedSyntax;
use pedant_syntax::{Location, SourceUnitKind};
use pedant_types::{
    CapabilityAnalysis, CapabilityFinding, CapabilityProfile, CapabilitySymbol,
    CapabilitySymbolKind, Language, SourceLocation, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

use super::envelope::{seal_with, unavailable};

/// Seal one structured analysis against the session that produced it.
///
/// `session` is absent when this build links no grammar for the source and when
/// the parser produced no tree. An error-bearing recovery tree is present but
/// incomplete: its findings stay, and attribution does not run. Both report
/// [`SymbolAttributionStatus::Unavailable`].
pub(crate) fn seal(
    session: Option<ParsedSyntax<'_>>,
    language: Language,
    findings: Box<[CapabilityFinding]>,
) -> CapabilityAnalysis {
    match session.filter(|parsed| !parsed.has_errors()) {
        Some(parsed) => {
            let symbols = symbol_profiles(&parsed, language, &findings);
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
/// The kind and name ride along from the first anchor that named this
/// declaration, because re-asking the session for them would be a second query
/// answering what the first already did.
struct Attributed {
    kind: CapabilitySymbolKind,
    name: Box<str>,
    /// Flat positions of this callable's findings, in detection order.
    positions: Vec<usize>,
}

/// Every callable that owns at least one finding, in declaration order.
fn symbol_profiles(
    parsed: &ParsedSyntax<'_>,
    language: Language,
    findings: &[CapabilityFinding],
) -> Box<[SymbolCapabilityProfile]> {
    grouped_by_callable(parsed, findings)
        .into_iter()
        .filter_map(|(declaration, owned)| profile_for(declaration, owned, language, findings))
        .collect()
}

/// Flat positions of the attributed findings, keyed by owning callable.
///
/// A `BTreeMap` puts the callables in declaration order, because the key opens
/// with the declaration's own position. Evidence at module scope, inside a
/// class body but outside its methods, or inside an anonymous callable names no
/// owner and so contributes no group at all.
fn grouped_by_callable(
    parsed: &ParsedSyntax<'_>,
    findings: &[CapabilityFinding],
) -> BTreeMap<Declaration, Attributed> {
    let mut grouped: BTreeMap<Declaration, Attributed> = BTreeMap::new();
    for (position, finding) in findings.iter().enumerate() {
        let Some(owner) = callable_owner(parsed, finding) else {
            continue;
        };
        grouped
            .entry(owner.declaration)
            .or_insert_with(|| Attributed {
                kind: owner.kind,
                name: owner.name,
                positions: Vec::new(),
            })
            .positions
            .push(position);
    }
    grouped
}

/// The named function or method containing one finding, if any.
///
/// Only a named [`SourceUnitKind::Function`] or [`SourceUnitKind::Method`]
/// carries a capability symbol. A class, a type, an enum, and an unnamed
/// declaration are lexical owners the model states no symbol for, so their
/// findings stay flat evidence.
fn callable_owner(parsed: &ParsedSyntax<'_>, finding: &CapabilityFinding) -> Option<CallableOwner> {
    let at = Location {
        line: finding.location.line,
        column: Some(finding.location.column),
    };
    let anchor = parsed.enclosing_unit_anchor(at)?;
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
    Some(CallableOwner {
        declaration: (anchor.start.line, anchor.start.column?),
        kind,
        name: anchor.name?,
    })
}

/// One callable's profile, cloning only the finding records it owns.
///
/// The clones are fixed-size records: their file and evidence payloads are
/// `Arc<str>` values shared with the flat profile, so grouping allocates no
/// string. The declaration's file comes from the group's own first finding,
/// which shares that same `Arc<str>`. A group with no member states no
/// callable, so every emitted profile is non-empty.
fn profile_for(
    declaration: Declaration,
    owned: Attributed,
    language: Language,
    findings: &[CapabilityFinding],
) -> Option<SymbolCapabilityProfile> {
    let members: Box<[CapabilityFinding]> = owned
        .positions
        .iter()
        .map(|&position| findings[position].clone())
        .collect();
    let file = Arc::clone(&members.first()?.location.file);
    let (line, column) = declaration;
    Some(SymbolCapabilityProfile {
        symbol: CapabilitySymbol {
            language,
            kind: owned.kind,
            name: owned.name,
            declaration: SourceLocation { file, line, column },
        },
        profile: CapabilityProfile { findings: members },
    })
}
