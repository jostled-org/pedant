//! The written-down ownership table, and the assertions every case reads it with.
//!
//! Every case writes down the complete flat occurrence sequence one source
//! produces and, per occurrence, the callable that must own it. The symbol
//! expectation is derived from that one table by filtering on ownership, so a
//! symbol profile cannot agree with an expectation the flat profile disagrees
//! with.
//!
//! A row's owner is compared by declaration position, not by name: equal names
//! at different declarations are different callables, and that is the point of
//! several cases built on this model.

use std::collections::BTreeMap;

use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, CapabilitySymbolKind, FindingOrigin,
    Language, SymbolAttributionStatus, SymbolCapabilityProfile,
};

use crate::language_probe::{FlatRow, analysis_for, assert_flat_sequence};

/// The callable a flat occurrence belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) kind: CapabilitySymbolKind,
    pub(crate) name: &'static str,
    /// One-based line of the declaration's first byte.
    pub(crate) line: usize,
    /// One-based UTF-8 byte column of the declaration's first byte.
    pub(crate) column: usize,
}

/// One written-down flat occurrence and its owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Row {
    pub(crate) capability: Capability,
    pub(crate) evidence: &'static str,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) origin: FindingOrigin,
    /// The detection family this occurrence proves.
    ///
    /// Every case names its families, and the two lists pin each other in both
    /// directions, so this value is load-bearing on every row rather than only
    /// where a coverage claim happens to read it.
    pub(crate) family: &'static str,
    /// `None` for evidence no callable contains, and for a lexical owner the
    /// symbol model states nothing for.
    pub(crate) owner: Option<Owner>,
}

/// One detection family a case must reach.
pub(crate) struct Family {
    pub(crate) name: &'static str,
    /// Whether a callable owns this family's occurrences in this case.
    ///
    /// `false` states the stronger claim: no occurrence of the family reaches a
    /// symbol profile here. An ES `import` and a Go import declaration are
    /// module-level by grammar, so `false` is the only truthful value for them
    /// anywhere; a bash command is module-level only where a source writes it
    /// that way, and the module case writes it exactly that way.
    pub(crate) owned: bool,
}

/// One source, and everything it must produce.
pub(crate) struct SubCase {
    pub(crate) source: &'static str,
    /// Every detection family the rows below reach, and no other.
    pub(crate) families: &'static [Family],
    /// The complete flat occurrence sequence, in detection order.
    pub(crate) rows: &'static [Row],
}

/// One backend, keyed once by language and path extension.
///
/// Keying a backend once is what stops a source being analyzed under another
/// language's extension: the three sub-cases share this row's identity instead
/// of each restating it.
pub(crate) struct LanguageCase {
    pub(crate) language: Language,
    /// The extension every path this backend is analyzed at carries.
    pub(crate) extension: &'static str,
    /// Every detection family this backend covers.
    pub(crate) families: SubCase,
    /// Duplicate names and nested callables.
    pub(crate) nesting: SubCase,
    /// Capability at module scope, with callables around it.
    pub(crate) module: SubCase,
}

/// One string-literal occurrence, which most rows are built from.
pub(crate) const fn literal_row(
    line: usize,
    column: usize,
    evidence: &'static str,
    owner: Option<Owner>,
) -> Row {
    Row {
        capability: Capability::Network,
        evidence,
        line,
        column,
        origin: FindingOrigin::StringLiteral,
        family: "string-literal",
        owner,
    }
}

/// The callable one row names.
pub(crate) const fn owned_by(
    kind: CapabilitySymbolKind,
    name: &'static str,
    line: usize,
    column: usize,
) -> Option<Owner> {
    Some(Owner {
        kind,
        name,
        line,
        column,
    })
}

/// Run one sub-case of every backend this build links a grammar for.
///
/// `stem` names the file each source is analyzed as; the extension comes from
/// the backend's own row, so the pairing cannot drift. The coverage guard reads
/// the table itself rather than a second hand-written feature list.
pub(crate) fn assert_every_backend(
    cases: &[LanguageCase],
    stem: &str,
    select: fn(&LanguageCase) -> &SubCase,
) {
    assert!(
        !cases.is_empty(),
        "these cases need at least one linked grammar"
    );
    for backend in cases {
        let path = format!("{stem}.{}", backend.extension);
        assert_case(&Case {
            language: backend.language,
            path: &path,
            sub: select(backend),
        });
    }
}

/// One sub-case, resolved to the path it is analyzed at.
struct Case<'a> {
    language: Language,
    path: &'a str,
    sub: &'a SubCase,
}

/// Assert one case's flat sequence, family coverage, and symbol projection.
fn assert_case(case: &Case<'_>) {
    let analysis = analysis_for(case.sub.source, case.path, case.language);
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "{} parses cleanly, so attribution is complete",
        case.path
    );

    assert_flat_sequence(&analysis, case.path, &expected_rows(case));
    assert_families_are_covered(case);
    assert_symbol_projection(case, &analysis);
}

/// The flat sequence the table states, in the shared projection.
fn expected_rows(case: &Case<'_>) -> Box<[FlatRow<'static>]> {
    case.sub
        .rows
        .iter()
        .map(|row| {
            (
                row.capability,
                row.evidence,
                row.line,
                row.column,
                Some(row.origin),
                Some(case.language),
            )
        })
        .collect()
}

/// The family list and the row table pin each other, in both directions.
///
/// Forward, every named family reaches an occurrence. Backward, every row names
/// a listed family, so a misspelled or unlisted family is a failure rather than
/// a value nothing reads.
fn assert_families_are_covered(case: &Case<'_>) {
    assert!(
        !case.sub.families.is_empty(),
        "{} states no detection family",
        case.path
    );
    for family in case.sub.families {
        assert_family_occurrence(case, family);
    }
    for row in case.sub.rows {
        assert!(
            case.sub
                .families
                .iter()
                .any(|family| family.name == row.family),
            "{} states the {} family at {}:{}, which its family list omits",
            case.path,
            row.family,
            row.line,
            row.column
        );
    }
}

/// One named family reaches an occurrence, owned exactly where it claims.
fn assert_family_occurrence(case: &Case<'_>, family: &Family) {
    let stated = case
        .sub
        .rows
        .iter()
        .filter(|row| row.family == family.name)
        .count();
    let owned = case
        .sub
        .rows
        .iter()
        .filter(|row| row.family == family.name && row.owner.is_some())
        .count();
    assert!(
        stated > 0,
        "{} must state an occurrence for the {} family",
        case.path,
        family.name
    );
    match family.owned {
        true => assert!(
            owned > 0,
            "{} must state a callable-owned occurrence for the {} family",
            case.path,
            family.name
        ),
        // The family sits outside every callable here, and that absence is the
        // claim: nothing below it may inherit the capability.
        false => assert_eq!(
            owned, 0,
            "no callable owns the {} family in {}, so no occurrence is owned",
            family.name, case.path
        ),
    }
}

/// The complete symbol sequence, by identity, occurrence value, order, and flat
/// index.
fn assert_symbol_projection(case: &Case<'_>, analysis: &CapabilityAnalysis) {
    let expected = expected_owners(case);
    assert!(
        !expected.is_empty(),
        "{} states no owned occurrence",
        case.path
    );
    assert_eq!(
        analysis.symbols.len(),
        expected.len(),
        "{} must project exactly the owned declarations",
        case.path
    );

    for (actual, (_, (owner, indices))) in analysis.symbols.iter().zip(&expected) {
        assert_symbol_identity(case, actual, owner);
        assert_owned_occurrences(case, actual, owner, indices, &analysis.profile.findings);
    }
}

/// One projected symbol's identity, against the owner the table states.
fn assert_symbol_identity(case: &Case<'_>, actual: &SymbolCapabilityProfile, owner: &Owner) {
    assert_eq!(
        actual.symbol.language, case.language,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
    assert_eq!(
        actual.symbol.kind, owner.kind,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
    assert_eq!(
        &*actual.symbol.name, owner.name,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
    assert_eq!(
        actual.symbol.declaration.line, owner.line,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
    assert_eq!(
        actual.symbol.declaration.column, owner.column,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
    assert_eq!(
        &*actual.symbol.declaration.file, case.path,
        "{} symbol {} at {}:{}",
        case.path, owner.name, owner.line, owner.column
    );
}

/// The occurrences one projected symbol owns, by value and by flat index.
fn assert_owned_occurrences(
    case: &Case<'_>,
    actual: &SymbolCapabilityProfile,
    owner: &Owner,
    indices: &[usize],
    findings: &[CapabilityFinding],
) {
    assert!(
        !actual.profile.findings.is_empty(),
        "{} symbol {} at {}:{} must emit no empty symbol profile",
        case.path,
        owner.name,
        owner.line,
        owner.column
    );
    assert_eq!(
        actual.profile.findings.len(),
        indices.len(),
        "{} symbol {} at {}:{} owns exactly its filtered occurrences",
        case.path,
        owner.name,
        owner.line,
        owner.column
    );
    for (member, &index) in actual.profile.findings.iter().zip(indices) {
        assert_eq!(
            member, &findings[index],
            "{} symbol {} at {}:{} must own flat occurrence {index}",
            case.path, owner.name, owner.line, owner.column
        );
    }
}

/// The owners the table states, in declaration order, with the flat indices
/// each one owns.
///
/// Derived from the flat table alone: a row with no owner contributes nothing,
/// so module and unsupported evidence cannot reach a symbol profile.
fn expected_owners(case: &Case<'_>) -> BTreeMap<(usize, usize), (Owner, Vec<usize>)> {
    let mut owners: BTreeMap<(usize, usize), (Owner, Vec<usize>)> = BTreeMap::new();
    for (index, row) in case.sub.rows.iter().enumerate() {
        if let Some(owner) = row.owner {
            owners
                .entry((owner.line, owner.column))
                .or_insert((owner, Vec::new()))
                .1
                .push(index);
        }
    }
    owners
}
