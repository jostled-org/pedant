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
    Capability, CapabilityAnalysis, CapabilitySymbolKind, FindingOrigin, Language,
    SymbolAttributionStatus,
};

use crate::language_probe::analysis_for;

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
    pub(crate) family: &'static str,
    /// `None` for evidence no callable contains, and for a lexical owner the
    /// symbol model states nothing for.
    pub(crate) owner: Option<Owner>,
}

/// One detection family a backend must cover.
#[derive(Clone, Copy)]
pub(crate) struct Family {
    pub(crate) name: &'static str,
    /// Whether the language lets this family appear inside a callable.
    ///
    /// An ES `import` and a Go import declaration are module-level by grammar,
    /// so their families are covered by an occurrence no callable can contain.
    pub(crate) callable: bool,
}

/// One language's case.
pub(crate) struct Case<'rows> {
    pub(crate) language: Language,
    pub(crate) path: &'static str,
    pub(crate) source: &'static str,
    /// Every detection family this backend must reach, or empty for a case that
    /// is about ownership rather than coverage.
    pub(crate) families: &'rows [Family],
    /// The complete flat occurrence sequence, in detection order.
    pub(crate) rows: &'rows [Row],
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

/// How many backends this build links a grammar for.
///
/// Every case contributes one per enabled backend, so a cfg slip that empties a
/// case fails rather than passing with nothing asserted.
fn enabled_backends() -> usize {
    [
        cfg!(feature = "ts-python"),
        cfg!(feature = "ts-javascript"),
        cfg!(feature = "ts-typescript"),
        cfg!(feature = "ts-go"),
        cfg!(feature = "ts-bash"),
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count()
}

pub(crate) fn assert_covered(reached: usize) {
    assert!(reached > 0, "these cases need at least one linked grammar");
    assert_eq!(
        reached,
        enabled_backends(),
        "every backend this build enables contributes one case"
    );
}

/// The flat projection of one finding, as every comparison here reads it.
type FlatRow<'a> = (
    Capability,
    &'a str,
    usize,
    usize,
    Option<FindingOrigin>,
    Option<Language>,
);

/// Assert one case's flat sequence, symbol projection, and index discipline.
pub(crate) fn assert_case(case: &Case<'_>) {
    let analysis = analysis_for(case.source, case.path, case.language);
    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "{} parses cleanly, so attribution is complete",
        case.path
    );

    assert_flat_sequence(case, &analysis);
    assert_families_are_covered(case);
    assert_symbol_projection(case, &analysis);
}

/// The whole flat sequence, by value, order, and length.
fn assert_flat_sequence(case: &Case<'_>, analysis: &CapabilityAnalysis) {
    let actual: Box<[FlatRow<'_>]> = analysis
        .profile
        .findings
        .iter()
        .map(|finding| {
            (
                finding.capability,
                &*finding.evidence,
                finding.location.line,
                finding.location.column,
                finding.origin,
                finding.language,
            )
        })
        .collect();
    let expected: Box<[FlatRow<'_>]> = case
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
        .collect();
    assert_eq!(
        actual, expected,
        "{} must produce exactly the written-down flat sequence",
        case.path
    );
    assert!(
        !actual.is_empty(),
        "{} must produce at least one finding",
        case.path
    );
}

/// Every named family contributes an occurrence, owned where the grammar allows.
fn assert_families_are_covered(case: &Case<'_>) {
    for family in case.families {
        let stated = case
            .rows
            .iter()
            .filter(|row| row.family == family.name)
            .count();
        let owned = case
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
        match family.callable {
            true => assert!(
                owned > 0,
                "{} must state a callable-owned occurrence for the {} family",
                case.path,
                family.name
            ),
            // Module-level by grammar: the family is covered by an occurrence no
            // callable can contain, and that absence is the claim.
            false => assert_eq!(
                owned, 0,
                "the {} family is module-level in {}, so no occurrence is owned",
                family.name, case.path
            ),
        }
    }
}

/// The complete symbol sequence, by identity, occurrence value, order, and flat
/// index.
fn assert_symbol_projection(case: &Case<'_>, analysis: &CapabilityAnalysis) {
    let expected = expected_owners(case);
    assert_eq!(
        analysis.symbols.len(),
        expected.len(),
        "{} must project exactly the owned declarations",
        case.path
    );

    let mut claimed: Vec<usize> = Vec::new();
    for (actual, (declaration, (owner, indices))) in analysis.symbols.iter().zip(&expected) {
        let (line, column) = *declaration;
        assert_eq!(actual.symbol.language, case.language, "{}", case.path);
        assert_eq!(actual.symbol.kind, owner.kind, "{}", case.path);
        assert_eq!(&*actual.symbol.name, owner.name, "{}", case.path);
        assert_eq!(actual.symbol.declaration.line, line, "{}", case.path);
        assert_eq!(actual.symbol.declaration.column, column, "{}", case.path);
        assert_eq!(&*actual.symbol.declaration.file, case.path);
        assert!(
            !actual.profile.findings.is_empty(),
            "{} must emit no empty symbol profile",
            case.path
        );
        assert_eq!(
            actual.profile.findings.len(),
            indices.len(),
            "{} symbol {} owns exactly its filtered occurrences",
            case.path,
            owner.name
        );
        for (member, &index) in actual.profile.findings.iter().zip(indices) {
            assert_eq!(
                member, &analysis.profile.findings[index],
                "{} symbol {} must own flat occurrence {index}",
                case.path, owner.name
            );
            claimed.push(index);
        }
    }

    let mut distinct = claimed.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        claimed.len(),
        "{} must claim each flat occurrence at most once",
        case.path
    );
}

/// The owners the table states, in declaration order, with the flat indices
/// each one owns.
///
/// Derived from the flat table alone: a row with no owner contributes nothing,
/// so module and unsupported evidence cannot reach a symbol profile.
fn expected_owners(case: &Case<'_>) -> BTreeMap<(usize, usize), (Owner, Vec<usize>)> {
    let mut owners: BTreeMap<(usize, usize), (Owner, Vec<usize>)> = BTreeMap::new();
    for (index, row) in case.rows.iter().enumerate() {
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
