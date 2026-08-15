//! The shape of a hand-written capability expectation, and the assertions that
//! hold an analysis to one.
//!
//! A submodule of `tests/capability.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: this directory carries no `main.rs`, so cargo
//! declares no test executable for it.
//!
//! A case states its complete expected flat occurrence sequence by hand. The
//! expected symbol sequence is derived here from that one table by filtering on
//! callable ownership, so nothing reads the production grouping to decide what
//! the grouping should be.

use std::collections::BTreeSet;

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::analyze;
use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, CapabilitySymbolKind, FindingOrigin,
    Language,
};

/// The capability-source fact family one expected occurrence came from.
///
/// `FindingOrigin` cannot carry this: an `unsafe` site and an `extern` block
/// both report [`FindingOrigin::CodeSite`], and the plan requires a non-zero
/// callable-owned row per *fact family*, not per origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FactFamily {
    UsePath,
    Unsafe,
    ExternBlock,
    Attribute,
    StringLiteral,
}

/// Every family the five stamped Rust capability-source facts cover.
pub(crate) const ALL_FAMILIES: &[FactFamily] = &[
    FactFamily::UsePath,
    FactFamily::Unsafe,
    FactFamily::ExternBlock,
    FactFamily::Attribute,
    FactFamily::StringLiteral,
];

/// The callable a finding is expected to belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedSymbol {
    pub(crate) kind: CapabilitySymbolKind,
    pub(crate) name: &'static str,
    /// One-based line of the declared name.
    pub(crate) line: usize,
    /// One-based column of the declared name.
    pub(crate) column: usize,
}

/// One expected flat finding occurrence and its callable owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExpectedFinding {
    pub(crate) family: FactFamily,
    pub(crate) capability: Capability,
    pub(crate) origin: FindingOrigin,
    /// One-based line of the finding.
    pub(crate) line: usize,
    /// One-based column of the finding.
    pub(crate) column: usize,
    pub(crate) evidence: &'static str,
    pub(crate) owner: Option<ExpectedSymbol>,
}

pub(crate) fn permissive_config() -> CheckConfig {
    CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

pub(crate) fn analysis_of(path: &str, source: &str) -> CapabilityAnalysis {
    analyze(path, source, &permissive_config(), None)
        .expect("the fixture source should parse")
        .capabilities
}

/// A finding rendered for comparison: everything a flat occurrence states,
/// except the file every finding in one analysis shares.
fn rendered(
    finding: &CapabilityFinding,
) -> (Capability, usize, usize, &str, Option<FindingOrigin>) {
    (
        finding.capability,
        finding.location.line,
        finding.location.column,
        &finding.evidence,
        finding.origin,
    )
}

fn rendered_expectation(
    expected: &ExpectedFinding,
) -> (Capability, usize, usize, &str, Option<FindingOrigin>) {
    (
        expected.capability,
        expected.line,
        expected.column,
        expected.evidence,
        Some(expected.origin),
    )
}

/// Hold the analysis to the complete expected flat sequence, by value, order,
/// and length.
pub(crate) fn assert_flat_sequence_is_exact(
    analysis: &CapabilityAnalysis,
    expected: &[ExpectedFinding],
) {
    let actual: Vec<_> = analysis.profile.findings.iter().map(rendered).collect();
    let wanted: Vec<_> = expected.iter().map(rendered_expectation).collect();
    assert_eq!(
        actual, wanted,
        "the complete flat occurrence sequence must match the hand-written table"
    );
}

/// The distinct expected owners, in declaration order.
fn expected_owners(expected: &[ExpectedFinding]) -> Box<[ExpectedSymbol]> {
    let mut owners: Vec<ExpectedSymbol> = Vec::new();
    for owner in expected.iter().filter_map(|row| row.owner) {
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    owners.sort_by_key(|owner| (owner.line, owner.column));
    owners.into_boxed_slice()
}

/// The flat indices each expected owner owns, in flat order.
fn expected_indices(expected: &[ExpectedFinding], owner: ExpectedSymbol) -> Box<[usize]> {
    expected
        .iter()
        .enumerate()
        .filter(|(_, row)| row.owner == Some(owner))
        .map(|(index, _)| index)
        .collect()
}

/// Hold the symbol projection to exactly what the flat table implies: identity,
/// occurrence value, occurrence order, flat index, and no reuse of an index.
pub(crate) fn assert_symbols_are_exactly_derived(
    analysis: &CapabilityAnalysis,
    file: &str,
    expected: &[ExpectedFinding],
) {
    let owners = expected_owners(expected);
    assert_eq!(
        analysis.symbols.len(),
        owners.len(),
        "one profile per callable that owns evidence, and no other: {:?}",
        analysis
            .symbols
            .iter()
            .map(|entry| &*entry.symbol.name)
            .collect::<Vec<_>>()
    );

    let mut claimed: BTreeSet<usize> = BTreeSet::new();
    for (actual, owner) in analysis.symbols.iter().zip(&owners) {
        assert_eq!(actual.symbol.language, Language::Rust);
        assert_eq!(actual.symbol.kind, owner.kind, "callable kind of {owner:?}");
        assert_eq!(&*actual.symbol.name, owner.name);
        assert_eq!(&*actual.symbol.declaration.file, file);
        assert_eq!(
            (
                actual.symbol.declaration.line,
                actual.symbol.declaration.column
            ),
            (owner.line, owner.column),
            "one-based declaration position of {owner:?}"
        );

        let indices = expected_indices(expected, *owner);
        assert!(
            !indices.is_empty(),
            "an expected owner with no evidence must not exist: {owner:?}"
        );
        let owned: Vec<_> = actual.profile.findings.iter().map(rendered).collect();
        let wanted: Vec<_> = indices
            .iter()
            .map(|&index| rendered(&analysis.profile.findings[index]))
            .collect();
        assert_eq!(
            owned, wanted,
            "{owner:?} must own exactly flat occurrences {indices:?}, in flat order"
        );
        for index in indices {
            assert!(
                claimed.insert(index),
                "flat occurrence {index} is claimed by more than one symbol profile"
            );
        }
    }

    assert!(
        analysis
            .symbols
            .iter()
            .all(|entry| !entry.profile.findings.is_empty()),
        "no emitted symbol profile may be empty"
    );
    let module_rows = expected.iter().filter(|row| row.owner.is_none()).count();
    assert_eq!(
        claimed.len() + module_rows,
        expected.len(),
        "every flat occurrence is either module evidence or owned exactly once"
    );
}

/// Every fact family must contribute at least one callable-owned occurrence, so
/// a family that silently stopped stamping its owner cannot pass.
pub(crate) fn assert_every_family_has_an_eligible_row(expected: &[ExpectedFinding]) {
    for family in ALL_FAMILIES {
        assert!(
            expected
                .iter()
                .any(|row| row.family == *family && row.owner.is_some()),
            "{family:?} must contribute a callable-owned occurrence"
        );
    }
}
