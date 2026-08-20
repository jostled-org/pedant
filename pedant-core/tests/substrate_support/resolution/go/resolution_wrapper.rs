//! The published wrapper: one report unit per snapshot package context, valid
//! coordinates in the exact snapshot bytes, a Go-only kind subset, and the
//! snapshot's own identity.
//!
//! This half reads a real corpus. The reports the production resolver never
//! writes are stated by [`crate::resolution::go::resolution_refusal`], because a
//! wrapper that only ever saw its own producer's output would prove nothing
//! about a report handed to it.

use pedant_core::resolution::go::{GoProjectResolution, GoResolutionLimits};
use pedant_types::{Language, ResolutionReport, SymbolDefinition, SymbolKind};

use crate::resolution::go::fixture::{resolve, resolve_default};
use crate::resolution::go::resolution_fixtures::BOUND_CONTEXTS;
use crate::resolution::go::resolution_refusal::assert_reports_it_did_not_write_are_refused;
use crate::resolution::go::resolution_views::{references, unit_references, units};
use crate::resolution::go::views::borrowed;

/// Every report unit [`BOUND_CONTEXTS`] states, one per snapshot package
/// context.
const BOUND_UNITS: &[&str] = &[
    "x#external_test",
    "x#internal_test",
    "x#production",
    "x/util#production",
];

/// The build-conditioned source of [`BOUND_CONTEXTS`], whose declarations only
/// some builds hold.
const CONDITIONED_SOURCE: &str = "tuned_linux.go";

/// The production context's own references, which is what shows the certainty
/// rule discriminates: the unconditioned call beside the conditioned one
/// resolves.
/// A site written inside the conditioned source states the predicate gap too,
/// whether or not it names a candidate at all.
const PRODUCTION_REFERENCES: &[&str] = &[
    "x#production|Import|x/util|app.go:2|resolved|x/util#production::util|",
    "x#production|Type|string|app.go:4|-||ExternalDefinition",
    "x#production|Call|Name|app.go:5|resolved|x/util#production::Name|",
    "x#production|Call|tuned|app.go:5|possible|x#production::tuned|ConditionalCompilation",
    "x#production|Type|string|tuned_linux.go:2|-||ExternalDefinition,ConditionalCompilation",
];

/// Every record naming a definition a build predicate governs.
///
/// One candidate each, so no answer here is possible because it is ambiguous:
/// the predicate alone is what keeps it from resolving.
const CONDITIONAL_EVIDENCE: &[&str] = &[
    "x#internal_test|Call|tuned|app.go:5|possible|x#internal_test::tuned|ConditionalCompilation",
    "x#production|Call|tuned|app.go:5|possible|x#production::tuned|ConditionalCompilation",
];

/// 5.T6 (Invariants 7, 19, 21): every published resolution binds one report
/// unit per snapshot context, states only Go-admitted kinds at coordinates the
/// snapshot holds, retains the snapshot's identity, and states the same bytes
/// whatever order the fixture was written in.
#[test]
fn go_project_resolution_validates_every_snapshot_binding_and_kind() {
    let (tree, snapshot, resolution) = resolve_default(BOUND_CONTEXTS);

    assert_eq!(
        &*borrowed(&units(&resolution)),
        BOUND_UNITS,
        "one report unit is bound per snapshot package context"
    );
    assert_eq!(
        resolution.units().len(),
        snapshot.units().len(),
        "every report unit binds one snapshot unit"
    );
    assert_eq!(
        resolution.snapshot_fingerprint(),
        snapshot.fingerprint(),
        "a published resolution retains the identity of the snapshot it read"
    );
    assert_eq!(
        resolution.root_module(),
        snapshot.root_module(),
        "a published resolution names the snapshot's main module"
    );
    for binding in resolution.units() {
        let bound = snapshot
            .unit(binding.snapshot_unit())
            .expect("a binding names a unit of its own snapshot");
        assert_eq!(
            binding.context(),
            bound.context(),
            "a binding restates the context of the unit it names"
        );
        assert_eq!(
            resolution.unit(binding.unit()).map(GoUnitId::of),
            Some(GoUnitId::of(binding)),
            "a resolution answers for every binding it issued"
        );
    }
    assert_go_kind_subset(resolution.report());
    assert_eq!(
        &*borrowed(&unit_references(&resolution, "x#production")),
        PRODUCTION_REFERENCES,
        "an unconditioned call resolves in the same report a conditioned one does not"
    );
    assert_conditional_evidence_is_possible(&resolution);

    drop(resolution);
    drop(snapshot);
    drop(tree);

    assert_bytes_are_enumeration_independent();
    assert_reports_it_did_not_write_are_refused(BOUND_UNITS);
}

/// The identity two bindings are compared by, which is every field one carries.
#[derive(Debug, PartialEq, Eq)]
struct GoUnitId {
    unit: u32,
    snapshot_unit: Box<str>,
    module: Box<str>,
    context: Box<str>,
}

impl GoUnitId {
    fn of(binding: &pedant_core::resolution::go::GoUnitBinding) -> Self {
        Self {
            unit: binding.unit().index(),
            snapshot_unit: format!("{:?}", binding.snapshot_unit()).into_boxed_str(),
            module: format!("{:?}", binding.module()).into_boxed_str(),
            context: Box::from(binding.context().token()),
        }
    }
}

/// Only the Go subset of the shared vocabulary appears.
fn assert_go_kind_subset(report: &ResolutionReport) {
    let refused: Box<[SymbolKind]> = report
        .definitions()
        .iter()
        .map(|definition| definition.kind())
        .filter(|kind| {
            matches!(
                kind,
                SymbolKind::Module
                    | SymbolKind::Enum
                    | SymbolKind::Union
                    | SymbolKind::Trait
                    | SymbolKind::Static
            )
        })
        .collect();
    assert!(
        refused.is_empty(),
        "a Go resolution states no Rust-only definition kind: {refused:?}"
    );
    for definition in report.definitions() {
        assert_eq!(
            definition.language(),
            Language::Go,
            "every definition carries its unit's language"
        );
    }
}

/// A candidate a build predicate governs is possible, never resolved, and says
/// which predicate family kept it possible.
///
/// This tier evaluates no predicate, so a definition only some builds hold
/// leaves the active universe unknown. The conditioned definitions are found by
/// the source that declares them and the list is required to be non-empty, so a
/// fixture that stopped stating conditional evidence fails here rather than
/// satisfying the rule over nothing.
fn assert_conditional_evidence_is_possible(resolution: &GoProjectResolution) {
    let report = resolution.report();
    let conditioned: Box<[u32]> = report
        .definitions()
        .iter()
        .enumerate()
        .filter(|(_, definition)| SymbolDefinition::span(definition).file() == CONDITIONED_SOURCE)
        .map(|(index, _)| u32::try_from(index).expect("a report-local definition identifier"))
        .collect();
    assert!(
        !conditioned.is_empty(),
        "{CONDITIONED_SOURCE} states the definitions this rule is read over"
    );

    let rendered = references(resolution);
    let naming: Box<[Box<str>]> = report
        .resolutions()
        .iter()
        .enumerate()
        .filter(|(_, record)| {
            record
                .candidates()
                .iter()
                .any(|candidate| conditioned.contains(&candidate.definition().index()))
        })
        .map(|(index, _)| rendered[index].clone())
        .collect();
    assert_eq!(
        &*borrowed(&naming),
        CONDITIONAL_EVIDENCE,
        "every record naming a conditioned definition is possible and states the predicate gap"
    );
}

/// Two loads whose fixture files were written in opposite orders state the same
/// report bytes.
fn assert_bytes_are_enumeration_independent() {
    let forward: Box<[_]> = BOUND_CONTEXTS.iter().copied().collect();
    let mut backward = forward.to_vec();
    backward.reverse();
    assert_eq!(
        report_bytes(&forward),
        report_bytes(&backward),
        "equal project bytes state equal report bytes whatever order the tree was written in"
    );
}

fn report_bytes(files: &[crate::resolution::fixture::FixtureFile]) -> Box<str> {
    let (tree, snapshot, resolution) = resolve(files, GoResolutionLimits::default());
    let resolution =
        resolution.unwrap_or_else(|error| panic!("the fixture should resolve: {error}"));
    let rendered = serde_json::to_string(resolution.report())
        .expect("a validated report serializes")
        .into_boxed_str();
    drop(resolution);
    drop(snapshot);
    drop(tree);
    rendered
}
