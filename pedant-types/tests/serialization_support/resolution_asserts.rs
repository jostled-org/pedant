//! The assertions behind the resolution-schema cases.
//!
//! The cases themselves stay at the test root, where cargo registers each under
//! its own bare name; what each one proves lives here, one job per function.

use std::collections::BTreeSet;
use std::sync::Arc;

use pedant_types::Language;
use pedant_types::resolution::{
    CandidateInput, ReferenceKind, ResolutionCertainty, ResolutionGap, ResolutionReport,
    ResolutionReportError, ResolutionReportLimits, SymbolKind,
};

use crate::resolution_builder_cases::{BuilderCase, finish_refusal};
use crate::resolution_case_model::{BuilderReach, MalformedCase, refusal};
use crate::resolution_fixture::{possible_report, span, valid_report};
use crate::resolution_seed::{SeededBuilder, seeded_builder};

/// Every handle-consuming operation refuses a foreign handle whose local index
/// names a valid local record.
pub fn foreign_handles_are_refused(local: &mut SeededBuilder, foreign: &SeededBuilder) {
    let unit_on_definition = local.builder.add_definition(
        &foreign.unit,
        SymbolKind::Function,
        Arc::from("run"),
        span("a/src/lib.rs", 4, 0, 8),
        None,
    );
    assert_eq!(
        unit_on_definition.err(),
        Some(ResolutionReportError::ForeignUnitHandle),
        "a foreign unit handle cannot own a definition"
    );

    let foreign_parent = local.builder.add_definition(
        &local.unit,
        SymbolKind::Function,
        Arc::from("run"),
        span("a/src/lib.rs", 4, 0, 8),
        Some(&foreign.definition),
    );
    assert_eq!(
        foreign_parent.err(),
        Some(ResolutionReportError::ForeignDefinitionHandle),
        "a foreign definition handle cannot be a parent"
    );

    let unit_on_reference = local.builder.add_reference(
        &foreign.unit,
        ReferenceKind::Call,
        Arc::from("run"),
        span("a/src/lib.rs", 5, 0, 8),
        None,
    );
    assert_eq!(
        unit_on_reference.err(),
        Some(ResolutionReportError::ForeignUnitHandle),
        "a foreign unit handle cannot own a reference"
    );

    let foreign_enclosing = local.builder.add_reference(
        &local.unit,
        ReferenceKind::Call,
        Arc::from("run"),
        span("a/src/lib.rs", 5, 0, 8),
        Some(&foreign.definition),
    );
    assert_eq!(
        foreign_enclosing.err(),
        Some(ResolutionReportError::ForeignDefinitionHandle),
        "a foreign definition handle cannot enclose a reference"
    );

    let foreign_reference = local.builder.set_resolution(
        &foreign.reference,
        Box::from([]),
        Box::from([ResolutionGap::MissingDefinition]),
    );
    assert_eq!(
        foreign_reference.err(),
        Some(ResolutionReportError::ForeignReferenceHandle),
        "a foreign reference handle cannot receive a record"
    );

    let foreign_candidate = local.builder.set_resolution(
        &local.reference,
        Box::from([CandidateInput::new(
            foreign.definition.clone(),
            ResolutionCertainty::Resolved,
        )]),
        Box::from([]),
    );
    assert_eq!(
        foreign_candidate.err(),
        Some(ResolutionReportError::ForeignDefinitionHandle),
        "a foreign definition handle cannot be a candidate"
    );
}

/// The seeded builder still finishes with exactly what it was seeded with.
pub fn seeded_builder_still_finishes(seeded: SeededBuilder, reason: &str) {
    let mut seeded = seeded;
    seeded
        .builder
        .set_resolution(
            &seeded.reference,
            Box::from([]),
            Box::from([ResolutionGap::MissingDefinition]),
        )
        .expect("the untouched builder still accepts its own reference");
    let report = seeded.builder.finish().expect(reason);
    assert_eq!(report.units().len(), 1, "{reason}: one unit was inserted");
    assert_eq!(
        report.definitions().len(),
        1,
        "{reason}: one definition was inserted"
    );
    assert_eq!(
        report.references().len(),
        1,
        "{reason}: one reference was inserted"
    );
    assert_eq!(report.resolutions().len(), 1, "{reason}: one record exists");
}

/// A builder at its configured capacity of one refuses every second insertion.
pub fn configured_capacity_is_enforced(seeded: &mut SeededBuilder) {
    assert_eq!(
        seeded
            .builder
            .add_unit(
                Language::Rust,
                Arc::from("b/Cargo.toml#lib:beta"),
                Arc::from("beta")
            )
            .err(),
        Some(ResolutionReportError::UnitCapacityExceeded { limit: 1 }),
        "the second unit exceeds the configured unit capacity"
    );
    assert_eq!(
        seeded
            .builder
            .add_definition(
                &seeded.unit,
                SymbolKind::Function,
                Arc::from("run"),
                span("a/src/lib.rs", 4, 0, 8),
                None,
            )
            .err(),
        Some(ResolutionReportError::DefinitionCapacityExceeded { limit: 1 }),
        "the second definition exceeds the configured definition capacity"
    );
    assert_eq!(
        seeded
            .builder
            .add_reference(
                &seeded.unit,
                ReferenceKind::Call,
                Arc::from("run"),
                span("a/src/lib.rs", 5, 0, 8),
                None,
            )
            .err(),
        Some(ResolutionReportError::ReferenceCapacityExceeded { limit: 1 }),
        "the second reference exceeds the configured reference capacity"
    );
}

/// The default limits are the identifier ceiling, enforced by the same check.
pub fn id_ceiling_is_enforced() {
    let default = ResolutionReportLimits::default();
    assert_eq!(
        default.max_units,
        u32::MAX,
        "units default to the ID ceiling"
    );
    assert_eq!(
        default.max_definitions,
        u32::MAX,
        "definitions default to the ID ceiling"
    );
    assert_eq!(
        default.max_references,
        u32::MAX,
        "references default to the ID ceiling"
    );

    let below = usize::try_from(u32::MAX - 1).expect("the near-ceiling count fits a usize");
    let at = usize::try_from(u32::MAX).expect("the ceiling count fits a usize");
    assert_eq!(
        default.admit_unit(below),
        Ok(u32::MAX - 1),
        "the last unit index below the ceiling is admitted"
    );
    assert_eq!(
        default.admit_unit(at),
        Err(ResolutionReportError::UnitCapacityExceeded { limit: u32::MAX }),
        "the ceiling itself is refused by the same check"
    );
    assert_eq!(
        default.admit_definition(at),
        Err(ResolutionReportError::DefinitionCapacityExceeded { limit: u32::MAX }),
        "definitions share the ceiling rule"
    );
    assert_eq!(
        default.admit_reference(at),
        Err(ResolutionReportError::ReferenceCapacityExceeded { limit: u32::MAX }),
        "references share the ceiling rule"
    );
}

/// Every case in a wire table produces its exact refusal.
pub fn every_case_produces_its_refusal(cases: &[MalformedCase], expected: usize, family: &str) {
    assert_eq!(cases.len(), expected, "every {family} stays covered");
    for case in cases {
        let reported = refusal(case);
        assert!(
            reported.contains(&case.expected.to_string()),
            "{}: expected {:?}, got {reported}",
            case.label,
            case.expected
        );
    }
}

/// Every case in a builder table produces its exact refusal from `finish`.
pub fn every_builder_case_produces_its_refusal(
    cases: &[BuilderCase],
    expected: usize,
    family: &str,
) {
    assert_eq!(
        cases.len(),
        expected,
        "every statable {family} stays covered"
    );
    for case in cases {
        assert_eq!(
            finish_refusal(case),
            case.expected,
            "{}: `finish` owes this exact refusal",
            case.label
        );
    }
}

/// The two construction boundaries cover the same families.
///
/// A wire case marked `Statable` has to have a `finish` case of the same label,
/// and a `finish` case has to answer a wire case: without this, one boundary
/// can grow a rule the other never proves. A wire-only case states why `finish`
/// cannot produce its shape, and that reason is what this asymmetry rests on.
pub fn boundaries_cover_the_same_families(wire: &[MalformedCase], builder: &[BuilderCase]) {
    let statable: BTreeSet<&str> = wire
        .iter()
        .filter(|case| case.reach == BuilderReach::Statable)
        .map(|case| case.label)
        .collect();
    let finished: BTreeSet<&str> = builder.iter().map(|case| case.label).collect();
    let wire_only: Box<[String]> = wire
        .iter()
        .filter_map(|case| match case.reach {
            BuilderReach::WireOnly(reason) => Some(format!("{}: {reason}", case.label)),
            BuilderReach::Statable => None,
        })
        .collect();
    assert_eq!(
        statable, finished,
        "every writer-statable family reaches `finish`, and no `finish` case is \
         unmatched; the wire-only families are {wire_only:?}"
    );
}

/// One reference carries exactly one record, at both writer boundaries.
pub fn one_record_per_reference() {
    let mut seeded = seeded_builder(ResolutionReportLimits::default());
    seeded
        .builder
        .set_resolution(
            &seeded.reference,
            Box::from([]),
            Box::from([ResolutionGap::MissingDefinition]),
        )
        .expect("the first record is admitted");
    assert_eq!(
        seeded
            .builder
            .set_resolution(
                &seeded.reference,
                Box::from([]),
                Box::from([ResolutionGap::ExternalDefinition]),
            )
            .err(),
        Some(ResolutionReportError::DuplicateResolution { reference: 0 }),
        "one reference carries exactly one record"
    );

    let report = valid_report();
    assert_eq!(
        report.resolutions().len(),
        report.references().len(),
        "a valid report has exactly one record per reference"
    );
}

/// A valid report survives serialization, the validator, and re-serialization.
pub fn valid_report_round_trips() {
    let report = valid_report();
    let encoded = serde_json::to_string(&report).expect("the report serializes");
    let restored: ResolutionReport =
        serde_json::from_str(&encoded).expect("a valid report survives the validator");
    assert_eq!(restored, report, "the report round trips");
    assert_eq!(
        serde_json::to_string(&restored).expect("the restored report serializes"),
        encoded,
        "serialization is stable across the round trip"
    );
}

/// Unit containment for parents and enclosing definitions, and a legal
/// cross-unit resolved candidate.
pub fn unit_containment_and_cross_unit_candidate() {
    let report = valid_report();
    let definitions = report.definitions();
    let references = report.references();

    let nested = &definitions[1];
    let parent = nested.parent().expect("the nested function has a parent");
    assert_eq!(
        definitions[at(parent.index())].unit(),
        nested.unit(),
        "a parent definition belongs to its child's unit"
    );

    let call = &references[1];
    let enclosing = call
        .enclosing_definition()
        .expect("the call site has an enclosing definition");
    assert_eq!(
        definitions[at(enclosing.index())].unit(),
        call.unit(),
        "an enclosing definition belongs to its reference's unit"
    );

    let record = &report.resolutions()[1];
    assert_eq!(record.reference(), call.id(), "record 1 owns the call site");
    let candidate = &record.candidates()[0];
    assert_eq!(
        candidate.certainty(),
        ResolutionCertainty::Resolved,
        "the unique cross-unit target is resolved"
    );
    assert_ne!(
        definitions[at(candidate.definition().index())].unit(),
        call.unit(),
        "a candidate may cross units"
    );
    assert!(record.gaps().is_empty(), "a resolved record carries no gap");
}

/// A possible candidate set is accepted, with the wire spelling `possible`.
///
/// The certainty rule has one permissive branch — one or more possible
/// candidates, with or without gaps — and every other case that names
/// `Possible` is a refusal, so without this the branch is never taken and no
/// accepted report ever carries the spelling. Callers pass the gaps the record
/// states: none when the alternatives are all present, one when the candidate
/// set is known to be incomplete.
pub fn possible_candidates_are_accepted(gaps: &[ResolutionGap]) {
    let report = possible_report(Box::from(gaps));
    let record = &report.resolutions()[1];
    let candidates = record.candidates();
    assert_eq!(
        candidates.len(),
        2,
        "an unproven site keeps every alternative rather than collapsing them"
    );
    for candidate in candidates {
        assert_eq!(
            candidate.certainty(),
            ResolutionCertainty::Possible,
            "every candidate in the set is possible"
        );
    }
    assert_eq!(record.gaps(), gaps, "the record carries the stated gaps");

    let definitions = report.definitions();
    assert_ne!(
        definitions[at(candidates[0].definition().index())].unit(),
        definitions[at(candidates[1].definition().index())].unit(),
        "a possible set may span units"
    );

    let encoded = serde_json::to_string(&report).expect("the report serializes");
    assert_eq!(
        encoded.matches("\"certainty\":\"possible\"").count(),
        candidates.len(),
        "every possible candidate spells its certainty `possible`: {encoded}"
    );
    assert!(
        !encoded.contains("\"certainty\":\"resolved\""),
        "no candidate in this report claims a proven target: {encoded}"
    );
    let restored: ResolutionReport =
        serde_json::from_str(&encoded).expect("a possible candidate set survives the validator");
    assert_eq!(restored, report, "the possible record round trips");
}

/// Rust is the language of every emitted record, with the wire spelling `rust`.
pub fn every_record_spells_its_language_rust() {
    assert_eq!(
        serde_json::to_string(&Language::Rust).expect("the language serializes"),
        "\"rust\"",
        "Rust's wire spelling is `rust`"
    );
    let restored: Language =
        serde_json::from_str("\"rust\"").expect("the wire spelling deserializes");
    assert_eq!(restored, Language::Rust, "the language round trips");

    let report = valid_report();
    for unit in report.units() {
        assert_eq!(unit.language(), Language::Rust, "units carry Rust");
    }
    for definition in report.definitions() {
        assert_eq!(
            definition.language(),
            Language::Rust,
            "definitions carry Rust"
        );
    }
    for reference in report.references() {
        assert_eq!(
            reference.language(),
            Language::Rust,
            "references carry Rust"
        );
    }
    let encoded = serde_json::to_string(&report).expect("the report serializes");
    assert!(
        !encoded.contains("\"language\":\"python\""),
        "no record claims another language: {encoded}"
    );
    assert_eq!(
        encoded.matches("\"language\":\"rust\"").count(),
        report.units().len() + report.definitions().len() + report.references().len(),
        "every emitted record spells its language `rust`"
    );
}

fn at(index: u32) -> usize {
    usize::try_from(index).expect("a report index fits a usize")
}
