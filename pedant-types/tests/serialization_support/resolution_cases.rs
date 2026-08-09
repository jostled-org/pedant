//! Every malformed wire report, and the exact refusal each one must produce.
//!
//! Each case is one mutation of the fixture report, so a case asserts the rule
//! it names. The expected errors are written out rather than read back from a
//! run: a validator that starts reporting a different rule fails here.
//!
//! This table is the deserialization half of the contract. Every case that a
//! writer can also state carries `BuilderReach::Statable` and is mirrored, by
//! label, in `resolution_builder_cases`.
//!
//! The fixture's sorted shape is fixed and every case below reads it:
//! units `0 = alpha`, `1 = beta`; definitions `0 = alpha` (module),
//! `1 = run` (function in alpha), `2 = helper` (function in beta);
//! references `0 = the import`, `1 = the call`; records `0` carries the
//! import's gap and record `1` carries the call's resolved candidate.

use pedant_types::Language;
use pedant_types::resolution::{ReportCollection, ResolutionGap, ResolutionReportError};
use serde_json::json;

use crate::resolution_case_model::{
    BRANDED, BuilderReach, COPIED_LANGUAGE, DENSE, MalformedCase, SORTED,
};
use crate::resolution_fixture::UNIT_A_KEY;

/// Every dangling, duplicate, non-dense, cyclic, order, gap, path, and span
/// family the shared validator owns.
pub fn malformed_cases() -> Box<[MalformedCase]> {
    dangling_cases()
        .into_vec()
        .into_iter()
        .chain(unit_cases())
        .chain(definition_cases())
        .chain(reference_cases())
        .chain(record_cases())
        .chain(span_cases())
        .chain(order_cases())
        .collect()
}

/// A record points at a unit, definition, or reference that is not present.
///
/// The validator reaches into a collection by position at six places, and one
/// case states each: a definition's unit and its parent, a reference's unit and
/// its enclosing definition, a record's reference, and a candidate's definition.
/// Every later consumer indexes these slices by the handle it is given, so a
/// lookup left unstated here is an out-of-range index somewhere downstream
/// rather than a refusal at the boundary that owns it.
fn dangling_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "a definition names a unit that does not exist",
            mutate: |report| report["definitions"][0]["unit"] = json!(7),
            expected: ResolutionReportError::UnknownUnit { unit: 7 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
        // A parent outside the slice reaches no other rule: the cycle walk
        // treats an unknown ancestor as an ended chain and the order rule never
        // reads a parent, so the report is accepted unless this lookup refuses.
        MalformedCase {
            label: "a definition names a parent that does not exist",
            mutate: |report| report["definitions"][1]["parent"] = json!(9),
            expected: ResolutionReportError::UnknownDefinition { definition: 9 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
        MalformedCase {
            label: "a reference names a unit that does not exist",
            mutate: |report| report["references"][0]["unit"] = json!(7),
            expected: ResolutionReportError::UnknownUnit { unit: 7 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
        MalformedCase {
            label: "a reference names a definition that does not exist",
            mutate: |report| report["references"][0]["enclosing_definition"] = json!(9),
            expected: ResolutionReportError::UnknownDefinition { definition: 9 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
        MalformedCase {
            label: "a record names a reference that does not exist",
            mutate: |report| report["resolutions"][1]["reference"] = json!(5),
            expected: ResolutionReportError::UnknownReference { reference: 5 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
        // The call site's one candidate stays one candidate, so the sort rule
        // has no pair to compare and the certainty rule reads a well-formed
        // resolved record. This lookup is the only rule the mutation meets.
        MalformedCase {
            label: "a candidate names a definition that does not exist",
            mutate: |report| report["resolutions"][1]["candidates"][0]["definition"] = json!(9),
            expected: ResolutionReportError::UnknownDefinition { definition: 9 },
            reach: BuilderReach::WireOnly(BRANDED),
        },
    ])
}

/// The unit slice is not dense, unique, or ordered, or a record contradicts it.
fn unit_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "unit ids are not dense",
            mutate: |report| report["units"][1]["id"] = json!(4),
            expected: ResolutionReportError::NonDenseId {
                collection: ReportCollection::Units,
                position: 1,
                id: 4,
            },
            reach: BuilderReach::WireOnly(DENSE),
        },
        MalformedCase {
            label: "two units share one key",
            mutate: |report| report["units"][1]["key"] = json!(UNIT_A_KEY),
            expected: ResolutionReportError::DuplicateUnitKey {
                key: Box::from(UNIT_A_KEY),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "units are not sorted by key",
            mutate: |report| report["units"][0]["key"] = json!("z/Cargo.toml#lib:alpha"),
            expected: ResolutionReportError::UnsortedEntries {
                collection: ReportCollection::Units,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
        // The two language cases name one unit from two collections. Each
        // refusal carries the offender's own coordinates, so the pair are two
        // values: a validator that reported only the unit would pass both
        // assertions with one of them.
        MalformedCase {
            label: "a definition contradicts its unit's language",
            mutate: |report| report["definitions"][0]["language"] = json!("python"),
            expected: ResolutionReportError::UnitLanguageMismatch {
                collection: ReportCollection::Definitions,
                position: 0,
                unit: 0,
                claimed: Language::Python,
                unit_language: Language::Rust,
            },
            reach: BuilderReach::WireOnly(COPIED_LANGUAGE),
        },
        MalformedCase {
            label: "a reference contradicts its unit's language",
            mutate: |report| report["references"][0]["language"] = json!("python"),
            expected: ResolutionReportError::UnitLanguageMismatch {
                collection: ReportCollection::References,
                position: 0,
                unit: 0,
                claimed: Language::Python,
                unit_language: Language::Rust,
            },
            reach: BuilderReach::WireOnly(COPIED_LANGUAGE),
        },
    ])
}

/// The definition slice is not dense, or its parent relation crosses a unit or
/// closes a cycle.
fn definition_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "definition ids are not dense",
            mutate: |report| report["definitions"][1]["id"] = json!(4),
            expected: ResolutionReportError::NonDenseId {
                collection: ReportCollection::Definitions,
                position: 1,
                id: 4,
            },
            reach: BuilderReach::WireOnly(DENSE),
        },
        MalformedCase {
            label: "a parent definition belongs to another unit",
            mutate: |report| report["definitions"][1]["parent"] = json!(2),
            expected: ResolutionReportError::ForeignParentDefinition {
                definition: 1,
                parent: 2,
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "the definition parent relation is cyclic",
            mutate: |report| {
                report["definitions"][0]["parent"] = json!(1);
                report["definitions"][1]["parent"] = json!(0);
            },
            expected: ResolutionReportError::DefinitionParentCycle { definition: 0 },
            reach: BuilderReach::WireOnly(
                "a parent handle exists before its child is stated, and no writer \
                call reparents a definition, so no stated forest closes a cycle",
            ),
        },
    ])
}

/// The reference slice is not dense, or an enclosing definition crosses a unit.
fn reference_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "reference ids are not dense",
            mutate: |report| report["references"][1]["id"] = json!(4),
            expected: ResolutionReportError::NonDenseId {
                collection: ReportCollection::References,
                position: 1,
                id: 4,
            },
            reach: BuilderReach::WireOnly(DENSE),
        },
        MalformedCase {
            label: "an enclosing definition belongs to another unit",
            mutate: |report| report["references"][1]["enclosing_definition"] = json!(2),
            expected: ResolutionReportError::ForeignEnclosingDefinition {
                reference: 1,
                enclosing: 2,
            },
            reach: BuilderReach::Statable,
        },
    ])
}

/// A reference has no record, two records, or a malformed candidate/gap set.
fn record_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "a reference carries no record",
            mutate: |report| {
                let resolutions = report["resolutions"]
                    .as_array_mut()
                    .expect("resolutions is an array");
                resolutions.truncate(1);
            },
            expected: ResolutionReportError::MissingResolution { reference: 1 },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "two records name one reference",
            mutate: |report| report["resolutions"][1]["reference"] = json!(0),
            expected: ResolutionReportError::DuplicateResolution { reference: 0 },
            reach: BuilderReach::WireOnly(
                "the writer itself refuses a second record for one reference",
            ),
        },
        MalformedCase {
            label: "a record repeats one candidate definition",
            mutate: |report| {
                report["resolutions"][0]["candidates"] = json!([
                    { "definition": 2, "certainty": "possible" },
                    { "definition": 2, "certainty": "possible" },
                ]);
            },
            expected: ResolutionReportError::DuplicateCandidate {
                reference: 0,
                definition: 2,
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a record's candidates are not sorted",
            mutate: |report| {
                report["resolutions"][0]["candidates"] = json!([
                    { "definition": 2, "certainty": "possible" },
                    { "definition": 1, "certainty": "possible" },
                ]);
            },
            expected: ResolutionReportError::UnsortedCandidates {
                reference: 0,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
        MalformedCase {
            label: "a record repeats one gap",
            mutate: |report| {
                report["resolutions"][0]["gaps"] =
                    json!(["external_definition", "external_definition"]);
            },
            expected: ResolutionReportError::DuplicateGap {
                reference: 0,
                gap: ResolutionGap::ExternalDefinition,
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a record's gaps are not sorted",
            mutate: |report| {
                report["resolutions"][0]["gaps"] =
                    json!(["dynamic_dispatch", "external_definition"]);
            },
            expected: ResolutionReportError::UnsortedGaps {
                reference: 0,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
    ])
}

/// A site span runs backwards, covers nothing, or names a path the
/// normalized-path rule rejects: empty, absolute, escaping, or
/// backslash-separated.
///
/// The validator applies the span rule to definitions and to references, so the
/// backwards family is stated on both. The structural order compares a span's
/// start before its end, so the call site's reversed end leaves the reference
/// order intact and the refusal comes from the span rule alone.
fn span_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "a reference span coordinate runs backwards",
            mutate: |report| {
                report["references"][1]["span"]["end"] = json!({ "line": 0, "column": 0 });
            },
            expected: ResolutionReportError::ReversedSiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a span coordinate runs backwards",
            mutate: |report| {
                report["definitions"][0]["span"]["start"] = json!({ "line": 1, "column": 0 });
                report["definitions"][0]["span"]["end"] = json!({ "line": 0, "column": 0 });
            },
            expected: ResolutionReportError::ReversedSiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a span is zero width",
            mutate: |report| {
                report["definitions"][0]["span"]["end"] = json!({ "line": 0, "column": 0 });
            },
            expected: ResolutionReportError::EmptySiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a span path escapes the repository root",
            mutate: |report| {
                report["definitions"][0]["span"]["file"] = json!("../outside/lib.rs");
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("../outside/lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a span path is absolute",
            mutate: |report| {
                report["definitions"][0]["span"]["file"] = json!("/a/src/lib.rs");
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("/a/src/lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a span path is empty",
            mutate: |report| {
                report["definitions"][0]["span"]["file"] = json!("");
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from(""),
            },
            reach: BuilderReach::Statable,
        },
        // `helper` is the only definition in its unit, so a backslash-separated
        // path does not also disturb the structural order. The refusal this
        // case asserts therefore comes from the path rule alone: drop that
        // clause and the report is accepted rather than refused for a
        // neighbouring reason.
        MalformedCase {
            label: "a span path is separated by backslashes",
            mutate: |report| {
                report["definitions"][2]["span"]["file"] = json!("b\\src\\lib.rs");
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("b\\src\\lib.rs"),
            },
            reach: BuilderReach::Statable,
        },
    ])
}

/// A slice is out of its stable structural order.
fn order_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "definitions are not sorted by unit and span",
            mutate: |report| {
                report["definitions"][0]["span"]["start"] = json!({ "line": 9, "column": 0 });
                report["definitions"][0]["span"]["end"] = json!({ "line": 9, "column": 4 });
            },
            expected: ResolutionReportError::UnsortedEntries {
                collection: ReportCollection::Definitions,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
        MalformedCase {
            label: "references are not sorted by unit and span",
            mutate: |report| {
                report["references"][0]["span"]["start"] = json!({ "line": 9, "column": 0 });
                report["references"][0]["span"]["end"] = json!({ "line": 9, "column": 4 });
            },
            expected: ResolutionReportError::UnsortedEntries {
                collection: ReportCollection::References,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
        MalformedCase {
            label: "records are not sorted by reference",
            mutate: |report| {
                let resolutions = report["resolutions"]
                    .as_array_mut()
                    .expect("resolutions is an array");
                resolutions.swap(0, 1);
            },
            expected: ResolutionReportError::UnsortedEntries {
                collection: ReportCollection::Resolutions,
                position: 1,
            },
            reach: BuilderReach::WireOnly(SORTED),
        },
    ])
}

/// Every illegal record shape, stated as a mutation of the fixture's records.
pub fn certainty_cases() -> Box<[MalformedCase]> {
    Box::from([
        MalformedCase {
            label: "a record mixes resolved and possible candidates",
            mutate: |report| {
                report["resolutions"][1]["candidates"] = json!([
                    { "definition": 1, "certainty": "resolved" },
                    { "definition": 2, "certainty": "possible" },
                ]);
            },
            expected: ResolutionReportError::MixedCandidateCertainty { reference: 1 },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a resolved record carries two candidates",
            mutate: |report| {
                report["resolutions"][1]["candidates"] = json!([
                    { "definition": 1, "certainty": "resolved" },
                    { "definition": 2, "certainty": "resolved" },
                ]);
            },
            expected: ResolutionReportError::ResolvedCandidateCount {
                reference: 1,
                candidates: 2,
            },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a resolved record carries a gap",
            mutate: |report| {
                report["resolutions"][1]["gaps"] = json!(["conditional_compilation"]);
            },
            expected: ResolutionReportError::ResolvedWithGaps { reference: 1 },
            reach: BuilderReach::Statable,
        },
        MalformedCase {
            label: "a candidate-free record carries no gap",
            mutate: |report| {
                report["resolutions"][0]["gaps"] = json!([]);
            },
            expected: ResolutionReportError::EmptyResolution { reference: 0 },
            reach: BuilderReach::Statable,
        },
    ])
}
