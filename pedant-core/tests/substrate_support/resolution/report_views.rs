//! Comparable text taken from a validated resolution report.
//!
//! Every syntactic case asserts against ordered `String` lines rather than
//! nested structures, so each borrowed report view is rendered exactly once
//! here and no case reimplements a reader.

use pedant_core::resolution::rust::RustTargetResolution;
use pedant_types::{
    ResolutionRecord, ResolutionReport, ResolutionUnitId, SourceSpan, SymbolDefinition,
    SymbolReference,
};

/// `key` for every unit the report holds, in report order.
pub fn render_units(report: &ResolutionReport) -> Vec<String> {
    report
        .units()
        .iter()
        .map(|unit| format!("{}|{}", unit.key(), unit.name()))
        .collect()
}

/// `unit|kind|name|span|parent` for every definition, in report order.
pub fn render_definitions(report: &ResolutionReport) -> Vec<String> {
    report
        .definitions()
        .iter()
        .map(|definition| {
            format!(
                "{}|{:?}|{}|{}|{}",
                unit_name(report, definition.unit()),
                definition.kind(),
                definition.name(),
                location(definition.span()),
                parent_name(report, definition),
            )
        })
        .collect()
}

/// `unit|kind|text|span` for every reference, in report order.
pub fn render_references(report: &ResolutionReport) -> Vec<String> {
    report
        .references()
        .iter()
        .map(|reference| {
            format!(
                "{}|{:?}|{}|{}",
                unit_name(report, reference.unit()),
                reference.kind(),
                reference.text(),
                location(reference.span()),
            )
        })
        .collect()
}

/// `text@span|candidates|gaps` for every record, in reference order.
pub fn render_records(report: &ResolutionReport) -> Vec<String> {
    report
        .resolutions()
        .iter()
        .map(|record| render_record(report, record))
        .collect()
}

/// `unit|text@span|candidates|gaps` for every record, where each candidate names
/// the unit, name, and span of the definition it selects.
///
/// A source two units share states the same names at the same spans twice, so
/// the candidate name alone cannot tell one unit's definition from the other's.
pub fn render_targets(report: &ResolutionReport) -> Vec<String> {
    report
        .resolutions()
        .iter()
        .map(|record| render_target(report, record))
        .collect()
}

/// The one record a reference at `span` whose text is `text` carries.
pub fn record_for(report: &ResolutionReport, text: &str, line: u32) -> String {
    let matching: Vec<String> = report
        .resolutions()
        .iter()
        .filter(|record| matches_site(report, record, (text, line)))
        .map(|record| render_record(report, record))
        .collect();
    match matching.as_slice() {
        [only] => only.clone(),
        found => panic!(
            "{text} at line {line} has {} records: {found:?}",
            found.len()
        ),
    }
}

/// The one unit-qualified target record at `text` and `line`.
pub fn target_for(report: &ResolutionReport, text: &str, line: u32) -> String {
    let matching: Vec<String> = report
        .resolutions()
        .iter()
        .filter(|record| matches_site(report, record, (text, line)))
        .map(|record| render_target(report, record))
        .collect();
    match matching.as_slice() {
        [only] => only.clone(),
        found => panic!(
            "{text} at line {line} has {} target records: {found:?}",
            found.len()
        ),
    }
}

/// `unit name|snapshot unit` for every binding the resolution carries.
pub fn render_bindings(resolution: &RustTargetResolution) -> Vec<String> {
    let report = resolution.report();
    resolution
        .units()
        .iter()
        .map(|binding| {
            format!(
                "{}|{:?}",
                unit_name(report, binding.unit()),
                binding.snapshot_unit(),
            )
        })
        .collect()
}

/// How one candidate's definition is named in a rendered record.
type CandidateText = fn(&ResolutionReport, &SymbolDefinition) -> String;

fn render_record(report: &ResolutionReport, record: &ResolutionRecord) -> String {
    let reference = reference_of(report, record);
    format!(
        "{}@{}|{}|{}",
        reference.text(),
        location(reference.span()),
        candidates(report, record, candidate_name),
        gaps(record),
    )
}

fn render_target(report: &ResolutionReport, record: &ResolutionRecord) -> String {
    let reference = reference_of(report, record);
    format!(
        "{}|{}@{}|{}|{}",
        unit_name(report, reference.unit()),
        reference.text(),
        location(reference.span()),
        candidates(report, record, candidate_identity),
        gaps(record),
    )
}

fn reference_of<'a>(
    report: &'a ResolutionReport,
    record: &ResolutionRecord,
) -> &'a SymbolReference {
    report
        .references()
        .get(index_of(record.reference().index()))
        .expect("every record names a reference in the report")
}

fn candidate_name(_report: &ResolutionReport, definition: &SymbolDefinition) -> String {
    definition.name().to_string()
}

fn candidate_identity(report: &ResolutionReport, definition: &SymbolDefinition) -> String {
    format!(
        "{}/{}@{}",
        unit_name(report, definition.unit()),
        definition.name(),
        location(definition.span()),
    )
}

fn matches_site(report: &ResolutionReport, record: &ResolutionRecord, site: (&str, u32)) -> bool {
    let (text, line) = site;
    report
        .references()
        .get(index_of(record.reference().index()))
        .is_some_and(|reference| {
            reference.text() == text && reference.span().start().line() == line
        })
}

fn candidates(
    report: &ResolutionReport,
    record: &ResolutionRecord,
    named: CandidateText,
) -> String {
    let rendered: Vec<String> = record
        .candidates()
        .iter()
        .map(|candidate| {
            let definition = report
                .definitions()
                .get(index_of(candidate.definition().index()));
            let unknown = || String::from("<unknown>");
            format!(
                "{:?}:{}",
                candidate.certainty(),
                definition.map_or_else(unknown, |found| named(report, found)),
            )
        })
        .collect();
    rendered.join(",")
}

fn gaps(record: &ResolutionRecord) -> String {
    let rendered: Vec<String> = record.gaps().iter().map(|gap| format!("{gap:?}")).collect();
    rendered.join(",")
}

fn unit_name(report: &ResolutionReport, unit: ResolutionUnitId) -> &str {
    report
        .units()
        .get(index_of(unit.index()))
        .map_or("<unknown>", |found| found.name())
}

fn parent_name<'a>(report: &'a ResolutionReport, definition: &SymbolDefinition) -> &'a str {
    definition
        .parent()
        .and_then(|parent| report.definitions().get(index_of(parent.index())))
        .map_or("-", SymbolDefinition::name)
}

fn location(span: &SourceSpan) -> String {
    format!(
        "{}:{}:{}-{}:{}",
        span.file(),
        span.start().line(),
        span.start().column(),
        span.end().line(),
        span.end().column(),
    )
}

fn index_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
