//! Flat renderings of a published Go project resolution.
//!
//! Whole ordered lists are compared against written-down tables, so a
//! definition, a reference, a candidate, or a gap that was gained, lost,
//! reordered, or re-certified fails the comparison rather than slipping past an
//! assertion that never asked.

use pedant_core::resolution::go::GoProjectResolution;
use pedant_types::{
    ResolutionCertainty, ResolutionRecord, ResolutionReport, SymbolDefinition, SymbolReference,
};

/// `<import path>|<context>` for every report unit, in report order.
pub fn units(resolution: &GoProjectResolution) -> Box<[Box<str>]> {
    resolution
        .report()
        .units()
        .iter()
        .map(|unit| Box::from(unit.key()))
        .collect()
}

/// `<unit>|<kind>|<name>|<file>:<line>|<parent>` for every definition.
pub fn definitions(resolution: &GoProjectResolution) -> Box<[Box<str>]> {
    let report = resolution.report();
    report
        .definitions()
        .iter()
        .map(|definition| definition_text(report, definition))
        .collect()
}

fn definition_text(report: &ResolutionReport, definition: &SymbolDefinition) -> Box<str> {
    let span = SymbolDefinition::span(definition);
    format!(
        "{}|{:?}|{}|{}:{}|{}",
        unit_key(report, definition.unit().index()),
        definition.kind(),
        definition.name(),
        span.file(),
        span.start().line(),
        definition
            .parent()
            .map(|parent| definition_name(report, parent.index()))
            .unwrap_or_default()
    )
    .into_boxed_str()
}

/// `<unit>|<kind>|<text>|<file>:<line>|<certainty>|<candidates>|<gaps>` for
/// every reference, in report order.
pub fn references(resolution: &GoProjectResolution) -> Box<[Box<str>]> {
    let report = resolution.report();
    report
        .references()
        .iter()
        .zip(report.resolutions())
        .map(|(reference, record)| reference_text(report, reference, record))
        .collect()
}

fn reference_text(
    report: &ResolutionReport,
    reference: &SymbolReference,
    record: &ResolutionRecord,
) -> Box<str> {
    let span = SymbolReference::span(reference);
    format!(
        "{}|{:?}|{}|{}:{}|{}|{}|{}",
        unit_key(report, reference.unit().index()),
        reference.kind(),
        reference.text(),
        span.file(),
        span.start().line(),
        certainty_token(record),
        candidate_text(report, record),
        gap_text(record)
    )
    .into_boxed_str()
}

/// The one certainty every candidate of a record shares, or `-` when the record
/// names none. A report carrying a mixed record cannot exist, so a single token
/// states the whole answer.
fn certainty_token(record: &ResolutionRecord) -> &'static str {
    match record.candidates().first().map(|first| first.certainty()) {
        None => "-",
        Some(ResolutionCertainty::Resolved) => "resolved",
        Some(ResolutionCertainty::Possible) => "possible",
    }
}

fn candidate_text(report: &ResolutionReport, record: &ResolutionRecord) -> Box<str> {
    let named: Box<[Box<str>]> = record
        .candidates()
        .iter()
        .map(|candidate| candidate_label(report, candidate.definition().index()))
        .collect();
    joined(&named)
}

fn candidate_label(report: &ResolutionReport, definition: u32) -> Box<str> {
    let found = report
        .definitions()
        .get(definition as usize)
        .expect("a candidate names a definition of its own report");
    format!(
        "{}::{}",
        unit_key(report, found.unit().index()),
        found.name()
    )
    .into_boxed_str()
}

fn gap_text(record: &ResolutionRecord) -> Box<str> {
    let named: Box<[Box<str>]> = record
        .gaps()
        .iter()
        .map(|gap| format!("{gap:?}").into_boxed_str())
        .collect();
    joined(&named)
}

fn joined(parts: &[Box<str>]) -> Box<str> {
    let borrowed: Box<[&str]> = parts.iter().map(|part| &**part).collect();
    borrowed.join(",").into_boxed_str()
}

fn unit_key(report: &ResolutionReport, unit: u32) -> &str {
    report
        .units()
        .get(unit as usize)
        .expect("a record names a unit of its own report")
        .key()
}

fn definition_name(report: &ResolutionReport, definition: u32) -> Box<str> {
    report
        .definitions()
        .get(definition as usize)
        .map(|found| Box::from(found.name()))
        .expect("a parent names a definition of its own report")
}

/// `<kind>|<text>|<file>:<line>|<answer file>:<line>,…` for every reference of
/// one unit that names one of `named`.
///
/// Every other table labels a candidate `<unit>::<name>`, which cannot tell two
/// definitions sharing a name apart. Go's promotion rule is exactly that
/// question: when a direct member and a promoted one are both called `Label`,
/// only the site the answer was declared at says which embedding level answered.
pub fn member_answers(
    resolution: &GoProjectResolution,
    key: &str,
    named: &[&str],
) -> Box<[Box<str>]> {
    let report = resolution.report();
    report
        .references()
        .iter()
        .zip(report.resolutions())
        .filter(|(reference, _)| unit_key(report, reference.unit().index()) == key)
        .filter(|(reference, _)| named.contains(&reference.text()))
        .map(|(reference, record)| answer_text(report, reference, record))
        .collect()
}

fn answer_text(
    report: &ResolutionReport,
    reference: &SymbolReference,
    record: &ResolutionRecord,
) -> Box<str> {
    let span = SymbolReference::span(reference);
    let sites: Box<[Box<str>]> = record
        .candidates()
        .iter()
        .map(|candidate| candidate_site(report, candidate.definition().index()))
        .collect();
    format!(
        "{:?}|{}|{}:{}|{}",
        reference.kind(),
        reference.text(),
        span.file(),
        span.start().line(),
        joined(&sites)
    )
    .into_boxed_str()
}

/// Where one candidate definition is written.
fn candidate_site(report: &ResolutionReport, definition: u32) -> Box<str> {
    let found = report
        .definitions()
        .get(definition as usize)
        .expect("a candidate names a definition of its own report");
    let span = SymbolDefinition::span(found);
    format!("{}:{}", span.file(), span.start().line()).into_boxed_str()
}

/// Every reference of one unit, which is what a case comparing one package's
/// answers writes down.
pub fn unit_references(resolution: &GoProjectResolution, key: &str) -> Box<[Box<str>]> {
    references(resolution)
        .iter()
        .filter(|line| line.starts_with(&format!("{key}|")))
        .cloned()
        .collect()
}

/// Every definition of one unit.
pub fn unit_definitions(resolution: &GoProjectResolution, key: &str) -> Box<[Box<str>]> {
    definitions(resolution)
        .iter()
        .filter(|line| line.starts_with(&format!("{key}|")))
        .cloned()
        .collect()
}
