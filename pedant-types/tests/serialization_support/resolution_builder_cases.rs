//! Every malformed report a writer can state, and the refusal `finish` returns.
//!
//! This table is the builder half of the contract. Deserialization refuses a
//! document; `finish` refuses a producer mid-flight, and a producer is the only
//! way a report is ever written in this repository. A case therefore states one
//! more fact on the fixture draft and finishes, so the refusal comes from the
//! real writer path rather than from a hand-built document.
//!
//! Each label names the wire case in `resolution_cases` it mirrors. The
//! identifiers in the expected errors are the ones `finish`'s own sort assigns,
//! which are not always the wire case's: the fixture's sorted shape is
//! units `0 = alpha`, `1 = beta`; definitions `0 = alpha` (module),
//! `1 = run` (function in alpha), `2 = helper` (function in beta); references
//! `0 = the import`, `1 = the call`; and a stated deviation takes the position
//! its own span earns.

use std::sync::Arc;

use pedant_types::Language;
use pedant_types::resolution::{
    CandidateInput, ReferenceKind, ResolutionCertainty, ResolutionGap, ResolutionReportBuilder,
    ResolutionReportError, SourceSpan, SymbolKind,
};

use crate::resolution_fixture::{
    DraftSites, UNIT_A_KEY, answer_call, answer_import, draft_report, span,
};

/// One malformed report a writer states, and the exact refusal `finish` owes.
pub struct BuilderCase {
    /// The label of the wire case this one mirrors.
    pub label: &'static str,
    /// The facts stated on top of the fixture draft, records included.
    pub state: fn(&mut ResolutionReportBuilder, &DraftSites),
    /// The error `finish` must return.
    pub expected: ResolutionReportError,
}

/// Every structural family a writer can state: a repeated unit key, a
/// cross-unit parent or enclosing definition, an unanswered reference, a
/// repeated candidate or gap, and every illegal span.
pub fn builder_cases() -> Box<[BuilderCase]> {
    unit_cases()
        .into_vec()
        .into_iter()
        .chain(containment_cases())
        .chain(record_cases())
        .chain(span_cases())
        .collect()
}

/// A writer states two units under one key.
fn unit_cases() -> Box<[BuilderCase]> {
    Box::from([BuilderCase {
        label: "two units share one key",
        state: |builder, sites| {
            stated(builder.add_unit(Language::Rust, Arc::from(UNIT_A_KEY), Arc::from("gamma")));
            answer_import(builder, sites);
            answer_call(builder, sites);
        },
        expected: ResolutionReportError::DuplicateUnitKey {
            key: Box::from(UNIT_A_KEY),
        },
    }])
}

/// A writer states a parent or an enclosing definition from another unit.
///
/// Both deviations sit at line 5 of alpha's source, so each sorts last within
/// its own unit: the stray definition takes identifier 2 and pushes `helper`
/// to 3, and the stray reference takes identifier 2.
fn containment_cases() -> Box<[BuilderCase]> {
    Box::from([
        BuilderCase {
            label: "a parent definition belongs to another unit",
            state: |builder, sites| {
                stated(builder.add_definition(
                    &sites.alpha,
                    SymbolKind::Function,
                    Arc::from("orphan"),
                    span("a/src/lib.rs", 5, 0, 6),
                    Some(&sites.helper),
                ));
                answer_import(builder, sites);
                answer_call(builder, sites);
            },
            expected: ResolutionReportError::ForeignParentDefinition {
                definition: 2,
                parent: 3,
            },
        },
        BuilderCase {
            label: "an enclosing definition belongs to another unit",
            state: |builder, sites| {
                let stray = stated(builder.add_reference(
                    &sites.alpha,
                    ReferenceKind::Call,
                    Arc::from("beta::helper"),
                    span("a/src/lib.rs", 5, 0, 6),
                    Some(&sites.helper),
                ));
                stated(builder.set_resolution(
                    &stray,
                    Box::from([]),
                    Box::from([ResolutionGap::MissingDefinition]),
                ));
                answer_import(builder, sites);
                answer_call(builder, sites);
            },
            expected: ResolutionReportError::ForeignEnclosingDefinition {
                reference: 2,
                enclosing: 2,
            },
        },
    ])
}

/// A writer leaves a reference unanswered or repeats a candidate or a gap.
fn record_cases() -> Box<[BuilderCase]> {
    Box::from([
        BuilderCase {
            label: "a reference carries no record",
            state: |builder, sites| answer_import(builder, sites),
            expected: ResolutionReportError::MissingResolution { reference: 1 },
        },
        BuilderCase {
            label: "a record repeats one candidate definition",
            state: |builder, sites| {
                stated(builder.set_resolution(
                    &sites.import,
                    Box::from([
                        CandidateInput::new(sites.helper.clone(), ResolutionCertainty::Possible),
                        CandidateInput::new(sites.helper.clone(), ResolutionCertainty::Possible),
                    ]),
                    Box::from([]),
                ));
                answer_call(builder, sites);
            },
            expected: ResolutionReportError::DuplicateCandidate {
                reference: 0,
                definition: 2,
            },
        },
        BuilderCase {
            label: "a record repeats one gap",
            state: |builder, sites| {
                stated(builder.set_resolution(
                    &sites.import,
                    Box::from([]),
                    Box::from([
                        ResolutionGap::ExternalDefinition,
                        ResolutionGap::ExternalDefinition,
                    ]),
                ));
                answer_call(builder, sites);
            },
            expected: ResolutionReportError::DuplicateGap {
                reference: 0,
                gap: ResolutionGap::ExternalDefinition,
            },
        },
    ])
}

/// A writer states a span that runs backwards, covers nothing, or names a path
/// the normalized-path rule rejects: empty, absolute, escaping, or
/// backslash-separated.
///
/// Each illegal span is carried by one extra definition in alpha, so the rest
/// of the fixture stays valid and the refusal names the span alone. The
/// validator applies the same rule to references, so the backwards family is
/// also stated on one extra reference.
fn span_cases() -> Box<[BuilderCase]> {
    Box::from([
        BuilderCase {
            label: "a reference span coordinate runs backwards",
            state: |builder, sites| stray_reference(builder, sites, span("a/src/lib.rs", 5, 6, 0)),
            expected: ResolutionReportError::ReversedSiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
        },
        BuilderCase {
            label: "a span coordinate runs backwards",
            state: |builder, sites| stray_definition(builder, sites, span("a/src/lib.rs", 5, 6, 0)),
            expected: ResolutionReportError::ReversedSiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
        },
        BuilderCase {
            label: "a span is zero width",
            state: |builder, sites| stray_definition(builder, sites, span("a/src/lib.rs", 5, 0, 0)),
            expected: ResolutionReportError::EmptySiteSpan {
                path: Box::from("a/src/lib.rs"),
            },
        },
        BuilderCase {
            label: "a span path escapes the repository root",
            state: |builder, sites| {
                stray_definition(builder, sites, span("../outside/lib.rs", 0, 0, 4));
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("../outside/lib.rs"),
            },
        },
        BuilderCase {
            label: "a span path is absolute",
            state: |builder, sites| {
                stray_definition(builder, sites, span("/a/src/lib.rs", 0, 0, 4));
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("/a/src/lib.rs"),
            },
        },
        BuilderCase {
            label: "a span path is empty",
            state: |builder, sites| stray_definition(builder, sites, span("", 0, 0, 4)),
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from(""),
            },
        },
        BuilderCase {
            label: "a span path is separated by backslashes",
            state: |builder, sites| {
                stray_definition(builder, sites, span("a\\src\\lib.rs", 0, 0, 4));
            },
            expected: ResolutionReportError::InvalidSourcePath {
                path: Box::from("a\\src\\lib.rs"),
            },
        },
    ])
}

/// Every illegal record shape a writer can state, mirroring the wire table.
pub fn builder_certainty_cases() -> Box<[BuilderCase]> {
    Box::from([
        BuilderCase {
            label: "a record mixes resolved and possible candidates",
            state: |builder, sites| {
                answer_import(builder, sites);
                stated(builder.set_resolution(
                    &sites.call,
                    Box::from([
                        CandidateInput::new(sites.run.clone(), ResolutionCertainty::Resolved),
                        CandidateInput::new(sites.helper.clone(), ResolutionCertainty::Possible),
                    ]),
                    Box::from([]),
                ));
            },
            expected: ResolutionReportError::MixedCandidateCertainty { reference: 1 },
        },
        BuilderCase {
            label: "a resolved record carries two candidates",
            state: |builder, sites| {
                answer_import(builder, sites);
                stated(builder.set_resolution(
                    &sites.call,
                    Box::from([
                        CandidateInput::new(sites.run.clone(), ResolutionCertainty::Resolved),
                        CandidateInput::new(sites.helper.clone(), ResolutionCertainty::Resolved),
                    ]),
                    Box::from([]),
                ));
            },
            expected: ResolutionReportError::ResolvedCandidateCount {
                reference: 1,
                candidates: 2,
            },
        },
        BuilderCase {
            label: "a resolved record carries a gap",
            state: |builder, sites| {
                answer_import(builder, sites);
                stated(builder.set_resolution(
                    &sites.call,
                    Box::from([CandidateInput::new(
                        sites.helper.clone(),
                        ResolutionCertainty::Resolved,
                    )]),
                    Box::from([ResolutionGap::ConditionalCompilation]),
                ));
            },
            expected: ResolutionReportError::ResolvedWithGaps { reference: 1 },
        },
        BuilderCase {
            label: "a candidate-free record carries no gap",
            state: |builder, sites| {
                stated(builder.set_resolution(&sites.import, Box::from([]), Box::from([])));
                answer_call(builder, sites);
            },
            expected: ResolutionReportError::EmptyResolution { reference: 0 },
        },
    ])
}

/// State one case's deviation on a fresh fixture draft and return the refusal
/// `finish` produced.
pub fn finish_refusal(case: &BuilderCase) -> ResolutionReportError {
    let mut draft = draft_report();
    (case.state)(&mut draft.builder, &draft.sites);
    match draft.builder.finish() {
        Ok(_) => panic!("{}: `finish` accepted a malformed report", case.label),
        Err(error) => error,
    }
}

/// One extra definition in alpha carrying an illegal span, with the fixture's
/// own two records so nothing else is missing.
fn stray_definition(builder: &mut ResolutionReportBuilder, sites: &DraftSites, site: SourceSpan) {
    stated(builder.add_definition(
        &sites.alpha,
        SymbolKind::Function,
        Arc::from("stray"),
        site,
        None,
    ));
    answer_import(builder, sites);
    answer_call(builder, sites);
}

/// One extra reference in alpha carrying an illegal span, answered by its own
/// gap record so no reference is left unresolved.
fn stray_reference(builder: &mut ResolutionReportBuilder, sites: &DraftSites, site: SourceSpan) {
    let stray = stated(builder.add_reference(
        &sites.alpha,
        ReferenceKind::Call,
        Arc::from("stray"),
        site,
        None,
    ));
    stated(builder.set_resolution(
        &stray,
        Box::from([]),
        Box::from([ResolutionGap::MissingDefinition]),
    ));
    answer_import(builder, sites);
    answer_call(builder, sites);
}

/// A fact the writer's own checks must admit; only `finish` may refuse it.
fn stated<T>(result: Result<T, ResolutionReportError>) -> T {
    result.expect("the writer admits the stated fact; only `finish` may refuse it")
}
