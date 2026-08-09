//! The one valid report every resolution-schema case starts from.
//!
//! Built through the public builder, so a case that mutates its wire form is
//! mutating something the production writer actually produces rather than a
//! hand-written document that may differ in several ways at once. A `finish`
//! case stops one step earlier, at the same builder before its records are
//! stated, so the two construction boundaries deviate from one shape.
//!
//! The fixture's sorted shape is fixed and every case below reads it:
//! units `0 = alpha`, `1 = beta`; definitions `0 = alpha` (module),
//! `1 = run` (function in alpha), `2 = helper` (function in beta);
//! references `0 = the import`, `1 = the call`; records `0` carries the
//! import's gap and record `1` carries the call's resolved candidate.

use std::sync::Arc;

use pedant_types::Language;
use pedant_types::resolution::{
    CandidateInput, DefinitionHandle, ReferenceHandle, ReferenceKind, ResolutionCertainty,
    ResolutionGap, ResolutionReport, ResolutionReportBuilder, ResolutionReportLimits,
    ResolutionTier, ResolutionUnitHandle, SourcePosition, SourceSpan, SymbolKind,
};
use serde_json::Value;

/// Stable key of the fixture's root unit.
pub const UNIT_A_KEY: &str = "a/Cargo.toml#lib:alpha";
/// Stable key of the fixture's dependency unit.
pub const UNIT_B_KEY: &str = "b/Cargo.toml#lib:beta";

/// A repository-relative span on one line, from `start` to `end` columns.
pub fn span(file: &str, line: u32, start: u32, end: u32) -> SourceSpan {
    SourceSpan::new(
        Arc::from(file),
        SourcePosition::new(line, start),
        SourcePosition::new(line, end),
    )
}

/// The fixture's units, definitions, and references, stated but not answered.
///
/// A `finish` case starts here, states one more fact, and finishes; the wire
/// cases start from the same report's serialized form. Both boundaries
/// therefore deviate from one shape rather than from two similar ones.
pub struct Draft {
    /// The writer holding everything stated so far.
    pub builder: ResolutionReportBuilder,
    /// The handles a case needs to state one more fact.
    pub sites: DraftSites,
}

/// The handles the fixture issued, named as the fixture's records are named.
pub struct DraftSites {
    /// The root unit `alpha`.
    pub alpha: ResolutionUnitHandle,
    /// The function `run`, nested in the module `alpha`.
    pub run: DefinitionHandle,
    /// The function `helper`, in the dependency unit `beta`.
    pub helper: DefinitionHandle,
    /// The import site in `alpha`, which resolves to nothing.
    pub import: ReferenceHandle,
    /// The call site in `alpha`, which resolves across units to `helper`.
    pub call: ReferenceHandle,
}

/// State the fixture's two units, three definitions, and two reference sites,
/// leaving every reference unanswered.
pub fn draft_report() -> Draft {
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Syntactic, ResolutionReportLimits::default());
    let alpha = builder
        .add_unit(Language::Rust, Arc::from(UNIT_A_KEY), Arc::from("alpha"))
        .expect("alpha is admitted");
    let beta = builder
        .add_unit(Language::Rust, Arc::from(UNIT_B_KEY), Arc::from("beta"))
        .expect("beta is admitted");
    let root = builder
        .add_definition(
            &alpha,
            SymbolKind::Module,
            Arc::from("alpha"),
            span("a/src/lib.rs", 0, 0, 1),
            None,
        )
        .expect("the root module is admitted");
    let run = builder
        .add_definition(
            &alpha,
            SymbolKind::Function,
            Arc::from("run"),
            span("a/src/lib.rs", 2, 4, 20),
            Some(&root),
        )
        .expect("the nested function is admitted");
    let helper = builder
        .add_definition(
            &beta,
            SymbolKind::Function,
            Arc::from("helper"),
            span("b/src/lib.rs", 1, 0, 18),
            None,
        )
        .expect("the dependency function is admitted");
    let import = builder
        .add_reference(
            &alpha,
            ReferenceKind::Import,
            Arc::from("std::fmt"),
            span("a/src/lib.rs", 1, 4, 12),
            None,
        )
        .expect("the import site is admitted");
    let call = builder
        .add_reference(
            &alpha,
            ReferenceKind::Call,
            Arc::from("beta::helper"),
            span("a/src/lib.rs", 3, 8, 22),
            Some(&run),
        )
        .expect("the call site is admitted");
    Draft {
        builder,
        sites: DraftSites {
            alpha,
            run,
            helper,
            import,
            call,
        },
    }
}

/// State the import's answer: no candidate and one external-definition gap.
pub fn answer_import(builder: &mut ResolutionReportBuilder, sites: &DraftSites) {
    builder
        .set_resolution(
            &sites.import,
            Box::from([]),
            Box::from([ResolutionGap::ExternalDefinition]),
        )
        .expect("the gap record is admitted");
}

/// State the call's answer: the resolved cross-unit candidate `helper`.
pub fn answer_call(builder: &mut ResolutionReportBuilder, sites: &DraftSites) {
    builder
        .set_resolution(
            &sites.call,
            Box::from([CandidateInput::new(
                sites.helper.clone(),
                ResolutionCertainty::Resolved,
            )]),
            Box::from([]),
        )
        .expect("the resolved record is admitted");
}

/// State the call's answer as two narrowed-but-unproven candidates: the local
/// `run` and the cross-unit `helper`, beside whatever gaps the caller states.
///
/// This is the shape a condition or an ambiguous path produces. The gaps say
/// whether the candidate set itself is known to be complete, so a caller states
/// none when the alternatives are all present and one when they are not.
pub fn answer_call_as_possible(
    builder: &mut ResolutionReportBuilder,
    sites: &DraftSites,
    gaps: Box<[ResolutionGap]>,
) {
    builder
        .set_resolution(
            &sites.call,
            Box::from([
                CandidateInput::new(sites.run.clone(), ResolutionCertainty::Possible),
                CandidateInput::new(sites.helper.clone(), ResolutionCertainty::Possible),
            ]),
            gaps,
        )
        .expect("the possible record is admitted");
}

/// A valid two-unit report: a cross-unit resolved call, an unresolved import
/// carrying one gap, and a nested definition whose parent is its own module.
pub fn valid_report() -> ResolutionReport {
    let mut draft = draft_report();
    answer_import(&mut draft.builder, &draft.sites);
    answer_call(&mut draft.builder, &draft.sites);
    draft.builder.finish().expect("the fixture report is valid")
}

/// The same report with the call answered by two possible candidates and the
/// stated gaps.
///
/// `finish` returning this is the claim: a possible candidate set is legal both
/// alone and beside a gap, and no other case proves it, because every other
/// case that mentions `Possible` is a refusal.
pub fn possible_report(gaps: Box<[ResolutionGap]>) -> ResolutionReport {
    let mut draft = draft_report();
    answer_import(&mut draft.builder, &draft.sites);
    answer_call_as_possible(&mut draft.builder, &draft.sites, gaps);
    draft
        .builder
        .finish()
        .expect("a possible candidate set is a legal record shape")
}

/// The fixture report as wire JSON, the starting point of every malformed case.
pub fn valid_report_json() -> Value {
    serde_json::to_value(valid_report()).expect("the fixture report serializes")
}
