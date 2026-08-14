//! One syntactic report restated through the public builder.
//!
//! The tier cases need two reports over one snapshot that differ in resolution
//! evidence alone, and the cache identity cases need one report per claim
//! dimension. No resolver produces either pair, so a restated report is rebuilt
//! here: every unit, definition, and reference is copied exactly, and the one
//! stated difference is applied on the way through.

use std::sync::Arc;

use pedant_core::resolution::rust::{RustResolutionSnapshot, RustTargetResolution};
use pedant_types::{
    CandidateInput, DefinitionHandle, ReferenceHandle, ReferenceKind, ResolutionCandidate,
    ResolutionCertainty, ResolutionGap, ResolutionRecord, ResolutionReport,
    ResolutionReportBuilder, ResolutionReportLimits, ResolutionTier, ResolutionUnitHandle,
    SymbolDefinition, SymbolKind, SymbolReference,
};

/// The one difference a restated report carries.
///
/// Every variant is a valid report over the same snapshot, so each is a claim a
/// caller can legitimately hand the graph beside the report the resolver
/// produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restatement {
    /// Every fact copied, at the report's own tier.
    Exact,
    /// Every fact copied, at the semantic tier.
    Tier,
    /// The semantic tier with record 13 downgraded and record 14 withdrawn.
    Promoted,
    /// The first answered record's candidates weakened to `Possible`.
    Certainty,
    /// The first answered record's candidates withdrawn, and the absence stated.
    Candidates,
    /// The first unanswered record's stated gaps replaced.
    Gaps,
    /// One further definition over the first definition's own span.
    Definitions,
    /// One further reference over the first reference's own span.
    References,
    /// The first definition stated a second time, field for field.
    ///
    /// The report contract sorts definitions by unit, span, kind, and name and
    /// permits equal keys, so the twin is distinguished by its occurrence among
    /// them and by nothing else.
    Tied,
    /// The tied pair beside one further definition over the same span.
    ///
    /// The added record sorts among the earliest definitions the report states,
    /// so every later dense identity moves while the tied pair does not.
    TiedProbe,
}

/// The name a case reports one restatement by.
impl Restatement {
    /// The claim dimension this restatement drives.
    pub fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Tier => "tier",
            Self::Promoted => "promoted",
            Self::Certainty => "certainty",
            Self::Candidates => "candidates",
            Self::Gaps => "gaps",
            Self::Definitions => "definitions",
            Self::References => "references",
            Self::Tied => "tied definitions",
            Self::TiedProbe => "tied definitions beside an earlier record",
        }
    }

    /// The tier the restated report is written at.
    fn tier(self, report: &ResolutionReport) -> ResolutionTier {
        match self {
            Self::Tier | Self::Promoted => ResolutionTier::Semantic,
            _ => report.tier(),
        }
    }
}

/// The same report at the semantic tier, with one candidate withdrawn and one
/// downgraded, validated against the same snapshot.
pub fn promoted_resolution(
    snapshot: &RustResolutionSnapshot,
    report: &ResolutionReport,
) -> RustTargetResolution {
    restate(snapshot, report, Restatement::Promoted)
}

/// One restated report, bound to the same snapshot it was copied from.
///
/// Definitions are restated parent-first because a builder cannot name a parent
/// it has not issued a handle for; `finish` restores the report's own order.
pub fn restate(
    snapshot: &RustResolutionSnapshot,
    report: &ResolutionReport,
    restatement: Restatement,
) -> RustTargetResolution {
    let mut builder =
        ResolutionReportBuilder::new(restatement.tier(report), ResolutionReportLimits::default());
    let units = restate_units(&mut builder, report);
    let definitions = restate_definitions(&mut builder, report, &units);
    let references = restate_references(&mut builder, report, (&units, &definitions));
    restate_resolutions(
        &mut builder,
        report,
        (&definitions, &references),
        restatement,
    );
    state_further_records(&mut builder, report, (&units, &definitions), restatement);
    let restated = builder.finish().expect("the restated report is valid");
    RustTargetResolution::try_new(snapshot, restated)
        .expect("the restated report binds to the same snapshot")
}

fn restate_units(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
) -> Vec<ResolutionUnitHandle> {
    report
        .units()
        .iter()
        .map(|unit| {
            builder
                .add_unit(
                    unit.language(),
                    Arc::from(unit.key()),
                    Arc::from(unit.name()),
                )
                .expect("restating a unit succeeds")
        })
        .collect()
}

/// The one further definition or reference a restatement adds, if it adds one.
///
/// Both are stated over a span the copied report already carries, so the added
/// record is a graph-relevant change to a valid report rather than a coordinate
/// the snapshot cannot prove.
fn state_further_records(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    bound: (&[ResolutionUnitHandle], &[DefinitionHandle]),
    restatement: Restatement,
) {
    match restatement {
        Restatement::Definitions => state_further_definition(builder, report, bound.0),
        Restatement::References => state_further_reference(builder, report, bound.0),
        Restatement::Tied => state_tied_definition(builder, report, bound),
        Restatement::TiedProbe => {
            state_tied_definition(builder, report, bound);
            state_further_definition(builder, report, bound.0);
        }
        _ => (),
    }
}

/// The first definition stated a second time, field for field.
///
/// The twin copies the unit, kind, name, span, and logical parent of the record
/// it doubles, so the two agree on every column the report sorts by and differ
/// only in the order they were stated in.
fn state_tied_definition(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    bound: (&[ResolutionUnitHandle], &[DefinitionHandle]),
) {
    let (units, definitions) = bound;
    let first = report
        .definitions()
        .first()
        .expect("the corpus states a definition");
    let parent = first
        .parent()
        .map(|parent| definitions[parent.index() as usize].clone());
    builder
        .add_definition(
            &units[first.unit().index() as usize],
            first.kind(),
            Arc::from(first.name()),
            SymbolDefinition::span(first).clone(),
            parent.as_ref(),
        )
        .expect("stating a tied definition succeeds");
}

fn state_further_definition(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    units: &[ResolutionUnitHandle],
) {
    let first = report
        .definitions()
        .first()
        .expect("the corpus states a definition");
    builder
        .add_definition(
            &units[first.unit().index() as usize],
            SymbolKind::Constant,
            Arc::from("cache_probe"),
            SymbolDefinition::span(first).clone(),
            None,
        )
        .expect("stating a further definition succeeds");
}

fn state_further_reference(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    units: &[ResolutionUnitHandle],
) {
    let first = report
        .references()
        .first()
        .expect("the corpus states a reference");
    let handle = builder
        .add_reference(
            &units[first.unit().index() as usize],
            ReferenceKind::Call,
            Arc::from("cache_probe"),
            SymbolReference::span(first).clone(),
            None,
        )
        .expect("stating a further reference succeeds");
    builder
        .set_resolution(
            &handle,
            Box::from([]),
            Box::from([ResolutionGap::MissingDefinition]),
        )
        .expect("stating a further answer succeeds");
}

fn restate_definitions(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    units: &[ResolutionUnitHandle],
) -> Vec<DefinitionHandle> {
    let mut handles: Vec<Option<DefinitionHandle>> = vec![None; report.definitions().len()];
    for position in parent_first_order(report) {
        let definition = &report.definitions()[position];
        let handle = restate_definition(builder, (definition, units), &handles);
        handles[position] = Some(handle);
    }
    handles
        .into_iter()
        .map(|handle| handle.expect("every definition is restated"))
        .collect()
}

fn restate_definition(
    builder: &mut ResolutionReportBuilder,
    stated: (&SymbolDefinition, &[ResolutionUnitHandle]),
    handles: &[Option<DefinitionHandle>],
) -> DefinitionHandle {
    let (definition, units) = stated;
    let parent = definition
        .parent()
        .and_then(|parent| handles[parent.index() as usize].clone());
    builder
        .add_definition(
            &units[definition.unit().index() as usize],
            definition.kind(),
            Arc::from(definition.name()),
            SymbolDefinition::span(definition).clone(),
            parent.as_ref(),
        )
        .expect("restating a definition succeeds")
}

/// Definition positions ordered so every parent precedes its children.
fn parent_first_order(report: &ResolutionReport) -> Vec<usize> {
    let mut ordered = Vec::with_capacity(report.definitions().len());
    let mut placed = vec![false; report.definitions().len()];
    for start in 0..report.definitions().len() {
        let mut chain = Vec::new();
        let mut current = Some(start);
        while let Some(position) = current.filter(|position| !placed[*position]) {
            chain.push(position);
            current = report.definitions()[position]
                .parent()
                .map(|parent| parent.index() as usize);
        }
        for position in chain.into_iter().rev() {
            placed[position] = true;
            ordered.push(position);
        }
    }
    ordered
}

fn restate_references(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    bound: (&[ResolutionUnitHandle], &[DefinitionHandle]),
) -> Vec<ReferenceHandle> {
    let (units, definitions) = bound;
    report
        .references()
        .iter()
        .map(|reference| {
            let enclosing = reference
                .enclosing_definition()
                .map(|enclosing| definitions[enclosing.index() as usize].clone());
            builder
                .add_reference(
                    &units[reference.unit().index() as usize],
                    reference.kind(),
                    Arc::from(reference.text()),
                    SymbolReference::span(reference).clone(),
                    enclosing.as_ref(),
                )
                .expect("restating a reference succeeds")
        })
        .collect()
}

/// One restatement beside the record and position its answer dimensions change.
///
/// The answered record is chosen rather than fixed at zero: weakening or
/// withdrawing an answer that states no candidate would restate the report
/// unchanged and prove nothing about the dimension it claims to drive.
struct Answers {
    restatement: Restatement,
    answered: usize,
    gapped: Option<usize>,
    position: usize,
}

fn restate_resolutions(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    bound: (&[DefinitionHandle], &[ReferenceHandle]),
    restatement: Restatement,
) {
    let (definitions, references) = bound;
    let answered = first_answered(report);
    let gapped = first_gapped(report);
    for (position, record) in report.resolutions().iter().enumerate() {
        let stated = Answers {
            restatement,
            answered,
            gapped,
            position,
        };
        let (candidates, gaps) = restated_answer(&stated, record, definitions);
        builder
            .set_resolution(&references[position], candidates, gaps)
            .expect("restating an answer succeeds");
    }
}

/// The first record that states a candidate at all.
fn first_answered(report: &ResolutionReport) -> usize {
    report
        .resolutions()
        .iter()
        .position(|record| !record.candidates().is_empty())
        .expect("the corpus states a resolved candidate")
}

/// The first record that states a gap instead of a candidate, when the report
/// states one at all.
///
/// A record either answers or states why it cannot; restating the gaps of an
/// answered record would be a report the builder refuses, not another claim. A
/// corpus that resolves everything has no such record, and the case that drives
/// the gap dimension proves its restated report differs rather than reading a
/// position that is not there.
fn first_gapped(report: &ResolutionReport) -> Option<usize> {
    report
        .resolutions()
        .iter()
        .position(|record| record.candidates().is_empty())
}

/// The gaps the gap dimension restates one record with.
const RESTATED_GAPS: [ResolutionGap; 2] = [
    ResolutionGap::ExternalDefinition,
    ResolutionGap::DynamicDispatch,
];

/// The answer one record takes under one restatement.
///
/// The promoted tier withdraws record 14 and downgrades record 13; the three
/// answer dimensions each change the first answered record alone. Every other
/// record is restated unchanged.
fn restated_answer(
    stated: &Answers,
    record: &ResolutionRecord,
    definitions: &[DefinitionHandle],
) -> (Box<[CandidateInput]>, Box<[ResolutionGap]>) {
    let candidates: Box<[CandidateInput]> = match withdraws(stated) {
        true => Box::from([]),
        false => record
            .candidates()
            .iter()
            .map(|candidate| restated_candidate(stated, candidate, definitions))
            .collect(),
    };
    (candidates, restated_gaps(stated, record))
}

/// Whether one record's candidates are withdrawn by one restatement.
fn withdraws(stated: &Answers) -> bool {
    match stated.restatement {
        Restatement::Promoted => stated.position == 14,
        Restatement::Candidates => stated.position == stated.answered,
        _ => false,
    }
}

/// The gaps one record states under one restatement.
fn restated_gaps(stated: &Answers, record: &ResolutionRecord) -> Box<[ResolutionGap]> {
    let answered = stated.position == stated.answered;
    let gapped = stated.gapped == Some(stated.position);
    match (stated.restatement, stated.position) {
        (Restatement::Promoted, 13) => Box::from([ResolutionGap::ConditionalCompilation]),
        (Restatement::Promoted, 14) => Box::from([ResolutionGap::MissingDefinition]),
        (Restatement::Candidates, _) if answered => Box::from([ResolutionGap::MissingDefinition]),
        (Restatement::Gaps, _) if gapped => Box::from(RESTATED_GAPS),
        _ => record.gaps().into(),
    }
}

/// One restated candidate, weakened where the restatement says so.
fn restated_candidate(
    stated: &Answers,
    candidate: &ResolutionCandidate,
    definitions: &[DefinitionHandle],
) -> CandidateInput {
    let weakened = match stated.restatement {
        Restatement::Promoted => stated.position == 13,
        Restatement::Certainty => stated.position == stated.answered,
        _ => false,
    };
    let certainty = match weakened {
        true => ResolutionCertainty::Possible,
        false => candidate.certainty(),
    };
    CandidateInput::new(
        definitions[candidate.definition().index() as usize].clone(),
        certainty,
    )
}
