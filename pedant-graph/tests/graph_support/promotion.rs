//! One syntactic report restated at the semantic tier.
//!
//! The tier cases need two reports over one snapshot that differ in resolution
//! evidence alone. No resolver produces that pair, so the promoted report is
//! rebuilt here through the public builder: every unit, definition, and
//! reference is restated exactly, and only the answers change.

use std::sync::Arc;

use pedant_core::resolution::rust::{RustResolutionSnapshot, RustTargetResolution};
use pedant_types::{
    CandidateInput, DefinitionHandle, ReferenceHandle, ResolutionCandidate, ResolutionCertainty,
    ResolutionGap, ResolutionRecord, ResolutionReport, ResolutionReportBuilder,
    ResolutionReportLimits, ResolutionTier, ResolutionUnitHandle, SymbolDefinition,
    SymbolReference,
};

/// The same report at the semantic tier, with one candidate withdrawn and one
/// downgraded, validated against the same snapshot.
///
/// Definitions are restated parent-first because a builder cannot name a parent
/// it has not issued a handle for; `finish` restores the report's own order.
pub fn promoted_resolution(
    snapshot: &RustResolutionSnapshot,
    report: &ResolutionReport,
) -> RustTargetResolution {
    let mut builder =
        ResolutionReportBuilder::new(ResolutionTier::Semantic, ResolutionReportLimits::default());
    let units: Vec<ResolutionUnitHandle> = report
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
        .collect();
    let definitions = restate_definitions(&mut builder, report, &units);
    let references = restate_references(&mut builder, report, (&units, &definitions));
    restate_resolutions(&mut builder, report, (&definitions, &references));
    let promoted = builder.finish().expect("the restated report is valid");
    RustTargetResolution::try_new(snapshot, promoted)
        .expect("the restated report binds to the same snapshot")
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

fn restate_resolutions(
    builder: &mut ResolutionReportBuilder,
    report: &ResolutionReport,
    bound: (&[DefinitionHandle], &[ReferenceHandle]),
) {
    let (definitions, references) = bound;
    for (position, record) in report.resolutions().iter().enumerate() {
        let (candidates, gaps) = promoted_answer(position, record, definitions);
        builder
            .set_resolution(&references[position], candidates, gaps)
            .expect("restating an answer succeeds");
    }
}

/// The answer each record takes at the promoted tier.
///
/// Record 13 keeps its candidate under a weaker certainty and a stated gap;
/// record 14 withdraws its candidate and states why. Every other record is
/// restated unchanged.
fn promoted_answer(
    position: usize,
    record: &ResolutionRecord,
    definitions: &[DefinitionHandle],
) -> (Box<[CandidateInput]>, Box<[ResolutionGap]>) {
    let candidates: Box<[CandidateInput]> = match position {
        14 => Box::from([]),
        _ => record
            .candidates()
            .iter()
            .map(|candidate| restated_candidate(position, candidate, definitions))
            .collect(),
    };
    let gaps: Box<[ResolutionGap]> = match position {
        13 => Box::from([ResolutionGap::ConditionalCompilation]),
        14 => Box::from([ResolutionGap::MissingDefinition]),
        _ => record.gaps().into(),
    };
    (candidates, gaps)
}

/// One restated candidate. Record 13 is the deliberate certainty downgrade.
fn restated_candidate(
    position: usize,
    candidate: &ResolutionCandidate,
    definitions: &[DefinitionHandle],
) -> CandidateInput {
    let certainty = match position {
        13 => ResolutionCertainty::Possible,
        _ => candidate.certainty(),
    };
    CandidateInput::new(
        definitions[candidate.definition().index() as usize].clone(),
        certainty,
    )
}
