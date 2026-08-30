//! One read, one parse, and one declaration walk per admitted source — and all
//! of them before a graph node is mapped to anything.
//!
//! The aggregate totals cannot state that. Three reads of one source and none
//! of another sum exactly as one read each, and a count of declaration
//! inventories cannot say whether a parser ran twice. So the observation is a
//! trace: every unit of source work in order, each one carrying the path it was
//! done for and the stage of the revision that was running when it happened.
//!
//! What the stages buy is the second half of the claim. Mapping a graph onto
//! retained declarations and answering a relation, a route, or an analysis both
//! run inside stages of their own, so work either of them did would be recorded
//! against that stage rather than against the admission that preceded it. The
//! rows below require the mapping stage to begin after the last unit of work
//! and require the query stage to be entered and to add none.

use std::collections::BTreeMap;

use pedant_snippet::{
    AnalysisMode, CodeIntelligenceState, PathQuery, RelationDirection, RelationQuery, SourceStep,
    WorkEvent, WorkPhase,
};

use super::fixture::{
    GO_SOURCE, LIBRARY_SOURCE, LIBRARY_UNIT, handle, indexed_graph, project, whole_page,
};
use super::oracles::analyzed;
use super::selection::everything;

/// The three units of work every admitted source states exactly one of, in the
/// order the store does them.
const EVERY_STEP: [SourceStep; 3] = [
    SourceStep::StoreRead,
    SourceStep::LanguageParse,
    SourceStep::DeclarationInventory,
];

/// How many times the query row asks for the same relation page.
///
/// More than once on purpose. A store that answered the first question from
/// retained records and went back to a parser for the second would leave the
/// second ask in the trace, which is the failure this row is named for.
const RELATION_ASKS: usize = 3;

/// Every answer the query row takes: the relation pages, one route, and one
/// analysis per published mode.
///
/// Derived rather than written down. A sixth analysis mode is a sixth answer
/// this row takes and a sixth chance for one of them to reach a parser, and a
/// hand-written count would state the old number beside the new list.
const ANSWERS: usize = RELATION_ASKS + 1 + AnalysisMode::ALL.len();

/// Mapping and querying the graphs cost no read, no parse, and no second walk.
#[test]
fn graph_projection_reuses_source_facts_without_reparse() {
    let (_repository, state) = indexed_graph();

    every_admitted_source_states_one_of_each_unit(&state);
    every_unit_of_work_precedes_the_mapping_stage(&state);
    every_graph_query_enters_its_stage_and_records_nothing(&state);
}

/// The sealed trace, as `path|step` rows in the order they were recorded.
fn rows(state: &CodeIntelligenceState) -> Box<[String]> {
    state
        .index()
        .source_work()
        .trace()
        .iter()
        .map(|event| format!("{}|{}", event.source(), event.step().token()))
        .collect()
}

/// Where each admitted source's three units of work sit in the trace.
fn positions(trace: &[WorkEvent]) -> BTreeMap<(&str, SourceStep), Vec<usize>> {
    let mut held: BTreeMap<(&str, SourceStep), Vec<usize>> = BTreeMap::new();
    for (at, event) in trace.iter().enumerate() {
        held.entry((event.source(), event.step()))
            .or_default()
            .push(at);
    }
    held
}

/// Every admitted source was read once, handed to one parser once, and had one
/// declaration inventory retained — whatever reached it.
fn every_admitted_source_states_one_of_each_unit(state: &CodeIntelligenceState) {
    let index = state.index();
    let trace = index.source_work().trace();
    let held = positions(&trace);
    let admitted: Vec<&str> = index.files().iter().map(|file| file.path()).collect();
    assert!(
        admitted.len() > 4,
        "the fixture admits several sources: {admitted:?}"
    );

    let stated: Vec<String> = admitted
        .iter()
        .flat_map(|path| EVERY_STEP.iter().map(move |step| (*path, *step)))
        .map(|(path, step)| {
            let at = held.get(&(path, step)).map_or(0, Vec::len);
            format!("{path}|{}|{at}", step.token())
        })
        .collect();
    let required: Vec<String> = admitted
        .iter()
        .flat_map(|path| {
            EVERY_STEP
                .iter()
                .map(move |step| format!("{path}|{}|1", step.token()))
        })
        .collect();
    assert_eq!(
        stated,
        required,
        "each admitted source states exactly one read, one parse, and one walk: {:?}",
        rows(state)
    );

    for path in &admitted {
        let ordered: Vec<usize> = EVERY_STEP
            .iter()
            .filter_map(|step| held.get(&(*path, *step))?.first().copied())
            .collect();
        assert!(
            ordered.windows(2).all(|pair| pair[0] < pair[1]),
            "{path} was read, then parsed, then inventoried, in that order: {ordered:?}"
        );
    }

    assert_eq!(
        (
            index.source_work().reads(),
            index.source_work().parses(),
            index.source_work().inventories(),
        ),
        (
            admitted.len() as u64,
            admitted.len() as u64,
            admitted.len() as u64,
        ),
        "and the totals state the same thing the trace does"
    );
    assert_eq!(
        trace.len(),
        admitted.len() * EVERY_STEP.len(),
        "with nothing in the trace that no admitted source owns"
    );
}

/// The library source is in every project graph the workspace states and was
/// read once, because the slices share one store.
///
/// The evidence is the pair of stages the trace states. Every source a project
/// closure reached was admitted while a loader was resolving, and every source
/// left over was admitted after the last one finished — so a source that
/// appeared in both segments would have been admitted twice.
fn every_unit_of_work_precedes_the_mapping_stage(state: &CodeIntelligenceState) {
    let index = state.index();
    let work = index.source_work();
    let trace = work.trace();
    let phases = work.phases();

    assert_eq!(
        phases.iter().map(|entry| entry.phase()).collect::<Vec<_>>(),
        vec![
            WorkPhase::Resolution,
            WorkPhase::LooseCorpus,
            WorkPhase::PhysicalMapping,
        ],
        "a sealed build states three stages, in this order"
    );
    let mapping = phases
        .iter()
        .find(|entry| entry.phase() == WorkPhase::PhysicalMapping)
        .expect("the build mapped its graphs");
    assert_eq!(
        mapping.at(),
        trace.len(),
        "and mapping began after the last unit of source work: {:?}",
        rows(state)
    );

    assert!(
        trace.iter().all(|event| matches!(
            event.phase(),
            WorkPhase::Resolution | WorkPhase::LooseCorpus
        )),
        "so every unit of work was done while sources were being admitted"
    );

    let resolved: Vec<&str> = trace
        .iter()
        .filter(|event| event.phase() == WorkPhase::Resolution)
        .map(WorkEvent::source)
        .collect();
    let loose: Vec<&str> = trace
        .iter()
        .filter(|event| event.phase() == WorkPhase::LooseCorpus)
        .map(WorkEvent::source)
        .collect();
    assert!(
        resolved.contains(&LIBRARY_SOURCE),
        "the library was admitted while every project graph of it resolved: {resolved:?}"
    );
    assert!(
        resolved.contains(&GO_SOURCE),
        "and so was the Go module's source: {resolved:?}"
    );
    assert!(
        loose.contains(&"tool.py"),
        "while a source no slice reached was admitted after them: {loose:?}"
    );
    assert!(
        loose.iter().all(|path| !resolved.contains(path)),
        "and no source was admitted in both stages: {resolved:?} then {loose:?}"
    );
}

/// Every graph question is answered from retained records, inside a stage that
/// would have recorded it had it not been.
fn every_graph_query_enters_its_stage_and_records_nothing(state: &CodeIntelligenceState) {
    let sealed = rows(state);
    let index = state.index();
    let totals = (
        index.source_work().reads(),
        index.source_work().parses(),
        index.source_work().inventories(),
    );

    let seed = handle(state, LIBRARY_SOURCE, "build");
    let relation = RelationQuery {
        structure: seed,
        project: None,
        direction: RelationDirection::Both,
        edges: everything(),
        max_depth: 4,
    };
    for _ in 0..RELATION_ASKS {
        state
            .query_relations(&relation, &whole_page())
            .expect("the relation query answers");
    }
    state
        .find_path(&PathQuery {
            from: seed,
            to: handle(state, LIBRARY_SOURCE, "make"),
            project: None,
            edges: everything(),
        })
        .expect("the path query answers");
    let library = project(state, LIBRARY_UNIT);
    for mode in AnalysisMode::ALL {
        analyzed(state, library, mode);
    }

    let phases = index.source_work().phases();
    let entered = phases.last().expect("the state states its stages");
    assert_eq!(
        entered.phase(),
        WorkPhase::Query,
        "answering entered the query stage, so work done there would carry it"
    );
    assert_eq!(
        phases.len(),
        4,
        "and {ANSWERS} answers entered it once, not once each: {:?}",
        phases.iter().map(|held| held.phase()).collect::<Vec<_>>()
    );
    assert_eq!(
        entered.at(),
        sealed.len(),
        "the stage began at the end of the sealed trace"
    );
    assert_eq!(
        rows(state),
        sealed,
        "and no answer opened a file, reached a parser, or walked a declaration"
    );
    assert_eq!(
        (
            index.source_work().reads(),
            index.source_work().parses(),
            index.source_work().inventories(),
        ),
        totals,
        "which the totals state too"
    );
}
