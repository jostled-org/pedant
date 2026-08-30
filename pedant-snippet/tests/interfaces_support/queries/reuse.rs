//! What a query costs: one read and one declaration walk per source, spent
//! before the first question and never again.

use pedant_snippet::{
    CodeIntelligenceState, MatchMode, NavigationResponse, ProjectRecord, StructureHandle,
};

use super::support::{column_of, first_page, mixed, page, search};

/// Every navigation query answers from retained records, so the source work one
/// index cost is the work it cost to build.
#[test]
fn navigation_queries_reuse_one_inventory_without_reparse() {
    let (repository, state) = mixed();
    let admitted = state.index().files().len() as u64;
    assert!(
        admitted > 1,
        "the mixed repository admits a corpus to reuse"
    );

    let reads = state.index().source_work().reads();
    let inventories = state.index().source_work().inventories();
    assert_eq!(
        reads, admitted,
        "one physical read per admitted source, whatever reached it"
    );
    assert_eq!(
        inventories, admitted,
        "and one declaration walk, whichever language owner took it"
    );

    // The tree is removed before the first query. A query that opened a file
    // would fail here rather than quietly cost a read, and the counters below
    // then have nothing left to hide.
    repository.remove();

    every_query_answers_the_same_twice(&state);
    assert_eq!(
        state.index().source_work().reads(),
        reads,
        "no query read a source"
    );
    assert_eq!(
        state.index().source_work().inventories(),
        inventories,
        "and no query took a second declaration walk"
    );
}

/// Run every navigation operation twice and require one answer each time.
fn every_query_answers_the_same_twice(state: &CodeIntelligenceState) {
    let first = every_answer(state);
    let second = every_answer(state);
    assert_eq!(
        first, second,
        "an immutable index answers the same question the same way"
    );
    assert!(
        first.len() > 50,
        "and the sweep asked enough to be worth repeating: {}",
        first.len()
    );
}

/// Every answer this index states, as one comparable list.
///
/// Boxed on the way out: the list grows while the sweep runs and nothing
/// touches it after, so what the caller holds owns its exact length.
fn every_answer(state: &CodeIntelligenceState) -> Box<[String]> {
    let mut answers = Vec::new();

    let projects = state
        .list_projects(&page(Some(1), None))
        .expect("the listing answers");
    answers.push(rendered_units(&projects));
    // One continuation per project is the most a page of one can need, and the
    // bound is what makes a cursor that keeps handing back a continuation a
    // failure rather than a run that never ends. An unbounded traversal here
    // would hang the suite on exactly the defect it exists to catch.
    let mut cursor = projects.next_page();
    for _ in 0..state.index().projects().len() {
        let Some(held) = cursor else {
            break;
        };
        let continued = state
            .list_projects(&page(Some(1), Some(held)))
            .expect("the listing continues");
        answers.push(rendered_units(&continued));
        cursor = continued.next_page();
    }
    assert!(
        cursor.is_none(),
        "the listing's cursors exhaust inside one page per project"
    );

    for mode in [MatchMode::Exact, MatchMode::Prefix, MatchMode::Contains] {
        let found = state
            .search_symbols(&search("Job", mode), &first_page())
            .expect("the search answers");
        answers.extend(
            found
                .result()
                .iter()
                .map(|structure| structure.qualified_name().to_owned()),
        );
    }

    // One hand-built handle, taken once. The read at position zero depends on
    // nothing about any file, so asking it inside the loop below re-read the
    // same structure per admitted source and pushed the same string eight
    // times — count the sweep grew by without a distinct answer behind it.
    let handle = StructureHandle::new(state.index().revision(), 0);
    answers.push(
        state
            .read_structure(handle)
            .expect("position zero reads")
            .result()
            .structure()
            .path()
            .to_owned(),
    );

    for record in state.index().files() {
        let outline = state
            .outline_file(record.path())
            .expect("every admitted source outlines");
        for structure in outline.result().structures() {
            let read = state
                .read_structure(structure.handle())
                .expect("every outlined structure reads");
            answers.push(read.result().text().to_owned());

            let span = structure.span();
            let column = column_of(record.text(), span.start_byte() as usize);
            let point = state
                .structure_at(record.path(), span.start_line(), Some(column))
                .expect("every structure's first byte names a structure");
            answers.push(point.result().structure().qualified_name().to_owned());
        }
    }

    answers.into_boxed_slice()
}

/// Every unit one page of the listing states.
fn rendered_units(listed: &NavigationResponse<Box<[ProjectRecord]>>) -> String {
    listed
        .result()
        .iter()
        .map(|project| project.unit())
        .collect::<Box<[&str]>>()
        .join(",")
}
