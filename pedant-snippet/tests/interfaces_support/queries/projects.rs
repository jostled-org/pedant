//! Every project one index resolved, as the public listing states it.

use super::paging::{
    Paged, Revisions, a_default_cursor_continues_at_fifty, paged_contract_holds, whole_result,
};
use super::support::{
    LISTING_LABEL, degraded_mixed, first_page, mixed, projects_page, search, symbols_page,
    the_envelope_round_trips,
};
use crate::index::fixture::Repository;
use crate::index::harness::indexed;
use crate::index::sources::{GO_MAIN_MODULE, GO_MODULES, KEPT, RUST_PACKAGE};
use pedant_snippet::{
    CodeIntelligenceState, HealthStatus, MatchMode, NavigationResponse, PageRequest, ProjectRecord,
    StructureCoverage,
};

/// Every project record, in project-key order, with its own page contract.
#[test]
fn list_projects_returns_complete_revision_bound_project_records() {
    let (_repository, state) = mixed();

    every_resolved_project_states_its_own_record(&state);
    an_index_with_no_project_states_an_empty_success();
    a_sibling_unit_refusal_reaches_the_project_record();

    // Two Go modules and no Rust, so the listing there is another index's and
    // still long enough for a page of one to leave a continuation.
    let modules = Repository::of(GO_MODULES);
    let elsewhere = indexed(&modules);
    let (_degraded_tree, degraded) = degraded_mixed();
    let symbol_query = search("", MatchMode::Contains);

    paged_contract_holds(&Paged {
        label: LISTING_LABEL,
        call: |request| projects_page(&state, request),
        revisions: Revisions::of(&state),
        other: |request| symbols_page(&state, &symbol_query, request),
        elsewhere: |request| projects_page(&elsewhere, request),
        elsewhere_revisions: Revisions::of(&elsewhere),
        degraded: |request| projects_page(&degraded, request),
        degraded_revisions: Revisions::of(&degraded),
        // Four projects, which one default page holds whole. The shared
        // contract therefore leaves the default-cursor continuation row untaken
        // here, and `a_default_page_of_projects_continues` below pays it over a
        // repository long enough to state it.
        outruns_default: false,
    });

    a_default_page_of_projects_continues(&crowded());
}

/// How many modules a repository needs before its listing outruns a default
/// page.
///
/// One project per Go module, and one more than the default page holds, so the
/// first page of the listing leaves a continuation to replay.
const MODULES_PAST_A_DEFAULT_PAGE: u32 = 51;

/// A repository stating more project authorities than one default page holds.
///
/// Go modules, because a Go authority is a file this fixture writes rather than
/// a package a resolver has to build. Every row of the shared contract above is
/// taken over the mixed repository, which resolves four projects — so that
/// fixture can never leave the listing a continuation, and the one row about
/// continuing under the default size is owed here or nowhere.
fn crowded() -> Repository {
    let repository = Repository::empty();
    for module in 0..MODULES_PAST_A_DEFAULT_PAGE {
        repository.write(
            &format!("m{module:03}/go.mod"),
            &format!("module example.com/m{module:03}\n\ngo 1.22\n"),
        );
        repository.write(
            &format!("m{module:03}/lib.go"),
            "package lib\n\nfunc Helper() {}\n",
        );
    }
    repository
}

/// A project cursor minted under the omitted default continues at an explicit
/// fifty.
fn a_default_page_of_projects_continues(repository: &Repository) {
    let state = indexed(repository);
    assert_eq!(
        state.index().projects().len(),
        MODULES_PAST_A_DEFAULT_PAGE as usize,
        "the crowded repository resolves one project per module it states"
    );
    let call = |request: &PageRequest| projects_page(&state, request);
    let whole = whole_result(LISTING_LABEL, &call);
    a_default_cursor_continues_at_fifty(LISTING_LABEL, &call, &whole);
}

/// One listed project, projected to the five fields the expectation states.
///
/// The two enums are rendered rather than compared as values, so a variant added
/// to either arrives here as a different string instead of as a new arm nothing
/// wrote. The two borrows are the record's own.
type StatedProject<'project> = (String, &'project str, &'project str, String, HealthStatus);

/// The listing states every project the index resolved, and states it exactly.
fn every_resolved_project_states_its_own_record(state: &CodeIntelligenceState) {
    let response = state
        .list_projects(&first_page())
        .expect("the mixed repository lists its projects");
    assert_eq!(response.index_revision(), state.index().revision());
    assert_eq!(response.state_revision(), state.revision());
    assert_eq!(response.health(), state.health());
    assert!(
        response.next_page().is_none(),
        "four projects fit in one default page"
    );

    let stated: Box<[StatedProject<'_>]> = response
        .result()
        .iter()
        .map(|project| {
            (
                format!("{:?}", project.language()),
                project.authority(),
                project.unit(),
                format!("{:?}", project.coverage()),
                project.health().status(),
            )
        })
        .collect();
    assert_eq!(
        &*stated,
        [
            (
                "Rust".to_owned(),
                "Cargo.toml",
                "crate-a::bin::crate-a",
                "Resolved".to_owned(),
                HealthStatus::Complete
            ),
            (
                "Rust".to_owned(),
                "Cargo.toml",
                "crate-a::lib::crate_a",
                "Resolved".to_owned(),
                HealthStatus::Complete
            ),
            (
                "Go".to_owned(),
                "go.mod",
                "example.com/main",
                "Resolved".to_owned(),
                HealthStatus::Complete
            ),
            (
                "Go".to_owned(),
                "nested/go.mod",
                "example.com/nested",
                "Resolved".to_owned(),
                HealthStatus::Complete
            ),
        ],
        "each project states its language, authority, unit, graph tier, and health, in key order"
    );

    every_record_selects_the_slice_it_describes(state, &response);
    the_envelope_round_trips(&response);
}

/// The handle each record carries selects the slice that record describes.
///
/// The graph tier is compared here as well as in the closed table above,
/// because the table cannot tell a record that read its slice from one that
/// wrote a constant: both slice producers state `Resolved`, so every project
/// this step can build states the same tier. The tiers a project can state
/// otherwise are 7.T5's, which is the step that produces a slice with less than
/// a resolved graph behind it. `StructureCoverage`'s other values are already
/// discriminated at this layer by 6.T1, whose outline states `SyntaxOnly` for
/// every loose source and `Resolved` for every project member.
fn every_record_selects_the_slice_it_describes(
    state: &CodeIntelligenceState,
    response: &NavigationResponse<Box<[ProjectRecord]>>,
) {
    for (position, project) in response.result().iter().enumerate() {
        let slice = state
            .index()
            .project(project.handle())
            .expect("the handle a listing states selects its slice");
        assert_eq!(
            slice.key().unit(),
            project.unit(),
            "record {position} carries the handle of the slice it describes"
        );
        assert_eq!(
            slice.coverage(),
            project.coverage(),
            "record {position} states the graph tier its own slice carries"
        );
    }
}

/// A repository with no project authority states no project and succeeds.
fn an_index_with_no_project_states_an_empty_success() {
    let loose = indexed(&Repository::of(&[KEPT]));
    let response = loose
        .list_projects(&first_page())
        .expect("a repository with no project still answers");
    assert!(response.result().is_empty(), "and states no project");
    assert!(response.next_page().is_none(), "with no continuation");
    assert_eq!(response.health().status(), HealthStatus::Complete);
}

/// A project whose sibling unit refused is listed with the health that says so.
///
/// One authority, two units: the library resolves and the binary does not, so
/// the slice that answered is still listed and the authority it was selected by
/// carries the refusal. A second, untouched authority is listed beside it,
/// because that is the only shape in which a record's own health can be told
/// from the index's: with one project, a whole-index health and an authority
/// health agree, and the row would hold whichever one production read.
fn a_sibling_unit_refusal_reaches_the_project_record() {
    let repository = Repository::of(RUST_PACKAGE);
    repository.write("src/main.rs", "fn main( {\n");
    for (path, contents) in GO_MAIN_MODULE {
        repository.write(path, contents);
    }
    let state = indexed(&repository);
    let response = state
        .list_projects(&first_page())
        .expect("a degraded repository still lists what it resolved");

    let stated: Box<[(&str, &str, HealthStatus)]> = response
        .result()
        .iter()
        .map(|project| {
            (
                project.authority(),
                project.unit(),
                project.health().status(),
            )
        })
        .collect();
    assert_eq!(
        &*stated,
        [
            (
                "Cargo.toml",
                "crate-a::lib::crate_a",
                HealthStatus::Degraded
            ),
            ("go.mod", "example.com/main", HealthStatus::Complete),
        ],
        "the unit that resolved is listed under the health its own authority \
         carries, and the authority that refused nothing is complete in the \
         same degraded index"
    );
    assert!(
        response
            .result()
            .iter()
            .all(|project| project.coverage() == StructureCoverage::Resolved),
        "a listed project resolved a graph, or it would not be listed: a \
         degraded authority states its refusal in its health, not in a tier"
    );
    assert_eq!(
        response.health().status(),
        HealthStatus::Degraded,
        "and the response states that the index as a whole is degraded"
    );

    let clean = indexed(&Repository::of(RUST_PACKAGE));
    assert_eq!(
        clean
            .list_projects(&first_page())
            .expect("the clean repository lists its project")
            .result()
            .first()
            .expect("one project")
            .health()
            .status(),
        HealthStatus::Complete,
        "and an authority that refused nothing states a complete project"
    );
}
