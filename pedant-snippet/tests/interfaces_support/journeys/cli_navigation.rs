//! 9.T1: the spawned CLI answers every navigation question exactly.
//!
//! Every expectation is the library's own answer to the same question, taken in
//! this process from the same repository. The journey therefore states no
//! outcome of its own: it proves the binary prints what the library returns,
//! byte for byte, and exits as the contract says.
//!
//! What the same binary *serves* — its command tree, and the names it answers
//! to — is [`crate::journeys::cli_inventory`], whose runs this journey collects
//! beside its own so one spawned journey states both.

use crate::command::Output;
use crate::failure::Failure;
use crate::index::fixture::Repository;
use crate::journeys::cli_inventory::{self, Inventory};
use crate::journeys::envelopes;
use crate::journeys::fixture::{Fixture, RUST_MAKE};
use crate::journeys::outcome::{
    assert_answer, assert_one_text_row_per, assert_states_something, assert_usage_error, refusal,
    rendered, run as at_root, value,
};
use pedant_snippet::{MatchMode, PageRequest, SymbolQuery};

/// One command line clap must refuse, and a fragment its refusal names.
struct Refusal {
    /// What this case proves, for assertion messages.
    label: &'static str,
    /// The arguments, exactly as a caller would spell them.
    arguments: &'static [&'static str],
    /// Text the refusal carries, so a run that exits 2 for another reason fails.
    reason: &'static str,
}

/// Every malformed command line, refused before any file is opened.
static REFUSALS: [Refusal; 4] = [
    Refusal {
        label: "a subcommand this binary does not serve",
        arguments: &["frobnicate"],
        reason: "frobnicate",
    },
    Refusal {
        label: "a search with no explicit match mode",
        arguments: &["search", "make"],
        reason: "--mode",
    },
    Refusal {
        label: "a match mode this vocabulary does not name",
        arguments: &["search", "make", "--mode", "fuzzy"],
        reason: "fuzzy",
    },
    Refusal {
        label: "a non-numeric line",
        arguments: &["at", "scripts/tool.py", "four"],
        reason: "four",
    },
];

/// One refused command line, kept beside the case that asked for it.
///
/// Paired rather than positional: an assertion that zipped the table against a
/// separate list would report the wrong case's label the moment one run is
/// added and the other list is not.
struct Refused {
    /// The case this run states.
    case: &'static Refusal,
    /// What the run printed and how it exited.
    output: Output,
}

/// Every run this journey makes, collected before any assertion.
struct Journey {
    inventory: Inventory,
    projects: Output,
    projects_text: Output,
    search: Output,
    filtered: Output,
    empty: Output,
    first_page: Output,
    outline: Output,
    read_text: Output,
    at: Output,
    unknown_file: Output,
    invalid_root: Output,
    degraded: Output,
    refusals: Box<[Refused]>,
}

#[tokio::test]
async fn code_intelligence_cli_navigation_journey_is_exact() {
    let fixture = Fixture::new();
    let degraded = degraded_repository();
    let journey = journey(&fixture, &degraded)
        .await
        .unwrap_or_else(|failure| panic!("every CLI run completes: {failure}"));

    cli_inventory::assert_the_inventory_is_exactly_the_nine(&journey.inventory);
    assert_json_matches_library(&fixture, &journey);
    assert_every_compared_answer_states_something(&journey);
    assert_text_projects_the_same_answer(&fixture, &journey);
    assert_paging_and_emptiness(&journey);
    assert_refusals_are_typed_and_exit_two(&fixture, &journey);
    assert_degraded_answers_and_exits_zero(&journey);
    assert_clap_refusals(&journey.refusals);
}

/// A repository whose one Python source cannot be decoded.
///
/// Its own tree rather than the shared fixture's: a degraded file changes the
/// index revision, and every other row of this journey is stated against the
/// revision the shared fixture published.
fn degraded_repository() -> Repository {
    let repository = Repository::of(&[("scripts/tool.py", "def build():\n    return 1\n")]);
    repository.write_bytes("scripts/broken.py", &[0xff, 0xfe, b'\n']);
    repository
}

/// Run every case, collecting each output before anything is asserted.
async fn journey(fixture: &Fixture, degraded: &Repository) -> Result<Journey, Failure> {
    let root = fixture.root();
    let revision = fixture.revision_text();
    let structure = fixture.structure(RUST_MAKE).to_string();
    let degraded_root = degraded
        .root()
        .to_str()
        .expect("the degraded root has a UTF-8 spelling")
        .to_owned();

    let mut refusals = Vec::with_capacity(REFUSALS.len());
    for case in &REFUSALS {
        let output = at_root(root, case.arguments, case.label).await?;
        refusals.push(Refused { case, output });
    }

    Ok(Journey {
        inventory: cli_inventory::inventory(root).await?,
        projects: at_root(root, &["list-projects"], "the project list").await?,
        projects_text: at_root(
            root,
            &["list-projects", "--format", "text"],
            "the project list rendered as text",
        )
        .await?,
        search: at_root(
            root,
            &["search", "make", "--mode", "exact"],
            "the exact search",
        )
        .await?,
        filtered: at_root(
            root,
            &["search", "Job", "--mode", "contains", "--language", "go"],
            "the filtered search",
        )
        .await?,
        empty: at_root(
            root,
            &["search", "nothing-declares-this", "--mode", "exact"],
            "a search nothing matches",
        )
        .await?,
        first_page: at_root(
            root,
            &["search", "e", "--mode", "contains", "--page-size", "2"],
            "the first page of a search",
        )
        .await?,
        outline: at_root(root, &["outline", "crate-a/src/lib.rs"], "the outline").await?,
        read_text: at_root(
            root,
            &["read", &revision, &structure, "--format", "text"],
            "one structure rendered as text",
        )
        .await?,
        at: at_root(root, &["at", "scripts/tool.py", "4"], "the point lookup").await?,
        unknown_file: at_root(root, &["outline", "nowhere.rs"], "an unadmitted path").await?,
        invalid_root: at_root(
            &format!("{root}/nowhere"),
            &["list-projects"],
            "a root that is not a directory",
        )
        .await?,
        degraded: at_root(&degraded_root, &["list-projects"], "a degraded repository").await?,
        refusals: refusals.into_boxed_slice(),
    })
}

/// Every JSON answer is the library's own answer to the same question.
fn assert_json_matches_library(fixture: &Fixture, journey: &Journey) {
    let state = fixture.state();
    let whole = PageRequest::default();

    assert_answer(
        &journey.projects,
        &rendered(&state.list_projects(&whole).expect("projects list")),
        "list-projects prints the library's project list",
    );
    assert_answer(
        &journey.search,
        &rendered(
            &state
                .search_symbols(&query("make", MatchMode::Exact, None), &whole)
                .expect("exact search"),
        ),
        "search prints the library's exact match set",
    );
    assert_answer(
        &journey.filtered,
        &rendered(
            &state
                .search_symbols(
                    &query("Job", MatchMode::Contains, Some(pedant_types::Language::Go)),
                    &whole,
                )
                .expect("filtered search"),
        ),
        "a language filter reaches the library unchanged",
    );
    assert_answer(
        &journey.outline,
        &rendered(
            &state
                .outline_file("crate-a/src/lib.rs")
                .expect("the Rust outline"),
        ),
        "outline prints the library's whole forest",
    );
    assert_answer(
        &journey.at,
        &rendered(
            &state
                .structure_at("scripts/tool.py", 4, None)
                .expect("the Python point"),
        ),
        "at prints the library's narrowest containing structure",
    );
}

/// Every answer compared against the library states something.
///
/// The expectations above are the library's own answers to the same questions,
/// taken in this process from the repository the CLI was pointed at — so two
/// empty renderings agree exactly and prove nothing about either. A fixture that
/// stopped declaring `make` or `Job`, or a `crate-a/src/lib.rs` that stopped
/// declaring anything, would leave four rows comparing nothing and still pass.
/// The fifth compared answer, `list-projects`, is guarded where its rows are
/// counted.
fn assert_every_compared_answer_states_something(journey: &Journey) {
    for (output, pointer, claim) in [
        (
            &journey.search,
            "/result",
            "the fixture declares the name an exact search states",
        ),
        (
            &journey.filtered,
            "/result",
            "and a name the language filter narrows to",
        ),
        (
            &journey.outline,
            "/result/structures",
            "and a Rust source with a forest to outline",
        ),
        (
            &journey.at,
            "/result/structure",
            "and a declaration containing the point the row names",
        ),
    ] {
        assert_states_something(output, pointer, claim);
    }
}

/// The text projection states the same answer the JSON one does.
fn assert_text_projects_the_same_answer(fixture: &Fixture, journey: &Journey) {
    let projected = assert_one_text_row_per(
        &journey.projects,
        &journey.projects_text,
        "/result",
        "list-projects --format text prints one row per project",
    );
    for (row, project) in &*projected {
        let authority = project["authority"]
            .as_str()
            .unwrap_or_else(|| panic!("a project states its authority: {project}"));
        assert!(
            row.contains(authority),
            "the row for {project} names its authority: {row}"
        );
    }

    // A structure's text projection is its exact bytes and nothing else, which
    // is the one projection a caller may pipe into a file.
    let expected = fixture
        .state()
        .read_structure(pedant_snippet::StructureHandle::new(
            fixture.revision(),
            fixture.structure(RUST_MAKE),
        ))
        .expect("the retained structure")
        .into_result();
    assert_eq!(
        &*journey.read_text.stdout,
        expected.text(),
        "read --format text prints the structure's exact bytes, with nothing added"
    );
}

/// An empty match set is a successful answer, and a page states its cursor.
fn assert_paging_and_emptiness(journey: &Journey) {
    let empty = value(&journey.empty, "an empty search");
    assert_eq!(
        empty["result"],
        serde_json::json!([]),
        "a query nothing matches is a successful empty result: {empty}"
    );
    assert!(
        journey.empty.status.success(),
        "and it exits zero: {:?}",
        journey.empty.status
    );

    let page = value(&journey.first_page, "the first page");
    let items = page["result"]
        .as_array()
        .unwrap_or_else(|| panic!("a page is an array: {page}"));
    assert_eq!(items.len(), 2, "the page carries the stated size: {page}");
    assert!(
        page["next_page"].is_string(),
        "and states the cursor that continues it: {page}"
    );
}

/// Every typed refusal writes its envelope to stderr and exits two.
fn assert_refusals_are_typed_and_exit_two(fixture: &Fixture, journey: &Journey) {
    let refused = refusal(&journey.unknown_file, "a path the index never admitted");
    assert_eq!(
        refused["error"]["code"],
        serde_json::json!("unknown_file"),
        "a query refusal states its code: {refused}"
    );
    assert_eq!(
        refused["index_revision"],
        serde_json::json!(fixture.revision_text()),
        "and the index it was refused from: {refused}"
    );

    let fatal = refusal(&journey.invalid_root, "a root that is not a directory");
    assert_eq!(
        fatal["error"]["code"],
        serde_json::json!("invalid_root"),
        "a fatal refusal states its code: {fatal}"
    );
    assert!(
        fatal["index_revision"].is_null(),
        "and no revision, because no index was published: {fatal}"
    );
    // The one envelope with no state behind it, so it is the one response type
    // whose written-down shape carries neither revision nor health.
    envelopes::assert_states_shape(
        &journey.invalid_root.stderr,
        &envelopes::fatal_refusal(),
        "a root that is not a directory",
    );
}

/// A degraded index answers and exits zero, because the answer states the issue.
fn assert_degraded_answers_and_exits_zero(journey: &Journey) {
    let answered = value(&journey.degraded, "a degraded repository");
    assert!(
        journey.degraded.status.success(),
        "a degraded index still answers: {:?}: {}",
        journey.degraded.status,
        journey.degraded.stderr
    );
    assert_eq!(
        answered["health"]["status"],
        serde_json::json!("degraded"),
        "and the response says so: {answered}"
    );
}

/// Every malformed command line exits two, prints no result, and says why.
fn assert_clap_refusals(refusals: &[Refused]) {
    crate::cases::assert_every_row_ran(refusals, &REFUSALS, "the clap refusal table");
    for refused in refusals {
        assert_usage_error(&refused.output, refused.case.label, refused.case.reason);
    }
}

/// One search with an optional language filter.
fn query(text: &str, mode: MatchMode, language: Option<pedant_types::Language>) -> SymbolQuery {
    SymbolQuery {
        text: Box::from(text),
        mode,
        language,
        kind: None,
        owner_name: None,
        path_prefix: None,
    }
}
