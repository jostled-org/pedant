//! 9.T2: the spawned CLI answers every graph question exactly.
//!
//! The three graph commands require an explicit edge selection, because which
//! relations answer a question is policy rather than topology. `path` also
//! states no depth at all: a route is as long as the topology makes it, and a
//! depth option would be a bound on an answer nobody can size in advance.

use crate::command::Output;
use crate::failure::Failure;
use crate::journeys::envelopes;
use crate::journeys::fixture::{
    Fixture, PYTHON_BUILD, RUST_BINARY_UNIT, RUST_LIBRARY_UNIT, RUST_MAIN, RUST_MAKE,
};
use crate::journeys::outcome::{
    assert_answer, assert_one_text_row_per, assert_states_something, assert_usage_error, refusal,
    rendered, run,
};
use pedant_snippet::{
    AnalysisLimitRequest, AnalysisMode, AnalysisQuery, EdgeCertainty, EdgeKind, EdgeSelection,
    PageRequest, PathQuery, ProjectHandle, RelationDirection, RelationQuery, StructureHandle,
};

/// Every run this journey makes, collected before any assertion.
struct Journey {
    /// The runs the index answers.
    answered: Answered,
    /// The runs it refuses, and the command lines clap never admits.
    refused: Refused,
}

/// Every graph question this journey asks and the index answers.
struct Answered {
    relations: Output,
    relations_text: Output,
    analysis: Output,
    path: Output,
}

/// Every run this journey expects to be refused.
///
/// The first is a typed refusal the index states; the other three are command
/// lines clap rejects, so no index is ever built for them.
struct Refused {
    unavailable: Output,
    no_edge_kind: Output,
    no_certainty: Output,
    path_depth: Output,
}

#[tokio::test]
async fn code_intelligence_cli_graph_journey_is_exact() {
    let fixture = Fixture::new();
    let journey = journey(&fixture)
        .await
        .unwrap_or_else(|failure| panic!("every graph run completes: {failure}"));

    assert_answers_match_the_library(&fixture, &journey.answered);
    assert_every_compared_answer_states_something(&journey.answered);
    assert_the_analysis_states_its_wire_shape(&journey.answered);
    assert_the_text_projection_covers_every_neighborhood(&journey.answered);
    assert_unavailable_coverage_is_typed(&journey.refused);
    assert_a_selection_is_required(&journey.refused);
    assert_path_states_no_depth(&journey.refused);
}

/// Run every case, collecting each output before anything is asserted.
async fn journey(fixture: &Fixture) -> Result<Journey, Failure> {
    Ok(Journey {
        answered: answered(fixture).await?,
        refused: refused(fixture).await?,
    })
}

/// Run every question the index answers.
async fn answered(fixture: &Fixture) -> Result<Answered, Failure> {
    let root = fixture.root();
    let revision = fixture.revision_text();
    let make = fixture.structure(RUST_MAKE).to_string();
    let main = fixture.structure(RUST_MAIN).to_string();
    let library = fixture.project(RUST_LIBRARY_UNIT).to_string();
    let binary = fixture.project(RUST_BINARY_UNIT).to_string();

    Ok(Answered {
        relations: run(
            root,
            &relations_selection(&revision, &make, &library),
            "the relation query",
        )
        .await?,
        relations_text: run(
            root,
            &[
                relations_selection(&revision, &make, &library).as_slice(),
                &["--format", "text"],
            ]
            .concat(),
            "the relation query rendered as text",
        )
        .await?,
        analysis: run(
            root,
            &[
                "graph",
                &revision,
                &library,
                "degree_centrality",
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
            ],
            "the degree-centrality analysis",
        )
        .await?,
        path: run(
            root,
            &[
                "path",
                &revision,
                &main,
                &revision,
                &make,
                "--project-id",
                &binary,
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
            ],
            "the path query",
        )
        .await?,
    })
}

/// The one `relations` question this journey asks, spelled once.
///
/// The journey asks it twice — as JSON and as the text projection of the same
/// answer — and the only thing comparing those two proves is that one question
/// was rendered two ways. Two hand-written copies of a thirteen-token selection
/// were two chances for a flag to move on one side, at which point the
/// comparison holds over two different questions and reports success.
///
/// The format flag is appended by the caller that wants it rather than taken as
/// a parameter, because the default rendering states no format at all and a
/// selection carrying an empty one would no longer be the command line an
/// operator types.
fn relations_selection<'run>(
    revision: &'run str,
    seed: &'run str,
    project: &'run str,
) -> [&'run str; 13] {
    [
        "relations",
        revision,
        seed,
        "--project-id",
        project,
        "--direction",
        "both",
        "--edge-kind",
        "call",
        "--certainty",
        "resolved",
        "--max-depth",
        "3",
    ]
}

/// Run every case this journey expects to be refused.
async fn refused(fixture: &Fixture) -> Result<Refused, Failure> {
    let root = fixture.root();
    let revision = fixture.revision_text();
    let make = fixture.structure(RUST_MAKE).to_string();
    let main = fixture.structure(RUST_MAIN).to_string();
    let python = fixture.structure(PYTHON_BUILD).to_string();

    Ok(Refused {
        unavailable: run(
            root,
            &[
                "relations",
                &revision,
                &python,
                "--direction",
                "outgoing",
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
                "--max-depth",
                "1",
            ],
            "a declaration no resolver covers",
        )
        .await?,
        no_edge_kind: run(
            root,
            &[
                "relations",
                &revision,
                &make,
                "--direction",
                "both",
                "--certainty",
                "resolved",
                "--max-depth",
                "1",
            ],
            "a relation query naming no edge kind",
        )
        .await?,
        no_certainty: run(
            root,
            &[
                "relations",
                &revision,
                &make,
                "--direction",
                "both",
                "--edge-kind",
                "call",
                "--max-depth",
                "1",
            ],
            "a relation query naming no certainty",
        )
        .await?,
        path_depth: run(
            root,
            &[
                "path",
                &revision,
                &main,
                &revision,
                &make,
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
                "--max-depth",
                "3",
            ],
            "a path query bounded by a depth",
        )
        .await?,
    })
}

/// The edge selection every case in this journey states.
fn edges() -> EdgeSelection {
    EdgeSelection {
        kinds: Box::new([EdgeKind::Call]),
        certainties: Box::new([EdgeCertainty::Resolved]),
    }
}

/// Every JSON answer is the library's own answer to the same question.
fn assert_answers_match_the_library(fixture: &Fixture, journey: &Answered) {
    let state = fixture.state();
    let revision = fixture.revision();
    let library = ProjectHandle::new(revision, fixture.project(RUST_LIBRARY_UNIT));
    let binary = ProjectHandle::new(revision, fixture.project(RUST_BINARY_UNIT));
    let make = StructureHandle::new(revision, fixture.structure(RUST_MAKE));
    let main = StructureHandle::new(revision, fixture.structure(RUST_MAIN));

    let relations = RelationQuery {
        structure: make,
        project: Some(library),
        direction: RelationDirection::Both,
        edges: edges(),
        max_depth: 3,
    };
    assert_answer(
        &journey.relations,
        &rendered(
            &state
                .query_relations(&relations, &PageRequest::default())
                .expect("the library answers the relation query"),
        ),
        "relations prints the library's neighborhoods",
    );

    let analysis = AnalysisQuery {
        project: library,
        edges: edges(),
        mode: AnalysisMode::DegreeCentrality,
        limits: AnalysisLimitRequest::default(),
    };
    assert_answer(
        &journey.analysis,
        &rendered(
            &state
                .analyze_graph(&analysis)
                .expect("the library answers the analysis query"),
        ),
        "graph prints the library's derived answer",
    );

    let path = PathQuery {
        from: main,
        to: make,
        project: Some(binary),
        edges: edges(),
    };
    assert_answer(
        &journey.path,
        &rendered(
            &state
                .find_path(&path)
                .expect("the library answers the path query"),
        ),
        "path prints the library's selected route",
    );
}

/// Every answer compared against the library states something.
///
/// The expectations above are the library's own answers to the same questions,
/// taken from the same repository the CLI was pointed at — so two empty answers
/// agree exactly and prove nothing about either. These guards are what make the
/// agreement evidence: a fixture that stopped stating a neighborhood, a measured
/// entity, or a route fails here rather than passing three rows over nothing.
///
/// The rows are this journey's; the predicate is
/// [`crate::journeys::outcome::assert_states_something`], which the navigation
/// journey supplies its own rows to. Two spellings of one guard had already
/// drifted — only one of them held the single-record case to anything.
fn assert_every_compared_answer_states_something(journey: &Answered) {
    for (output, pointer, claim) in [
        (
            &journey.relations,
            "/result",
            "the fixture states neighborhoods to compare",
        ),
        (
            &journey.analysis,
            "/result/answer",
            "and measured entities to compare",
        ),
        (
            &journey.path,
            "/result/selected",
            "and a selected route to compare",
        ),
    ] {
        assert_states_something(output, pointer, claim);
    }
}

/// The analysis answer states the wire shape written down for its mode.
///
/// The expectations above are the library's own answers, so a renamed serde
/// field renames it on both sides and every row still agrees. The shape is the
/// claim about the bytes, and this is the mode that needs one of its own:
/// [`crate::journeys::parity`] pins `components`, and an adjacently tagged union
/// is exactly where a wire shape can move for one variant and no other.
fn assert_the_analysis_states_its_wire_shape(journey: &Answered) {
    envelopes::assert_states_shape(
        &journey.analysis.stdout,
        &envelopes::degree_centrality(),
        "the degree-centrality answer",
    );
}

/// The text projection prints one row per neighborhood the JSON answer states.
fn assert_the_text_projection_covers_every_neighborhood(journey: &Answered) {
    drop(assert_one_text_row_per(
        &journey.relations,
        &journey.relations_text,
        "/result",
        "relations --format text prints one row per neighborhood",
    ));
}

/// A declaration no resolver covers refuses honestly rather than answering
/// empty.
fn assert_unavailable_coverage_is_typed(journey: &Refused) {
    let refused = refusal(&journey.unavailable, "a syntax-only declaration");
    assert_eq!(
        refused["error"]["code"],
        serde_json::json!("unavailable_coverage"),
        "absence of evidence is stated, not rendered as evidence of absence: {refused}"
    );
}

/// Neither half of an edge selection has a default.
fn assert_a_selection_is_required(journey: &Refused) {
    for (output, flag) in [
        (&journey.no_edge_kind, "--edge-kind"),
        (&journey.no_certainty, "--certainty"),
    ] {
        assert_usage_error(output, "an omitted edge selection", flag);
    }
}

/// `path` accepts no depth option at all.
fn assert_path_states_no_depth(journey: &Refused) {
    assert_usage_error(
        &journey.path_depth,
        "a route bounded by the topology alone",
        "--max-depth",
    );
}
