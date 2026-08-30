//! 9.T4: for every operation, the CLI and the MCP server send the same bytes.
//!
//! One case table, read twice. Each row spells one question two ways — as a
//! command line and as a tool call — and both are asked of the same immutable
//! fixture under the same revision, so an answer that differed would be a
//! renderer one transport has and the other does not.
//!
//! Parity is asserted on the bytes rather than on parsed values. Two renderings
//! that agree after parsing can still differ in field order, in a number's
//! spelling, or in whether an absent cursor is `null` or missing, and a client
//! reading either transport has to see one shape.
//!
//! Every row also states where its answer must hold something. Two renderings
//! of an empty result are the same bytes under any pair of renderers, and an
//! array shape requires no row — so a question nothing matches compares nothing
//! and checks no shape, in the one journey five of those array shapes are read.

use serde_json::{Value, json};

use crate::child::Server;
use crate::command::Output;
use crate::failure::Failure;
use crate::journeys::client;
use crate::journeys::envelopes;
use crate::journeys::fixture::{
    Fixture, GO_NEW, PYTHON_BUILD, RUST_BINARY_UNIT, RUST_LIBRARY_UNIT, RUST_MAIN, RUST_MAKE,
    root_arguments,
};
use crate::journeys::outcome::{
    assert_answer_states_something, assert_answered, assert_clean, assert_refused, run,
};

/// The wire shape one operation's answer is held to.
///
/// A function rather than a value, because a shape document is composed from
/// the fields it shares with its siblings and a table of eight built values
/// would build all eight for every row that reads one.
type Shape = fn() -> Value;

/// One question, spelled for both transports.
struct Case {
    /// What this row proves, for assertion messages.
    label: &'static str,
    /// The command line, with every identity already substituted.
    arguments: Box<[Box<str>]>,
    /// The tool one call names.
    tool: &'static str,
    /// The arguments that call supplies.
    parameters: Value,
    /// Whether the index answers this question or refuses it.
    answered: bool,
    /// The written-down wire shape both renderings are held to.
    shape: Shape,
    /// Where in that rendering this row must state something.
    ///
    /// Two renderings of nothing agree exactly, and an array shape holds no
    /// rows to the descriptor written down for them. One row already asked a
    /// question nothing matched: a Go `Job` is a `struct`, and the filtered
    /// search asked for a `defined_type`.
    states: &'static str,
}

/// What one row produced on both transports.
///
/// Both renderings arrive whole rather than already reduced to the bytes that
/// will be compared. Deciding which stream carries the answer means asserting
/// the run answered, and the assertion phase is after the teardown: a claim made
/// while the child is live unwinds past [`crate::child::Server::shutdown`] and
/// discards the server's own log.
struct Compared {
    /// The row that asked.
    label: &'static str,
    /// The tool that row named, carried so the table can be held against the
    /// registry's own served list rather than against a second copy of it.
    tool: &'static str,
    /// Whether the row expects an answer.
    answered: bool,
    /// The written-down wire shape both renderings are held to.
    shape: Shape,
    /// Where in that rendering this row must state something.
    states: &'static str,
    /// What the CLI run printed, and how it exited.
    printed: Output,
    /// The whole reply the tool call carried back.
    sent: Value,
}

#[tokio::test]
async fn code_intelligence_stdio_navigation_and_graph_journey_matches_cli() {
    let fixture = Fixture::new();
    let cases = cases(&fixture);
    let (compared, termination) = client::session(
        &root_arguments(&fixture),
        "the parity journey",
        async |server| journey(server, &fixture, &cases).await,
    )
    .await;
    assert_clean(&termination, "the parity session");

    crate::cases::assert_every_row_ran(&compared, &cases, "the parity table");
    for row in &*compared {
        assert_both_transports_send_one_answer(row);
    }
    assert_the_table_covers_both_outcomes(&compared);
}

/// One row's two renderings are the same bytes, in the shape written down.
///
/// The whole outcome is asserted here rather than in the loop that ran it:
/// which stream carries the answer is decided by whether the run answered, and
/// that is a claim, so it waits for the teardown like every other.
fn assert_both_transports_send_one_answer(row: &Compared) {
    let (printed, content) = match row.answered {
        true => {
            assert_answered(&row.printed, row.label);
            (&*row.printed.stdout, client::answered(&row.sent, row.label))
        }
        false => {
            assert_refused(&row.printed, row.label);
            (&*row.printed.stderr, client::refused(&row.sent, row.label))
        }
    };
    // The CLI writes an answer to stdout and a refusal to stderr, and both carry
    // one trailing newline. The tool content carries neither, so the comparison
    // is over the envelope itself.
    let printed = printed.trim_end_matches('\n');
    assert_eq!(
        printed, content,
        "{}: both transports send the same bytes",
        row.label
    );
    envelopes::assert_states_shape(printed, &(row.shape)(), row.label);
    // And the bytes both transports agreed on say something. Equality between
    // two renderings of an empty result is satisfied by any pair of renderers,
    // and an array shape holds no rows to the descriptor written down for them,
    // so without this the row proves that two transports were both silent.
    assert_answer_states_something(&document(printed, row.label), row.states, row.label);
}

/// The one document both transports sent, parsed for the guard above.
fn document(printed: &str, label: &str) -> Value {
    serde_json::from_str(printed)
        .unwrap_or_else(|error| panic!("{label}: the sent bytes are one JSON document: {error}"))
}

/// The table states a refusal and an answer, so parity covers both outcomes.
///
/// Both halves, because one of them says nothing on its own: a table of
/// refusals proves that a refusal renders alike and nothing about an answer,
/// and a table of answers proves the reverse. The guard used to make only the
/// first half, so a table that lost every answered row was a claim about half
/// this product with nothing red.
fn assert_the_table_covers_both_outcomes(compared: &[Compared]) {
    assert!(
        compared.iter().any(|row| !row.answered),
        "the table states at least one typed refusal, so parity covers a refusal"
    );
    assert!(
        compared.iter().any(|row| row.answered),
        "and at least one answer, so it covers the other outcome too"
    );
    assert_the_table_covers_every_served_tool(compared);
}

/// Every tool the registry serves is asked at least one parity question.
///
/// Read from `mcp_registry`'s own list rather than restated here, because a
/// second copy is what lets the two disagree. Without this, a ninth operation
/// is forced into the registry's `REQUIRED` inventory by that root's own length
/// equality and ships with no parity coverage at all — a tool whose CLI and MCP
/// renderings are never compared, and nothing red to say so.
fn assert_the_table_covers_every_served_tool(compared: &[Compared]) {
    let mut asked: Vec<&str> = compared.iter().map(|row| row.tool).collect();
    asked.sort_unstable();
    asked.dedup();
    let mut served = super::mcp_registry::TOOLS;
    served.sort_unstable();
    assert_eq!(
        asked, served,
        "every served tool is asked a parity question, and no row names a tool the registry \
         does not serve"
    );
}

/// Every case in the table, spelled for the fixture's own identities.
///
/// One group per question family, because a family is what a reader checks for
/// completeness: every operation this product serves appears in exactly one of
/// them, and the refusals are their own group so a table that lost them is
/// visible rather than merely shorter.
///
/// Boxed once the groups are gathered, for the reason [`spelled`] boxes a row's
/// arguments: the table is built here and read through a slice after, and
/// nothing appends a case to it once the journey starts.
fn cases(fixture: &Fixture) -> Box<[Case]> {
    let mut cases = discovery_cases();
    cases.extend(structure_cases(fixture));
    cases.extend(traversal_cases(fixture));
    cases.extend(analysis_cases(fixture));
    cases.extend(refusal_cases(fixture));
    cases.into_boxed_slice()
}

/// The questions that find something without naming it first.
///
/// They take no identity from the fixture, which is the point: a caller who
/// knows nothing about a repository starts here.
fn discovery_cases() -> Vec<Case> {
    vec![
        Case {
            label: "list_projects",
            arguments: spelled(&["list-projects"]),
            tool: "list_projects",
            parameters: json!({}),
            answered: true,
            shape: envelopes::projects,
            states: "/result",
        },
        // The kind is the one the fixture's Go source declares. `type Job
        // struct` is a `struct`; `defined_type` is the kind Go gives a name
        // declared over an underlying type, which nothing here spells `Job`.
        // Asking for it matched no structure, so both transports rendered an
        // empty result and the row compared two silences.
        Case {
            label: "search_symbols with filters",
            arguments: spelled(&[
                "search",
                "Job",
                "--mode",
                "contains",
                "--language",
                "go",
                "--kind",
                "struct",
            ]),
            tool: "search_symbols",
            parameters: json!({
                "text": "Job", "mode": "contains", "language": "go", "kind": "struct"
            }),
            answered: true,
            shape: envelopes::symbols,
            states: "/result",
        },
        Case {
            label: "search_symbols first page",
            arguments: spelled(&["search", "e", "--mode", "contains", "--page-size", "3"]),
            tool: "search_symbols",
            parameters: json!({ "text": "e", "mode": "contains", "page_size": 3 }),
            answered: true,
            shape: envelopes::symbols,
            states: "/result",
        },
    ]
}

/// The questions that name a place and read the structure there.
fn structure_cases(fixture: &Fixture) -> Vec<Case> {
    let revision = fixture.revision_text();
    let make = fixture.structure(RUST_MAKE);
    let go = fixture.structure(GO_NEW);

    vec![
        Case {
            label: "outline_file",
            arguments: spelled(&["outline", "web/app.ts"]),
            tool: "outline_file",
            parameters: json!({ "path": "web/app.ts" }),
            answered: true,
            shape: envelopes::outline,
            states: "/result/structures",
        },
        Case {
            label: "read_structure",
            arguments: spelled(&["read", &revision, &make.to_string()]),
            tool: "read_structure",
            parameters: json!({ "revision": revision, "structure_id": make }),
            answered: true,
            shape: envelopes::source,
            states: "/result/structure",
        },
        Case {
            label: "structure_at",
            arguments: spelled(&["at", "scripts/tool.sh", "1", "--column", "2"]),
            tool: "structure_at",
            parameters: json!({ "path": "scripts/tool.sh", "line": 1, "column": 2 }),
            answered: true,
            shape: envelopes::point,
            states: "/result/structure",
        },
        Case {
            label: "read_structure over the Go module",
            arguments: spelled(&["read", &revision, &go.to_string()]),
            tool: "read_structure",
            parameters: json!({ "revision": revision, "structure_id": go }),
            answered: true,
            shape: envelopes::source,
            states: "/result/structure",
        },
    ]
}

/// The questions that walk edges from a declaration.
fn traversal_cases(fixture: &Fixture) -> Vec<Case> {
    let revision = fixture.revision_text();
    let make = fixture.structure(RUST_MAKE);
    let main = fixture.structure(RUST_MAIN);
    let library = fixture.project(RUST_LIBRARY_UNIT);
    let binary = fixture.project(RUST_BINARY_UNIT);

    vec![
        Case {
            label: "query_relations",
            arguments: spelled(&[
                "relations",
                &revision,
                &make.to_string(),
                "--project-id",
                &library.to_string(),
                "--direction",
                "both",
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
                "--max-depth",
                "2",
            ]),
            tool: "query_relations",
            parameters: json!({
                "revision": revision,
                "structure_id": make,
                "project_id": library,
                "direction": "both",
                "edge_kinds": ["call"],
                "certainties": ["resolved"],
                "max_depth": 2
            }),
            answered: true,
            shape: envelopes::relations,
            states: "/result",
        },
        Case {
            label: "find_path",
            arguments: spelled(&[
                "path",
                &revision,
                &main.to_string(),
                &revision,
                &make.to_string(),
                "--project-id",
                &binary.to_string(),
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
            ]),
            tool: "find_path",
            parameters: json!({
                "from_revision": revision,
                "from_id": main,
                "to_revision": revision,
                "to_id": make,
                "project_id": binary,
                "edge_kinds": ["call"],
                "certainties": ["resolved"]
            }),
            answered: true,
            shape: envelopes::path,
            states: "/result/selected",
        },
    ]
}

/// The question that derives one answer about a whole project graph.
fn analysis_cases(fixture: &Fixture) -> Vec<Case> {
    let revision = fixture.revision_text();
    let library = fixture.project(RUST_LIBRARY_UNIT);

    vec![Case {
        label: "analyze_graph",
        arguments: spelled(&[
            "graph",
            &revision,
            &library.to_string(),
            "components",
            "--edge-kind",
            "call",
            "--certainty",
            "resolved",
        ]),
        tool: "analyze_graph",
        parameters: json!({
            "project_revision": revision,
            "project_id": library,
            "mode": "components",
            "edge_kinds": ["call"],
            "certainties": ["resolved"]
        }),
        answered: true,
        shape: envelopes::components,
        states: "/result/answer",
    }]
}

/// The questions the index refuses, so parity covers both outcomes.
fn refusal_cases(fixture: &Fixture) -> Vec<Case> {
    let revision = fixture.revision_text();
    let python = fixture.structure(PYTHON_BUILD);

    vec![
        Case {
            label: "a typed refusal about an unadmitted path",
            arguments: spelled(&["outline", "nowhere.rs"]),
            tool: "outline_file",
            parameters: json!({ "path": "nowhere.rs" }),
            answered: false,
            shape: envelopes::refusal,
            states: "/error",
        },
        Case {
            label: "a typed refusal about coverage the build states no evidence for",
            arguments: spelled(&[
                "relations",
                &revision,
                &python.to_string(),
                "--direction",
                "outgoing",
                "--edge-kind",
                "call",
                "--certainty",
                "resolved",
                "--max-depth",
                "1",
            ]),
            tool: "query_relations",
            parameters: json!({
                "revision": revision,
                "structure_id": python,
                "direction": "outgoing",
                "edge_kinds": ["call"],
                "certainties": ["resolved"],
                "max_depth": 1
            }),
            answered: false,
            shape: envelopes::refusal,
            states: "/error",
        },
    ]
}

/// One command line, owned so the identities substituted into it outlive it.
///
/// Boxed rather than a `Vec`: a row is spelled once at table construction and
/// nothing appends to it after.
fn spelled(arguments: &[&str]) -> Box<[Box<str>]> {
    arguments.iter().map(|part| Box::from(*part)).collect()
}

/// Run every case on both transports, collecting both renderings.
///
/// The collected rows are boxed for the reason the table is: one row per case,
/// pushed as each case runs, and read through a slice once every case has.
async fn journey(
    server: &mut Server,
    fixture: &Fixture,
    cases: &[Case],
) -> Result<Box<[Compared]>, Failure> {
    client::initialized(server).await?;
    let mut compared = Vec::with_capacity(cases.len());
    for (index, case) in cases.iter().enumerate() {
        let arguments: Vec<&str> = case.arguments.iter().map(|part| &**part).collect();
        let printed = run(fixture.root(), &arguments, case.label).await?;
        let identifier = i64::try_from(index).unwrap_or(i64::MAX).saturating_add(2);
        let sent = client::called(server, identifier, case.tool, &case.parameters).await?;
        compared.push(Compared {
            label: case.label,
            tool: case.tool,
            answered: case.answered,
            shape: case.shape,
            states: case.states,
            printed,
            sent,
        });
    }
    Ok(compared.into_boxed_slice())
}
