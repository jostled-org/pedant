//! Out-of-process MCP journeys: real stdio framing, real tool dispatch, and
//! the completion receipt that binds a typed-query run to one tree.
//!
//! Every child here is owned by [`process_guard::Guard`]. A test collects what
//! it needs while the server is live, tears the tree down, and only then
//! asserts — an assertion that fired mid-conversation would unwind past the
//! teardown and leave a process holding the pipes.

/// Only the final-tree adapter names a path of its own; every fixture path
/// comes from [`committed_fixture`].
#[cfg(feature = "completion-proof-support")]
use std::path::PathBuf;

use pedant_process_guard::run_fixture;
use serde_json::{Value, json};

/// Bounded ownership of every child this root spawns.
///
/// The `#[path]` is required. Default resolution would place these files in
/// `tests/integration/`, which pedant's `conflicting-module-root` rule rejects
/// beside `integration.rs`, and its advice — fold the root into
/// `integration/mod.rs` — does not apply to a cargo test root, since cargo
/// builds a test executable per `tests/*.rs` and would stop building this one.
/// A sibling directory satisfies both: cargo declares no target for it,
/// because it holds no `main.rs`.
#[path = "integration_support/process_guard.rs"]
mod process_guard;

/// JSON-RPC over that guard. Same `#[path]` reason as [`process_guard`].
#[path = "integration_support/protocol.rs"]
mod protocol;

/// The completion receipt's inputs, writer, and validator. Same `#[path]`
/// reason as [`process_guard`].
#[path = "integration_support/receipt.rs"]
mod receipt;

/// The one stdio journey both completion proofs run. Same `#[path]` reason as
/// [`process_guard`].
#[path = "integration_support/journey.rs"]
mod journey;

/// The termination paths the guard must survive. Same `#[path]` reason as
/// [`process_guard`].
#[path = "integration_support/guard_cases.rs"]
mod guard_cases;

/// The one well-formed input set the contract rows start from. Same `#[path]`
/// reason as [`process_guard`].
#[path = "integration_support/receipt_fixture.rs"]
mod receipt_fixture;

/// Inputs the contract must refuse. Same `#[path]` reason as [`process_guard`].
#[path = "integration_support/receipt_input_cases.rs"]
mod receipt_input_cases;

/// Written receipts the contract must refuse. Same `#[path]` reason as
/// [`process_guard`].
#[path = "integration_support/receipt_document_cases.rs"]
mod receipt_document_cases;

/// Where the committed fixture workspaces live, shared with every other root
/// that reads one. Same `#[path]` reason as [`process_guard`].
#[path = "fixture_support/committed_fixture.rs"]
mod committed_fixture;

use crate::committed_fixture::fixture_path;
use crate::guard_cases::{GUARD_ROWS, guarded_run_leaves_no_descendant};
use crate::process_guard::{BUDGET, Completed, Failure, Guard, Run, execute};
use crate::protocol::{
    INDEXED_REPLY, REPLY, call_tool, initialize, request_bare, tool_json, tool_text,
};
use crate::receipt::CompletionProofInputs;
use crate::receipt_document_cases::{DOCUMENT_CASES, assert_document_case_is_rejected};
use crate::receipt_fixture::{Fixture, assert_valid_inputs_and_receipt_pass, workspace_root};
use crate::receipt_input_cases::{INPUT_CASES, assert_input_case_is_rejected};

/// The package set this plan affects, which is what a completion receipt has
/// to have answered typed queries for.
const AFFECTED_PACKAGES: [&str; 7] = [
    "pedant-types",
    "pedant-syntax",
    "pedant-lang",
    "pedant-core",
    "pedant-snippet",
    "pedant-mcp",
    "pedant",
];

#[test]
fn process_tree_fixture() {
    run_fixture().expect("the process-tree fixture should run");
}

/// Start the server in a fixture, initialize, hold one conversation, and tear
/// the tree down before anything is asserted.
fn fixture_session<T>(
    fixture: &str,
    conversation: impl FnOnce(&mut Guard) -> Result<T, Failure>,
) -> (Value, T, Completed) {
    let cwd = fixture_path(fixture);
    let mut guard = Guard::spawn(&Run::server(&cwd)).expect("the server should start");
    let held = initialize(&mut guard, REPLY)
        .and_then(|handshake| conversation(&mut guard).map(|answered| (handshake, answered)));
    let completed = guard
        .finish(BUDGET)
        .expect("the server's tree should tear down");
    let (handshake, answered) =
        held.unwrap_or_else(|failure| panic!("the exchange failed: {failure}"));
    (handshake, answered, completed)
}

// ---------------------------------------------------------------------------
// stdio framing and tool dispatch
// ---------------------------------------------------------------------------

#[test]
fn test_stdio_initialize_handshake() {
    let (handshake, (), completed) = fixture_session("multi_crate", |_| Ok(()));

    assert_eq!(handshake["jsonrpc"], "2.0");
    assert_eq!(handshake["id"], 1);
    assert!(
        handshake["result"]["capabilities"].is_object(),
        "expected server capabilities: {handshake}"
    );
    assert!(
        handshake["result"]["serverInfo"].is_object(),
        "expected server info: {handshake}"
    );
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_stdio_tools_list() {
    let (_, response, completed) = fixture_session("multi_crate", |guard| {
        request_bare(guard, 2, "tools/list", REPLY)
    });

    assert_eq!(response["id"], 2);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for expected in [
        "query_capabilities",
        "query_gate_verdicts",
        "query_violations",
        "search_by_capability",
        "explain_finding",
        "audit_crate",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected}, found: {names:?}"
        );
    }
    assert!(
        tools.len() >= 6,
        "expected at least 6 tools, got {}",
        tools.len()
    );
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_stdio_tools_call_query_capabilities() {
    let (_, response, completed) = fixture_session("multi_crate", |guard| {
        call_tool(
            guard,
            3,
            "query_capabilities",
            &json!({"scope": "lib-a"}),
            REPLY,
        )
    });

    assert_eq!(response["id"], 3);
    let text = tool_text(&response).expect("expected text content");
    assert!(
        text.contains("network"),
        "expected network capability in response: {text}"
    );
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_stdio_tools_call_audit_crate() {
    let (_, response, completed) = fixture_session("multi_crate", |guard| {
        call_tool(guard, 4, "audit_crate", &json!({"scope": "lib-a"}), REPLY)
    });

    assert_eq!(response["id"], 4);
    let audit = tool_json(&response).expect("expected JSON in text content");
    for field in ["capabilities", "gate_verdicts", "tier"] {
        assert!(
            audit.get(field).is_some(),
            "expected {field} in audit: {audit}"
        );
    }
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_stdio_unknown_tool_returns_error() {
    let (_, response, completed) = fixture_session("multi_crate", |guard| {
        call_tool(guard, 5, "nonexistent_tool", &json!({}), REPLY)
    });

    assert_eq!(response["id"], 5);
    // Either an error response or a tool result with isError=true.
    let has_error = response.get("error").is_some() || response["result"]["isError"] == json!(true);
    assert!(has_error, "expected error for unknown tool: {response}");
    // An unknown tool is refused in a response, not by dying: the server still
    // shuts down cleanly when stdin closes.
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_self_analysis_via_mcp() {
    let root = workspace_root();
    let mut guard = Guard::spawn(&Run::server(&root)).expect("the server should start");
    let held = initialize(&mut guard, INDEXED_REPLY).and_then(|_| {
        call_tool(
            &mut guard,
            10,
            "query_capabilities",
            &json!({"scope": "pedant-core"}),
            INDEXED_REPLY,
        )
    });
    let completed = guard
        .finish(BUDGET)
        .expect("the server's tree should tear down");
    let response = held.unwrap_or_else(|failure| panic!("the self-analysis failed: {failure}"));

    assert_eq!(response["id"], 10);
    let text = tool_text(&response).expect("expected text content for capabilities");
    assert!(
        text.contains("file_read"),
        "expected file_read capability in pedant-core: {text}"
    );
    assert!(completed.success(), "{}", completed.transcript());
}

#[test]
fn test_binary_no_workspace_exits_with_error() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let completed = execute(&Run::server(temp.path())).expect("the guard should report an ending");

    assert!(
        !completed.success(),
        "expected a non-zero exit: {}",
        completed.transcript()
    );
    assert!(
        completed.stderr.contains("workspace") || completed.stderr.contains("Cargo.toml"),
        "expected a workspace error in stderr: {}",
        completed.stderr
    );
}

// ---------------------------------------------------------------------------
// Process ownership
// ---------------------------------------------------------------------------

#[test]
fn mcp_stdio_guard_reaps_descendants_on_success_timeout_and_early_error() {
    for row in GUARD_ROWS {
        guarded_run_leaves_no_descendant(row);
    }
}

// ---------------------------------------------------------------------------
// Completion receipt
// ---------------------------------------------------------------------------

#[test]
fn completion_receipt_contract_rejects_missing_or_mismatched_fields() {
    assert_valid_inputs_and_receipt_pass();
    for case in INPUT_CASES {
        assert_input_case_is_rejected(case);
    }
    for case in DOCUMENT_CASES {
        assert_document_case_is_rejected(case);
    }
}

#[test]
fn mcp_stdio_receipt_round_trip_with_synthetic_identity() {
    let fixture = Fixture::valid();
    let inputs = CompletionProofInputs {
        test_scope: AFFECTED_PACKAGES.iter().copied().map(Box::from).collect(),
        ..fixture.inputs
    };
    journey::run(&inputs).expect("the synthetic completion journey should produce a valid receipt");
}

/// The final-tree adapter: the same journey, run against whatever the proof
/// runner states rather than against synthetic values.
///
/// Compiled only by the default-off `completion-proof-support` feature, so an
/// ordinary test run cannot report it as passed, and it cannot silently return
/// when its evidence is absent — a missing variable is a failure here.
#[cfg(feature = "completion-proof-support")]
#[test]
fn completion_receipt_binds_typed_queries_to_final_tree() {
    let inputs = runner_inputs().expect("the proof runner must supply every completion input");
    journey::run(&inputs).expect("the final-tree completion journey should validate");
}

#[cfg(feature = "completion-proof-support")]
#[test]
fn relative_completion_paths_are_anchored_to_workspace_root() {
    let root = workspace_root();
    let inputs = runner_inputs_from(root.clone(), |name| {
        let value = match name {
            "PROOF_OUTPUT_DIR" => "proof-output",
            "PLAN_COMPLETION_RECEIPT" => "proof-output/receipt.json",
            "PLAN_TEST_SCOPE" => "pedant-core pedant-mcp",
            "PLAN_HEAD_SHA" => "0123456789abcdef0123456789abcdef01234567",
            "PLAN_TERMINAL_SUMMARY" => "relative path regression",
            _ => return Err(format!("unexpected environment request: {name}")),
        };
        Ok(String::from(value))
    })
    .expect("relative runner inputs should parse");

    assert_eq!(inputs.proof_output_dir, root.join("proof-output"));
    assert_eq!(inputs.receipt_path, root.join("proof-output/receipt.json"));
}

/// Read the runner's stated identity, refusing anything it did not supply.
#[cfg(feature = "completion-proof-support")]
fn runner_inputs() -> Result<CompletionProofInputs, String> {
    runner_inputs_from(workspace_root(), required)
}

#[cfg(feature = "completion-proof-support")]
fn runner_inputs_from(
    root: PathBuf,
    mut require: impl FnMut(&str) -> Result<String, String>,
) -> Result<CompletionProofInputs, String> {
    let proof_output_dir = runner_path(&root, &require("PROOF_OUTPUT_DIR")?);
    let receipt_path = runner_path(&root, &require("PLAN_COMPLETION_RECEIPT")?);
    let scope = require("PLAN_TEST_SCOPE")?;
    Ok(CompletionProofInputs {
        root,
        head_sha: require("PLAN_HEAD_SHA")?.into(),
        test_scope: scope.split_whitespace().map(Box::from).collect(),
        terminal_summary: require("PLAN_TERMINAL_SUMMARY")?.into(),
        proof_output_dir,
        receipt_path,
    })
}

#[cfg(feature = "completion-proof-support")]
fn runner_path(root: &std::path::Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    match path.is_absolute() {
        true => path,
        false => root.join(path),
    }
}

#[cfg(feature = "completion-proof-support")]
fn required(name: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("{name} is not set, so the final tree is unproven")),
    }
}
