//! The real stdio MCP journey: handshake, one tool, every outcome, and bounded
//! shutdown.
//!
//! Every case comes from [`cases::cases`] and every failure from
//! [`cases::FAILURES`], so this journey states no outcome of its own: it proves
//! the tool sends the shared envelope, byte for byte, for the same questions the
//! library and the CLI answer.

use serde_json::{Value, json};

use crate::cases::{self, Case, Tree};
use crate::child::{Failure, Server, Termination};
use crate::mcp_journey::{
    self, IN_FLIGHT_ID, INVALID_PARAMS, Journey, LAST_CALL_LABEL, MISSPELLED_ARGUMENT, UNKNOWN_TOOL,
};

/// The name the server gives itself in the handshake.
///
/// Written down rather than read from `CARGO_PKG_NAME`. rmcp's default fills
/// this field from *its own* build environment, so an expectation derived from
/// a build environment is exactly the mistake this assertion catches.
const SERVER_NAME: &str = "pedant-snippet";

/// The type the input schema declares for each argument it names.
///
/// A property the schema merely declares is not enough: a `line` typed
/// `"string"` would keep an is-an-object assertion green while every
/// schema-validating client refused a correct call.
const SCHEMA_TYPES: [(&str, &str); 3] = [
    ("path", "string"),
    ("line", "integer"),
    ("column", "integer"),
];

/// Every behaviour hint the tool publishes, and the value it publishes.
///
/// Written down as wire keys, not read from the server. An absent `annotations`
/// block is not neutral: MCP reads it as `readOnlyHint: false`,
/// `destructiveHint: true`, and `openWorldHint: true`, so a tool holding one
/// `file_read` capability would be gated behind an approval prompt. Each value
/// here is a fact about this tool — it opens the named file, writes nothing,
/// answers the same question the same way, and reaches no host but this one.
const ANNOTATIONS: [(&str, bool); 3] = [
    ("readOnlyHint", true),
    ("idempotentHint", true),
    ("openWorldHint", false),
];

/// Assert `tools/list` exposes exactly the one documented tool.
fn assert_single_tool(response: &Value) {
    let tools = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list returns an array: {response}"));
    assert_eq!(tools.len(), 1, "exactly one tool is served: {response}");
    assert_eq!(
        tools[0]["name"],
        json!(cases::TOOL),
        "the served tool is the one every interface names: {response}"
    );
    assert_eq!(
        tools[0]["description"],
        json!(cases::TOOL_DESCRIPTION),
        "the tool describes itself as documented: {response}"
    );

    let annotations = &tools[0]["annotations"];
    for (hint, published) in ANNOTATIONS {
        assert_eq!(
            annotations[hint],
            json!(published),
            "the tool publishes {hint} as {published}: {annotations}"
        );
    }

    let schema = &tools[0]["inputSchema"];
    assert_eq!(
        schema["type"],
        json!("object"),
        "the input schema describes an object: {schema}"
    );
    assert_eq!(
        schema["required"],
        json!(["path", "line"]),
        "path and line are required, column is not: {schema}"
    );
    for (property, kind) in SCHEMA_TYPES {
        assert_eq!(
            schema["properties"][property]["type"],
            json!(kind),
            "the schema types {property} as {kind}: {schema}"
        );
    }
    // Exhaustive in both directions: a fourth property with no `Params` field
    // would advertise an argument `deny_unknown_fields` then refuses at call
    // time, and a per-property loop alone would stay green.
    assert_eq!(
        schema["properties"].as_object().map(serde_json::Map::len),
        Some(SCHEMA_TYPES.len()),
        "the schema names no argument this table omits: {schema}"
    );
    assert_eq!(
        schema["additionalProperties"],
        json!(false),
        "the schema refuses an argument it does not name: {schema}"
    );
}

/// Assert one response carries exactly `envelope` and reports no tool error.
///
/// The protocol-error check comes first and asserts the positive shape. A
/// JSON-RPC error response carries no `result` at all, so every field read
/// beneath it yields `Null`; an `assert_ne!` against `true` would pass on a
/// refusal and leave `content_text` to panic about missing content blocks for a
/// failure that is really "the server never ran the tool".
fn assert_answered(response: &Value, envelope: &str, label: &str) {
    assert!(
        response["error"].is_null(),
        "{label}: an answer is not a protocol error: {response}"
    );
    assert_eq!(
        response["result"]["isError"],
        json!(false),
        "{label}: an answer is not a tool error: {response}"
    );
    assert_eq!(
        content_text(response, label),
        envelope,
        "{label}: the tool sends the envelope every interface sends"
    );
}

/// Assert one response is a tool error carrying everything the failure states.
///
/// What the message must say is [`cases::assert_carries`], beside the table both
/// transports read. This supplies only this interface's surface: the one content
/// block a tool error carries.
fn assert_refused(response: &Value, failure: &cases::FailureCase, path: &str) {
    assert_eq!(
        response["result"]["isError"],
        json!(true),
        "{}: a refusal is a tool error: {response}",
        failure.label
    );
    let text = content_text(response, failure.label);
    cases::assert_carries(text, failure, path, failure.label);
}

/// Assert one response is a JSON-RPC error carrying `code` and every reason in
/// `expected`.
///
/// A protocol error is not a tool error: it carries no result at all, so a
/// client can tell a tool that ran and failed from one that never ran — an
/// unserved name, or arguments that did not deserialize.
fn assert_protocol_error(response: &Value, code: i32, expected: &[&str], label: &str) {
    assert_eq!(
        response["error"]["code"],
        json!(code),
        "{label}: the response is a JSON-RPC error: {response}"
    );
    assert!(
        response["result"].is_null(),
        "{label}: a protocol error carries no result: {response}"
    );
    let message = response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: the error states its reason: {response}"));
    for reason in expected {
        assert!(
            message.contains(reason),
            "{label}: the error carries {reason:?}: {message}"
        );
    }
}

/// The one text block a tool response carries.
fn content_text<'a>(response: &'a Value, label: &str) -> &'a str {
    let content = response["result"]["content"]
        .as_array()
        .unwrap_or_else(|| panic!("{label}: the response carries content: {response}"));
    assert_eq!(content.len(), 1, "{label}: one content block: {response}");
    content[0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: the block is text: {response}"))
}

/// The server's own diagnostics, for a message about a journey that failed.
///
/// A teardown that succeeded established three facts, so all three travel: a
/// server that answered wrongly *and* exited non-zero *and* wrote unsolicited
/// stdout reports every one of them at the panic, not just its stderr.
fn logs(teardown: &Result<Termination, Failure>) -> Box<str> {
    match teardown {
        Ok(termination) => format!(
            "\nserver exit: {:?}\nserver stderr: {}\nserver trailing stdout: {}",
            termination.status, termination.stderr, termination.trailing
        ),
        Err(failure) => format!("\nteardown also failed: {failure}"),
    }
    .into_boxed_str()
}

#[tokio::test]
async fn present_absent_and_unreadable_stdio_journey() {
    let tree = Tree::new().expect("temporary fixture tree");
    let cases = cases::cases();
    let mut server = Server::start()
        .await
        .unwrap_or_else(|failure| panic!("the stdio server starts: {failure}"));

    let outcome = mcp_journey::run(&mut server, &tree, &cases).await;
    let teardown = server.shutdown().await;

    let journey = outcome.unwrap_or_else(|failure| {
        panic!("the MCP journey completes: {failure}{}", logs(&teardown))
    });
    let termination =
        teardown.unwrap_or_else(|failure| panic!("the server exits inside its budget: {failure}"));

    assert_handshake(&journey.initialize);
    assert_single_tool(&journey.tools);
    assert_answers(&cases, &journey);
    assert_refusals(&tree, &journey);
    assert_clean_exit(&termination);
}

/// The handshake advertises tools, names the server, and pins the version.
fn assert_handshake(initialize: &Value) {
    assert!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        "the server advertises tools: {initialize}"
    );
    // Equality, not merely an object. rmcp's default server info expands
    // `CARGO_CRATE_NAME` and `CARGO_PKG_VERSION` where rmcp itself is compiled,
    // so a server that never states its own reports the transport library and
    // its release to every client — and any is-an-object check passes on that.
    let identity = &initialize["result"]["serverInfo"];
    assert_eq!(
        identity["name"],
        json!(SERVER_NAME),
        "the server names itself, not its transport library: {initialize}"
    );
    // The version is read from a build environment where the name is written
    // down, because this test root lives in the package that builds the binary:
    // `CARGO_PKG_VERSION` expands to the server's own release here, and writing
    // it down would mean editing this file on every release. The name assertion
    // above is what catches a regression to rmcp's default identity.
    assert_eq!(
        identity["version"],
        json!(env!("CARGO_PKG_VERSION")),
        "the server reports its own release: {initialize}"
    );
    // Pinned from the running server: it negotiates the same "2025-03-26" the
    // client asks for in `initialize_request`.
    assert_eq!(
        initialize["result"]["protocolVersion"],
        json!("2025-03-26"),
        "the server negotiates the version the client requests: {initialize}"
    );
}

/// Every answered call sends the envelope its case states, replays included.
fn assert_answers(cases: &[Case], journey: &Journey) {
    cases::assert_every_row_ran(cases.len(), journey.cases.len(), "tools/call");
    for (case, response) in &journey.cases {
        assert_answered(response, case.envelope, case.label);
    }

    assert_answered(
        &journey.explicit_null_column,
        cases::PRESENT_ENVELOPE,
        "an explicit null column",
    );
    // Read after `close_stdin` returned, which is all a client can observe: the
    // server may have written this answer before the close or after it, and
    // nothing over the protocol says which. What is proven is that the call sent
    // last is the call answered last, and `assert_clean_exit` proves EOF then
    // ended the run.
    assert_answered(&journey.in_flight, cases::PRESENT_ENVELOPE, LAST_CALL_LABEL);
    assert_eq!(
        journey.in_flight["id"],
        json!(IN_FLIGHT_ID),
        "{LAST_CALL_LABEL}: the answer read after EOF answers the last call: {}",
        journey.in_flight
    );
}

/// Every refused call says why, and a call that never reached the tool — an
/// unserved name, or arguments that did not deserialize — refuses as a protocol
/// error rather than as a tool result.
fn assert_refusals(tree: &Tree, journey: &Journey) {
    cases::assert_every_row_ran(
        cases::FAILURES.len(),
        journey.failures.len(),
        "the unreadable sources",
    );
    for (failure, response) in &journey.failures {
        assert_refused(response, failure, &tree.argument(failure.source));
    }

    let refused = &journey.refusals;
    assert_protocol_error(
        &refused.unknown_tool,
        INVALID_PARAMS,
        &[&format!("unknown tool: {UNKNOWN_TOOL}")],
        "a tool this server does not serve",
    );
    // The exact serde wording, not merely "path": every other deserialization
    // refusal enumerates the expected fields, so a message naming "path" for an
    // unrelated reason would satisfy a looser expectation.
    assert_protocol_error(
        &refused.invalid_parameters,
        INVALID_PARAMS,
        &["invalid parameters", "missing field `path`"],
        "arguments without the required path",
    );
    assert_protocol_error(
        &refused.misspelled_argument,
        INVALID_PARAMS,
        &["invalid parameters", MISSPELLED_ARGUMENT],
        "a misspelled column argument",
    );
    assert_protocol_error(
        &refused.non_integer_line,
        INVALID_PARAMS,
        &["invalid parameters", "invalid type: string"],
        "a line that is not an integer",
    );
}

/// EOF shuts the server down cleanly, silently, and with nothing left to say.
fn assert_clean_exit(termination: &Termination) {
    assert!(
        termination.status.success(),
        "EOF shuts the server down cleanly: {:?}: {}",
        termination.status,
        termination.stderr
    );
    assert!(
        termination.trailing.is_empty(),
        "the server sends nothing the client did not ask for: {}",
        termination.trailing
    );
    assert_eq!(
        &*termination.stderr, "",
        "a journey the server answered in full writes no diagnostics"
    );
}
