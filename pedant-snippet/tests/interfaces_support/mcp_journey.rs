//! Requests and responses for the real stdio MCP journey.

use pedant_snippet::Location;
use serde_json::{Value, json};

use crate::cases::{self, Case, FailureCase, Tree};
use crate::child::{Failure, Server};

/// The id the last call carries, sent immediately before stdin closes.
///
/// Nothing over this protocol orders the server's answer against the close, so
/// the id proves what is observable: the answer read after stdin closed is the
/// answer to the last call, and no earlier reply arriving late.
pub const IN_FLIGHT_ID: u32 = 90;

/// What the call carrying [`IN_FLIGHT_ID`] proves.
///
/// One sentence, read three times: the step a failure names, the label the
/// answer is asserted under, and the claim itself. It says only what the wire
/// shows — the call is answered and EOF still ends the run — because no client
/// can order the server's write against its own `close_stdin`.
pub const LAST_CALL_LABEL: &str = "a call sent immediately before EOF is still answered";

/// The method every case, failure, and refusal in this journey invokes.
const CALL: &str = "tools/call";

/// A tool name this server does not serve.
pub const UNKNOWN_TOOL: &str = "not_a_tool";

/// The JSON-RPC code for a request this server cannot accept.
pub const INVALID_PARAMS: i32 = -32602;

/// A misspelling of the optional `column` argument.
pub const MISSPELLED_ARGUMENT: &str = "colunm";

/// A `line` a schema-validating client would never send.
///
/// The CLI's parity case is `--line seven`, which clap refuses; here the same
/// mistake must fail deserialization rather than reach the tool.
const NON_INTEGER_LINE: &str = "seven";

/// Every response this journey collects before it asserts.
///
/// Every response travels with the row that asked for it. An earlier draft kept
/// bare `Box<[Value]>` and paired each against the table with `zip` at the
/// assertion: `zip` stops at the shorter side and reports success, so one
/// skipped row narrowed the whole assertion and left the suite green. Pairing at
/// construction makes the mismatch unrepresentable rather than unlikely.
pub struct Journey<'a> {
    /// The handshake response.
    pub initialize: Value,
    /// The `tools/list` response.
    pub tools: Value,
    /// One response per case, paired with the case it answers.
    pub cases: Box<[(&'a Case, Value)]>,
    /// One response per unreadable file, paired with the row it answers.
    pub failures: Box<[(&'a FailureCase, Value)]>,
    /// The present case called with an explicit `"column": null`.
    pub explicit_null_column: Value,
    /// Every call the server refused before the tool ran.
    pub refusals: Refusals,
    /// The present case, sent immediately before stdin closed and read after.
    pub in_flight: Value,
}

/// Every call this server must refuse before it reaches the tool.
///
/// Grouped rather than flattened into [`Journey`] because they answer one
/// question: a client is told the call never ran. [`Journey::failures`] holds
/// the other kind — a tool that ran and reported why it could not answer.
pub struct Refusals {
    /// A call naming a tool this server does not serve.
    pub unknown_tool: Value,
    /// A call whose arguments omit the required `path`.
    pub invalid_parameters: Value,
    /// A call whose arguments misspell `column`.
    pub misspelled_argument: Value,
    /// A call whose `line` is a string rather than an integer.
    pub non_integer_line: Value,
}

/// The `initialize` request every client sends first.
fn initialize_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "pedant-snippet-test", "version": "0.1.0" }
        }
    })
}

/// One `enclosing_unit` call, carrying `column` only when `at` has one.
///
/// A column-absent case omits the key entirely, which is the shape the input
/// schema calls optional.
fn call_request(id: u32, path: &str, at: Location) -> Value {
    let mut arguments = json!({ "path": path, "line": at.line });
    if let Some(column) = at.column {
        arguments["column"] = json!(column);
    }
    tool_call(id, cases::TOOL, arguments)
}

/// One `tools/call` request for `name`.
fn tool_call(id: u32, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

/// Drive the whole protocol journey, closing stdin immediately after the last
/// call.
pub async fn run<'a>(
    server: &mut Server,
    tree: &Tree,
    cases: &'a [Case],
) -> Result<Journey<'a>, Failure> {
    let initialize = server
        .request(&initialize_request())
        .await
        .map_err(|failure| failure.during("the handshake", "initialize"))?;
    server
        .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await
        .map_err(|failure| failure.during("the handshake", "notifications/initialized"))?;

    let tools = server
        .request(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .await
        .map_err(|failure| failure.during("the served tool list", "tools/list"))?;

    let answers = request_cases(server, tree, cases).await?;
    let failures = request_failures(server, tree).await?;

    let path = tree.argument(cases::PRESENT_AT);
    let explicit_null_column = server
        .request(&tool_call(
            70,
            cases::TOOL,
            json!({ "path": &*path, "line": cases::PRESENT_LINE, "column": Value::Null }),
        ))
        .await
        .map_err(|failure| failure.during("an explicit null column", CALL))?;

    let refusals = request_refusals(server, &path).await?;

    // Sent, then stdin closed, then read. Nothing over this protocol orders the
    // server's write against the close, so the claim asserted is the one the
    // wire can show: the last call is answered, the answer is read after stdin
    // closed, and EOF then shuts the server down — which `assert_clean_exit`
    // proves from the exit status and the empty trailing stdout.
    server
        .send(&call_request(IN_FLIGHT_ID, &path, cases::present_point()))
        .await
        .map_err(|failure| failure.during(LAST_CALL_LABEL, CALL))?;
    server.close_stdin();
    let in_flight = server
        .recv()
        .await
        .map_err(|failure| failure.during(LAST_CALL_LABEL, "the answer read after EOF"))?;

    Ok(Journey {
        initialize,
        tools,
        cases: answers,
        failures,
        explicit_null_column,
        refusals,
        in_flight,
    })
}

/// Every call the server must refuse before the tool runs, one exchange each.
///
/// `path` is a readable source, so nothing here is refused for naming a file
/// the server cannot open: each call is malformed as a call.
async fn request_refusals(server: &mut Server, path: &str) -> Result<Refusals, Failure> {
    let unknown_tool = server
        .request(&tool_call(80, UNKNOWN_TOOL, json!({})))
        .await
        .map_err(|failure| failure.during("a tool this server does not serve", CALL))?;
    let invalid_parameters = server
        .request(&tool_call(
            81,
            cases::TOOL,
            json!({ "line": cases::PRESENT_LINE }),
        ))
        .await
        .map_err(|failure| failure.during("arguments without the required path", CALL))?;
    let misspelled_argument = server
        .request(&tool_call(
            82,
            cases::TOOL,
            json!({
                "path": path,
                "line": cases::PRESENT_LINE,
                MISSPELLED_ARGUMENT: cases::PRESENT_COLUMN
            }),
        ))
        .await
        .map_err(|failure| failure.during("a misspelled column argument", CALL))?;

    // A stringified integer is the malformed call a schema-blind client makes
    // most often. The schema types `line` as an integer; this proves the server
    // enforces the type it advertises rather than merely declaring it.
    let non_integer_line = server
        .request(&tool_call(
            83,
            cases::TOOL,
            json!({ "path": path, "line": NON_INTEGER_LINE }),
        ))
        .await
        .map_err(|failure| failure.during("a line that is not an integer", CALL))?;

    Ok(Refusals {
        unknown_tool,
        invalid_parameters,
        misspelled_argument,
        non_integer_line,
    })
}

/// Request every declaration case in table order, paired with its case.
async fn request_cases<'a>(
    server: &mut Server,
    tree: &Tree,
    cases: &'a [Case],
) -> Result<Box<[(&'a Case, Value)]>, Failure> {
    let mut answers = Vec::with_capacity(cases.len());
    for (index, case) in cases.iter().enumerate() {
        let request = call_request(10 + index as u32, &tree.argument(case.source), case.at);
        let response = server
            .request(&request)
            .await
            .map_err(|failure| failure.during(case.label, CALL))?;
        answers.push((case, response));
    }
    Ok(answers.into())
}

/// Request every unreadable source in table order, paired with its row.
async fn request_failures(
    server: &mut Server,
    tree: &Tree,
) -> Result<Box<[(&'static FailureCase, Value)]>, Failure> {
    let mut failures = Vec::with_capacity(cases::FAILURES.len());
    for (index, row) in cases::FAILURES.iter().enumerate() {
        let request = call_request(
            40 + index as u32,
            &tree.argument(row.source),
            cases::present_point(),
        );
        let response = server
            .request(&request)
            .await
            .map_err(|failure| failure.during(row.label, CALL))?;
        failures.push((row, response));
    }
    Ok(failures.into())
}
