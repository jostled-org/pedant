//! The client half of every stdio journey: handshake, list, call, and poll.
//!
//! Six journeys speak this protocol and none of them is about the protocol, so
//! the messages are written here once. Every id is distinct and every reply is
//! matched to the request that asked for it by [`Server::request`], so no
//! assertion can compare an answer to the wrong question.
//!
//! The bounded poll is here for the same reason, and there is one of it. Five
//! journeys wait for the watcher to publish, none of them waits by sleeping for
//! a duration somebody guessed, and a second copy of that loop is a second place
//! for one of them to quietly start waiting a different way. [`published`] and
//! [`healthy`] differ only in which field they read and which way they compare
//! it, so that is all they state.
//!
//! The session itself is here too. Twelve journeys spawn a server, drive it,
//! tear it down, and report — and the order those four steps run in is what
//! makes a failure readable, so [`session`] owns it and no journey restates it.
//! [`claimed`] is the other half of that discipline: a claim made while the
//! child is live returns rather than panics, so the teardown still happens and
//! the message still carries the server's own log.
//!
//! Every claim about a response is therefore stated twice — once returning and
//! once panicking. The `claimed_*` form is the one a drive closure calls, and it
//! is the one the panicking form is written on, so the two cannot state
//! different rules. A journey that reached for the panicking form mid-session
//! would unwind past [`Server::shutdown`] and lose the drain, the log, and the
//! trailing stdout: not a leak, because the destructor still ends the tree, but
//! the loss of exactly the diagnostics this module exists to preserve.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

use crate::child::{Server, Termination};
use crate::failure::Failure;

/// The protocol version the client asks for and the server negotiates.
pub const PROTOCOL: &str = "2025-03-26";

/// The JSON-RPC code an unserved name or undeserializable arguments return.
pub const INVALID_PARAMS: i32 = -32602;

/// How long a journey waits for the watcher to publish one change.
///
/// Generous, because it bounds a filesystem notification, a settle window, and a
/// whole repository rebuild on a loaded machine. Nothing waits the whole budget
/// unless the publish never happens.
pub const PUBLISH_BUDGET: Duration = Duration::from_secs(30);

/// How long to wait between polls for a new answer.
const POLL: Duration = Duration::from_millis(50);

/// The probe every bounded poll asks with.
///
/// It takes no argument and every state answers it, so a poll cannot fail for a
/// reason belonging to the question rather than to the state under it.
const PROBE: &str = "list_projects";

/// Start a server, drive one journey, tear it down, and report both halves.
///
/// The order is [`crate::child`]'s contract, stated once. The journey's outcome
/// is collected, the child is torn down, and only then does anything panic — so
/// a failed claim reaches the reader with the server's own diagnostics attached
/// rather than with the drain aborted underneath it.
///
/// Both halves come back. A caller that dropped the [`Termination`] would have
/// proved the server returned from its transport, which is not the claim: the
/// exit status, the trailing stdout, the log, and the process tree are what say
/// it stopped.
pub async fn session<T>(
    arguments: &[&str],
    label: &str,
    drive: impl AsyncFnOnce(&mut Server) -> Result<T, Failure>,
) -> (T, Termination) {
    let mut server = Server::start(arguments)
        .await
        .unwrap_or_else(|failure| panic!("{label}: the stdio server starts: {failure}"));

    let outcome = drive(&mut server).await;
    let teardown = server.shutdown().await;

    let answered =
        outcome.unwrap_or_else(|failure| panic!("{label} completes: {failure}{}", logs(&teardown)));
    let termination = teardown
        .unwrap_or_else(|failure| panic!("{label}: the server exits inside its budget: {failure}"));
    (answered, termination)
}

/// One claim a journey makes while its child is still live.
///
/// A [`Failure`] rather than an assertion, for the reason [`crate::child`]
/// states: a panic here unwinds past [`Server::shutdown`], so [`logs`] never
/// runs and the destructor aborts the stderr drain — discarding the server's own
/// account of exactly the failure that needed explaining. The message is built
/// on the failing path alone, so a journey that answers allocates nothing here.
pub fn claimed(held: bool, stated: impl FnOnce() -> String) -> Result<(), Failure> {
    match held {
        true => Ok(()),
        false => Err(Failure::Protocol(stated().into())),
    }
}

/// Complete the handshake and return what the server said about itself.
pub async fn initialized(server: &mut Server) -> Result<Value, Failure> {
    let initialize = server
        .request(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": { "name": "pedant-snippet-tests", "version": "0" }
            }
        }))
        .await?;
    server
        .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await?;
    Ok(initialize)
}

/// The tools one listing states.
///
/// Here rather than beside each reader, because the protocol is written once in
/// this module and a listing is protocol: two journeys read the same three keys
/// out of the same reply, and the second copy had already grown a failure of its
/// own shape.
pub fn tools<'response>(
    response: &'response Value,
    label: &str,
) -> Result<&'response [Value], Failure> {
    response["result"]["tools"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| {
            Failure::Protocol(format!("{label}: the listing states its tools: {response}").into())
        })
}

/// Ask for the served tools.
pub async fn listed(server: &mut Server, id: i64) -> Result<Value, Failure> {
    server
        .request(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        }))
        .await
}

/// Call one tool by name with one argument object.
pub async fn called(
    server: &mut Server,
    id: i64,
    name: &str,
    arguments: &Value,
) -> Result<Value, Failure> {
    server
        .request(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))
        .await
}

/// Call one tool under the next id nobody on this connection has used.
pub async fn asked(server: &mut Server, name: &str, arguments: &Value) -> Result<Value, Failure> {
    let id = server.next_id();
    called(server, id, name, arguments).await
}

/// The parsed envelope one answered tool call carries.
///
/// The first step of every journey, so it states its claim rather than
/// asserting it: a tool error here would otherwise panic inside the drive
/// closure and take the server's log with it.
pub async fn envelope(
    server: &mut Server,
    name: &str,
    arguments: &Value,
    label: &str,
) -> Result<Value, Failure> {
    let response = asked(server, name, arguments).await?;
    parsed(claimed_answer(&response, label)?, label)
}

/// The parsed envelope one refused tool call carries.
///
/// The twin of [`envelope`], differing only in which claim the reply is held
/// to. Here rather than beside the one journey that reads a refusal back
/// through a tool: the decode is the same decode, and a copy written at a call
/// site is where the two start reporting a malformed answer differently.
pub async fn refusal(
    server: &mut Server,
    name: &str,
    arguments: &Value,
    label: &str,
) -> Result<Value, Failure> {
    let response = asked(server, name, arguments).await?;
    parsed(claimed_refusal(&response, label)?, label)
}

/// One tool content block, read as the JSON document it carries.
fn parsed(answer: &str, label: &str) -> Result<Value, Failure> {
    serde_json::from_str(answer)
        .map_err(|error| Failure::Protocol(format!("{label}: the answer parses: {error}").into()))
}

/// One string field of an envelope, named by the journey reading it.
///
/// `Box<str>` rather than `String`: the reading is taken out of a borrowed
/// answer and compared, and nothing appends to it.
pub fn stated(answered: &Value, field: &str, label: &str) -> Result<Box<str>, Failure> {
    answered[field].as_str().map(Box::from).ok_or_else(|| {
        Failure::Protocol(format!("{label}: the answer states its {field}: {answered}").into())
    })
}

/// Ask the probe once and read the index revision the session opened on.
///
/// The step every journey takes straight after the handshake. Four of them
/// opened this way and two were byte-identical, so the answer, the field, and
/// the label are written once. Both halves come back: a caller compares against
/// the revision and quotes the state in whatever it fails on.
pub async fn opened(server: &mut Server, label: &str) -> Result<(Value, Box<str>), Failure> {
    let answered = envelope(server, PROBE, &json!({}), label).await?;
    let revision = stated(&answered, "index_revision", label)?;
    Ok((answered, revision))
}

/// Poll the probe until `settled` accepts what `read` states, or time out.
///
/// The one bounded poll. A wait for the answer to change rather than a sleep
/// for a duration somebody guessed: a host that publishes sooner finishes
/// sooner, and a host that never publishes fails on the budget rather than on a
/// race. What differs between the waits below is which field is read and which
/// way the comparison runs, so those are the caller's and the deadline, the
/// probe, and the sleep are not.
///
/// The reading comes back with the state it was taken from. A caller that only
/// got the state would have to read the same field off the same value again to
/// learn what settled the poll — a re-read that can only agree with the branch
/// that returned, and so can only look like a claim.
async fn poll(
    server: &mut Server,
    label: &str,
    read: impl Fn(&Value) -> Result<Box<str>, Failure>,
    settled: impl Fn(&str) -> bool,
    unmet: impl Fn(&Value) -> String,
) -> Result<(Value, Box<str>), Failure> {
    let deadline = Instant::now() + PUBLISH_BUDGET;
    loop {
        let answered = envelope(server, PROBE, &json!({}), label).await?;
        let reading = read(&answered)?;
        if settled(&reading) {
            return Ok((answered, reading));
        }
        if Instant::now() >= deadline {
            return Err(Failure::Protocol(unmet(&answered).into()));
        }
        sleep(POLL).await;
    }
}

/// Poll the probe until `field` leaves `held`, and state what it left it for.
pub async fn published(
    server: &mut Server,
    field: &str,
    held: &str,
    label: &str,
) -> Result<(Value, Box<str>), Failure> {
    poll(
        server,
        label,
        |answered| stated(answered, field, label),
        |reading| reading != held,
        |_| {
            format!(
                "{label}: the server still reports {field} {held} after {}s",
                PUBLISH_BUDGET.as_secs()
            )
        },
    )
    .await
}

/// Poll the probe until it reports the health `wanted` names, or time out.
///
/// Health is not a revision: a state can be republished under a new identity
/// and still be the same health, so a journey about staleness has to wait for
/// the status rather than for the state to move.
pub async fn healthy(server: &mut Server, wanted: &str, label: &str) -> Result<Value, Failure> {
    poll(
        server,
        label,
        |answered| stated(&answered["health"], "status", label),
        |reading| reading == wanted,
        |answered| {
            format!(
                "{label}: the server never reported health {wanted} in {}s: {}",
                PUBLISH_BUDGET.as_secs(),
                answered["health"]
            )
        },
    )
    .await
    .map(|(answered, _)| answered)
}

/// The one text block a tool response carries, stated rather than asserted.
pub fn claimed_content<'response>(
    response: &'response Value,
    label: &str,
) -> Result<&'response str, Failure> {
    let content = response["result"]["content"].as_array().ok_or_else(|| {
        Failure::Protocol(format!("{label}: the response carries content: {response}").into())
    })?;
    claimed(content.len() == 1, || {
        format!("{label}: one content block: {response}")
    })?;
    content[0]["text"]
        .as_str()
        .ok_or_else(|| Failure::Protocol(format!("{label}: the block is text: {response}").into()))
}

/// One response is a successful tool result, and this is its content.
pub fn claimed_answer<'response>(
    response: &'response Value,
    label: &str,
) -> Result<&'response str, Failure> {
    claimed(response["error"].is_null(), || {
        format!("{label}: an answer is not a protocol error: {response}")
    })?;
    claimed(response["result"]["isError"] == json!(false), || {
        format!("{label}: an answer is not a tool error: {response}")
    })?;
    claimed_content(response, label)
}

/// One response is a tool error, and this is its content.
pub fn claimed_refusal<'response>(
    response: &'response Value,
    label: &str,
) -> Result<&'response str, Failure> {
    claimed(response["error"].is_null(), || {
        format!("{label}: a query that ran and refused is not a protocol error: {response}")
    })?;
    claimed(response["result"]["isError"] == json!(true), || {
        format!("{label}: a typed refusal is a tool error: {response}")
    })?;
    claimed_content(response, label)
}

/// One response is a JSON-RPC error carrying `code` and every reason.
///
/// A protocol error is not a tool error: it carries no result at all, so a
/// client can tell a tool that ran and failed from one that never ran.
pub fn claimed_protocol_error(
    response: &Value,
    code: i32,
    expected: &[&str],
    label: &str,
) -> Result<(), Failure> {
    claimed(response["error"]["code"] == json!(code), || {
        format!("{label}: the response is a JSON-RPC error: {response}")
    })?;
    claimed(response["result"].is_null(), || {
        format!("{label}: a protocol error carries no result: {response}")
    })?;
    let message = response["error"]["message"].as_str().ok_or_else(|| {
        Failure::Protocol(format!("{label}: the error states its reason: {response}").into())
    })?;
    expected.iter().try_for_each(|reason| {
        claimed(message.contains(reason), || {
            format!("{label}: the error carries {reason:?}: {message}")
        })
    })
}

/// Assert one response is a successful tool result, and return its content.
///
/// For the assertion phase, after [`session`] has torn the child down and
/// attached its log. Built on the returning form so the two cannot state
/// different rules, which is also why it carries no message of its own: the
/// sentence a reader gets is the one the claim already wrote.
pub fn answered<'response>(response: &'response Value, label: &str) -> &'response str {
    reported(claimed_answer(response, label))
}

/// Assert one response is a tool error, and return its content.
pub fn refused<'response>(response: &'response Value, label: &str) -> &'response str {
    reported(claimed_refusal(response, label))
}

/// Assert one listing states its tools, and return them.
///
/// The assertion-phase form of [`tools`], built on it for the reason
/// [`answered`] is built on its claim: a registry journey reads the listing
/// three times after its teardown, and a panicking reader written beside those
/// readers is the second copy this module exists to prevent.
pub fn served<'response>(response: &'response Value, label: &str) -> &'response [Value] {
    reported(tools(response, label))
}

/// Assert one response is a JSON-RPC error carrying `code` and every reason.
pub fn assert_protocol_error(response: &Value, code: i32, expected: &[&str], label: &str) {
    reported(claimed_protocol_error(response, code, expected, label));
}

/// One stated claim, failed as an assertion.
fn reported<T>(claim: Result<T, Failure>) -> T {
    claim.unwrap_or_else(|failure| panic!("{failure}"))
}

/// The server's own diagnostics, for a message about a journey that failed.
///
/// Private, because [`session`] is the one place a journey failure is reported
/// and folding the log in is what that function is for.
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
