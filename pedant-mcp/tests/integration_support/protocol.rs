//! Newline-delimited JSON-RPC over a guarded child's stdio.
//!
//! Every helper here returns `Result` while the child is still live, so a
//! caller can tear the guard down and only then assert. A helper that panicked
//! mid-conversation would unwind past the teardown the guard exists to run.
//!
//! Responses are matched by request id rather than by arrival order: the
//! server is free to interleave notifications, and a reader that took the next
//! line whatever it was would answer one request with another's payload.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::process_guard::{Failure, Guard, protocol};

/// Ceiling on one request-response exchange against a fixture workspace.
pub(crate) const REPLY: Duration = Duration::from_secs(30);

/// Ceiling on the first exchange against this repository, which indexes every
/// crate before it answers.
pub(crate) const INDEXED_REPLY: Duration = Duration::from_secs(180);

/// The protocol revision this root speaks.
const PROTOCOL_VERSION: &str = "2025-03-26";

/// Send `initialize`, take its response, and send `initialized`.
pub(crate) fn initialize(guard: &mut Guard, budget: Duration) -> Result<Value, Failure> {
    let response = request(
        guard,
        1,
        "initialize",
        &json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "pedant-mcp-tests", "version": "0.1.0"},
        }),
        budget,
    )?;
    notify(guard, "notifications/initialized")?;
    Ok(response)
}

/// Send one request and return the response carrying its id.
pub(crate) fn request(
    guard: &mut Guard,
    id: u64,
    method: &str,
    params: &Value,
    budget: Duration,
) -> Result<Value, Failure> {
    send(
        guard,
        &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )?;
    receive(guard, id, budget)
}

/// Send one request that carries no parameters.
pub(crate) fn request_bare(
    guard: &mut Guard,
    id: u64,
    method: &str,
    budget: Duration,
) -> Result<Value, Failure> {
    send(
        guard,
        &json!({"jsonrpc": "2.0", "id": id, "method": method}),
    )?;
    receive(guard, id, budget)
}

/// Call one tool and return the whole JSON-RPC response.
pub(crate) fn call_tool(
    guard: &mut Guard,
    id: u64,
    name: &str,
    arguments: &Value,
    budget: Duration,
) -> Result<Value, Failure> {
    request(
        guard,
        id,
        "tools/call",
        &json!({"name": name, "arguments": arguments}),
        budget,
    )
}

/// The first text block of a tool result.
pub(crate) fn tool_text(response: &Value) -> Result<&str, Failure> {
    response["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| protocol(format!("no text content in {response}")))
}

/// The first text block of a tool result, parsed as the JSON it carries.
pub(crate) fn tool_json(response: &Value) -> Result<Value, Failure> {
    let text = tool_text(response)?;
    serde_json::from_str(text).map_err(|error| protocol(format!("{error} in tool text {text}")))
}

fn notify(guard: &mut Guard, method: &str) -> Result<(), Failure> {
    send(guard, &json!({"jsonrpc": "2.0", "method": method}))
}

fn send(guard: &mut Guard, message: &Value) -> Result<(), Failure> {
    let line = serde_json::to_string(message)
        .map_err(|error| protocol(format!("the request is not serializable: {error}")))?;
    guard.send_line(&line)
}

/// Read until the response carrying `id` arrives or the budget expires.
fn receive(guard: &mut Guard, id: u64, budget: Duration) -> Result<Value, Failure> {
    let deadline = Instant::now() + budget;
    let wanted = json!(id);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = guard.read_line(remaining)?;
        let message: Value = serde_json::from_str(line)
            .map_err(|error| protocol(format!("{error} in server line {line}")))?;
        match message.get("id") == Some(&wanted) {
            true => return Ok(message),
            false => continue,
        }
    }
}
