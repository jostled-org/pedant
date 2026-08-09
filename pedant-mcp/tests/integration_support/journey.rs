//! The one stdio journey both completion proofs run.
//!
//! Start the real server at the stated root, dispatch the typed gate,
//! violation, and capability tools for the exact affected package set, tear
//! the child down, then write and re-read the receipt. The synthetic-input
//! test and the feature-gated final-tree adapter differ only in where their
//! `CompletionProofInputs` come from, so neither can drift into proving
//! something the other does not.

use serde_json::{Value, json};

use crate::process_guard::{BUDGET, Completed, Failure, Guard, Run, protocol};
use crate::protocol::{INDEXED_REPLY, call_tool, initialize, tool_json};
use crate::receipt::{CompletionProofInputs, QueryRecord, TYPED_TOOLS};

/// Run the journey end to end and leave a validated receipt behind.
pub(crate) fn run(inputs: &CompletionProofInputs) -> Result<(), String> {
    inputs.validate()?;
    let (queries, completed) = dispatch(inputs).map_err(|failure| failure.to_string())?;
    check_shutdown(&completed)?;
    crate::receipt::write(inputs, queries)?;
    crate::receipt::validate(inputs)
}

/// Ask every typed question once, then shut the server down.
///
/// The queries are collected while the child is live and the outcome is read
/// after teardown, so nothing asserts against a process still holding pipes.
fn dispatch(inputs: &CompletionProofInputs) -> Result<(Box<[QueryRecord]>, Completed), Failure> {
    let mut guard = Guard::spawn(&Run::server(&inputs.root))?;
    let collected = collect(&mut guard, &inputs.test_scope);
    let completed = guard.finish(BUDGET)?;
    Ok((collected?, completed))
}

fn collect(guard: &mut Guard, scope: &[Box<str>]) -> Result<Box<[QueryRecord]>, Failure> {
    initialize(guard, INDEXED_REPLY)?;
    let mut records = Vec::with_capacity(scope.len() * TYPED_TOOLS.len());
    for (package, tool) in scope
        .iter()
        .flat_map(|package| TYPED_TOOLS.map(|tool| (package, tool)))
    {
        let id = u64::try_from(records.len()).unwrap_or(0) + 2;
        records.push(query(guard, id, package, tool)?);
    }
    Ok(records.into_boxed_slice())
}

fn query(guard: &mut Guard, id: u64, package: &str, tool: &str) -> Result<QueryRecord, Failure> {
    let response = call_tool(guard, id, tool, &json!({"scope": package}), INDEXED_REPLY)?;
    let results = array_len(&tool_json(&response)?)
        .ok_or_else(|| protocol(format!("{tool} answered {package} with {response}")))?;
    Ok(QueryRecord {
        package: package.into(),
        tool: tool.into(),
        results,
    })
}

fn array_len(payload: &Value) -> Option<usize> {
    payload.as_array().map(Vec::len)
}

/// The server must have shut down on stdin EOF, not been killed for overrunning.
fn check_shutdown(completed: &Completed) -> Result<(), String> {
    match completed.success() {
        true => Ok(()),
        false => Err(format!(
            "the server did not exit cleanly on stdin EOF: {:?} {}",
            completed.outcome,
            completed.transcript()
        )),
    }
}
