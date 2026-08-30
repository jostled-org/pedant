//! CLI and MCP entry point for the pedant-snippet code-intelligence tool.

mod cli;
mod command;
mod operation;
mod registry;
mod render;
mod request;
mod server;
mod token;

use std::process::ExitCode;

use clap::Parser;
use pedant_snippet::LiveIndexError;

use crate::cli::Cli;
use crate::command::Outcome;

/// The status a command that could not answer exits with.
///
/// Two statuses, and no third. Clap already exits two for a malformed command
/// line, and an operator scripting this binary reads "the question was not
/// answered" from one number rather than from a table of reasons — the typed
/// diagnostic on stderr is where the reason lives.
const REFUSED: u8 = 2;

/// Why a command could not finish.
///
/// A refused query is not here: it is an answer about the repository, and it
/// travels as a serialized envelope on both transports. Every variant below is a
/// failure of this process rather than of the question.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommandError {
    /// The result could not be encoded as JSON.
    #[error("failed to serialize the result: {0}")]
    Serialize(#[source] serde_json::Error),
    /// Standard output rejected the result.
    #[error("failed to write the result: {0}")]
    Write(#[source] std::io::Error),
    /// The live index could not be opened, watched, or read.
    #[error(transparent)]
    Live(#[from] LiveIndexError),
    /// The async runtime the MCP transport needs could not start.
    #[error("failed to start the runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// The MCP handshake never completed.
    ///
    /// The transport's error is boxed: at over five hundred bytes it would
    /// otherwise set the size of every `Result` this crate returns.
    #[error("the MCP server failed to start: {0}")]
    ServerStart(#[source] Box<rmcp::service::ServerInitializeError>),
    /// The MCP server task ended abnormally.
    #[error("the MCP server stopped with an error: {0}")]
    ServerStop(#[source] tokio::task::JoinError),
    /// The MCP server was cancelled before its client disconnected.
    #[error("the MCP server was cancelled before the client disconnected")]
    ServerCancelled,
    /// The MCP server stopped for a reason this build does not name.
    ///
    /// `rmcp::service::QuitReason` is `#[non_exhaustive]`, so a reason added by
    /// a later release arrives here and is reported rather than read as a clean
    /// shutdown.
    #[error("the MCP server stopped unexpectedly: {0}")]
    ServerQuit(Box<str>),
}

/// Run one command and state its outcome as an exit status.
///
/// Every diagnostic is written by the command itself, so nothing is reported
/// here: the runtime's own `Debug` rendering of a returned error would print a
/// struct where the operator is already holding a typed envelope.
fn main() -> ExitCode {
    match command::run(Cli::parse().command) {
        Outcome::Answered => ExitCode::SUCCESS,
        Outcome::Refused => ExitCode::from(REFUSED),
    }
}
