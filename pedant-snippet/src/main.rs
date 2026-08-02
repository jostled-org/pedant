//! CLI and MCP entry point for the pedant-snippet tool.

mod cli;
mod command;
mod server;
mod tool;

use clap::Parser;
use pedant_snippet::SnippetError;

use crate::cli::Cli;

/// Why a subcommand could not finish.
///
/// Absence is not a failure: a location in no declaration prints an absent
/// result and exits zero. Every variant here means the command produced no
/// answer at all. It lives at the crate root so the transports report failures
/// in one vocabulary without depending on each other.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommandError {
    /// The source file could not be read.
    #[error(transparent)]
    Extract(#[from] SnippetError),
    /// The result could not be encoded as JSON.
    #[error("failed to serialize the result: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Standard output rejected the result.
    #[error("failed to write the result: {0}")]
    Write(#[source] std::io::Error),
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

/// A failure on its way to the operator.
///
/// Returning `Result` from `main` reports the error and terminates non-zero
/// without this crate naming any process API, which keeps its capability
/// profile read-only. The runtime reports through `Debug`, so this wrapper
/// forwards to `Display` and the operator reads the sentence, not the struct.
struct Reported(CommandError);

impl std::fmt::Debug for Reported {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

fn main() -> Result<(), Reported> {
    command::run(Cli::parse().command).map_err(Reported)
}
