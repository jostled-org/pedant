//! Running one command: which index, which question, and what the operator
//! reads.
//!
//! Every command but `mcp` is the same three steps — build one index, ask it one
//! question, print the answer — so the steps are written once and the command
//! supplies only the root, the question, and the format. That is also what makes
//! the exit contract one sentence rather than nine: an answer exits zero, and
//! every refusal writes its typed diagnostic to stderr and exits two.

use std::io::Write;

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeIntelligenceState, FatalReport,
    LiveIndexError, QueryFailure,
};

use crate::CommandError;
use crate::cli::{Command, Format, HostArgs, Question};
use crate::operation::Answered;
use crate::render;
use crate::request::{self, Requested};
use crate::server;

/// What one command produced, once every diagnostic has been written.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The command answered. Nothing was written to stderr.
    Answered,
    /// The command refused, and said why on stderr.
    Refused,
}

/// Run one command to completion.
///
/// Every failure is reported here rather than propagated, because the operator
/// reads one diagnostic and the caller reads one outcome. A failure that reached
/// the runtime would print a `Debug` rendering of a struct instead.
pub(crate) fn run(command: Command) -> Outcome {
    match command {
        Command::Mcp(host) => served(&host),
        Command::Answer(question) => asked(&question),
    }
}

/// Serve every question over stdio until the client disconnects.
///
/// A first build that refuses is reported as the same typed envelope every
/// other command writes for the same classification. The server indexes before
/// it accepts a handshake, so that refusal is the one an operator reads instead
/// of a session — and reading it in a different shape from the CLI's would make
/// one product state one failure two ways.
fn served(host: &HostArgs) -> Outcome {
    match server::serve_stdio(host) {
        Ok(()) => Outcome::Answered,
        Err(CommandError::Live(LiveIndexError::Build(failure))) => {
            diagnosed(&FatalReport::of(&failure), &failure)
        }
        Err(failure) => refused(&failure.to_string()),
    }
}

/// Build one index, ask it one question, and print the answer.
fn asked(question: &Question) -> Outcome {
    let requested = request::requested(question);
    match built(&requested) {
        Ok(state) => answered(&requested, &state),
        Err(failure) => diagnosed(&FatalReport::of(&failure), &failure),
    }
}

/// The index one request states.
fn built(requested: &Requested<'_>) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
    let host: &HostArgs = requested.host;
    CodeIntelligenceIndex::build(&host.root, &host.projects, host.limits())
}

/// Ask one built state one question, and print or diagnose the result.
fn answered(requested: &Requested<'_>, state: &CodeIntelligenceState) -> Outcome {
    match requested.operation.answered(state) {
        Ok(answer) => printed(&answer, requested.format),
        Err(failure) => diagnosed(&QueryFailure::of(state, &failure), &failure),
    }
}

/// Print one answer in the requested format, and exit zero.
fn printed(answer: &Answered, format: Format) -> Outcome {
    match rendered(answer, format) {
        Ok(bytes) => written(&bytes),
        Err(failure) => refused(&failure.to_string()),
    }
}

/// One answer in the requested format, exactly as it will be written.
///
/// The JSON rendering ends in a newline and the text rendering does not: a table
/// already terminates each of its rows, and a structure's projection is the
/// file's own bytes, which anything appended would no longer be.
///
/// Both renderings are handed over as the `String` they were built in. The
/// terminator is pushed onto the serializer's own buffer and the whole thing is
/// written and dropped, so every reshaping between here and the write — a
/// `format!` that copies the document to add one byte, an `into_boxed_str` that
/// reallocates it to shed a capacity — is a copy of the answer nothing reads.
fn rendered(answer: &Answered, format: Format) -> Result<String, CommandError> {
    match format {
        Format::Json => answer
            .json()
            .map(|mut json| {
                json.push('\n');
                json
            })
            .map_err(CommandError::Serialize),
        Format::Text => Ok(render::text(answer)),
    }
}

/// Write one rendered answer to standard output, byte for byte.
///
/// The lock, the write, the flush, and the outcome in one body. Split in two,
/// both halves carried this same sentence and the second existed only to turn
/// the first one's `Result` into an [`Outcome`].
fn written(rendered: &str) -> Outcome {
    let mut stdout = std::io::stdout().lock();
    let emitted = stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush());
    match emitted {
        Ok(()) => Outcome::Answered,
        Err(failure) => refused(&CommandError::Write(failure).to_string()),
    }
}

/// Write one serialized refusal to stderr.
///
/// The envelope is rendered by [`render::refusal`], which the MCP transport also
/// sends, so an operator and a client read one refusal in one shape.
fn diagnosed(report: &impl serde::Serialize, error: &CodeIntelligenceError) -> Outcome {
    refused(&render::refusal(report, error))
}

/// Write one diagnostic line to stderr and refuse.
///
/// A stderr that will not take the diagnostic changes nothing: the command
/// already refused, and the exit status still says so, which is why the write
/// is dropped rather than reported.
fn refused(diagnostic: &str) -> Outcome {
    let mut stderr = std::io::stderr().lock();
    drop(writeln!(stderr, "{diagnostic}"));
    Outcome::Refused
}
