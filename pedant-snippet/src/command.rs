//! Subcommand execution and the exact `extract` output.

use std::io::Write;

use pedant_snippet::{Extraction, Location, SourceUnit, extract_path};

use crate::CommandError;
use crate::cli::{Command, ExtractArgs, Format};
use crate::server;

/// What the text format prints when no declaration contains the location.
///
/// Every terminator this module writes is appended at the call site, so the
/// output shape is readable without opening a constant.
const NO_UNIT: &str = "no enclosing unit";

/// Run one subcommand.
pub(crate) fn run(command: Command) -> Result<(), CommandError> {
    match command {
        Command::Extract(args) => extract(&args),
        Command::Mcp => server::serve_stdio(),
    }
}

/// Extract one declaration and print it in the requested format.
fn extract(args: &ExtractArgs) -> Result<(), CommandError> {
    let at = Location {
        line: args.line,
        column: args.column,
    };
    let unit = extract_path(&args.file, at)?;
    match args.format {
        Format::Json => {
            let json = Extraction { unit }.to_json()?;
            emit(&[&json, "\n"])
        }
        Format::Text => emit_text(unit.as_ref()),
    }
}

/// Print one declaration's exact bytes, or the sentence absence prints.
///
/// A present declaration is byte-exact, so nothing follows it. Absence is a
/// sentence about the run, so it ends like one.
fn emit_text(unit: Option<&SourceUnit>) -> Result<(), CommandError> {
    match unit {
        Some(unit) => emit(&[&unit.text]),
        None => emit(&[NO_UNIT, "\n"]),
    }
}

/// Write one rendered result to standard output, byte for byte.
fn emit(parts: &[&str]) -> Result<(), CommandError> {
    let mut stdout = std::io::stdout().lock();
    for part in parts {
        stdout
            .write_all(part.as_bytes())
            .map_err(CommandError::Write)?;
    }
    stdout.flush().map_err(CommandError::Write)
}
