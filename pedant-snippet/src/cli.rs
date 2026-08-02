//! The command-line surface: subcommands, arguments, and output format.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// The `pedant-snippet` command line.
#[derive(Parser, Debug)]
#[command(
    name = "pedant-snippet",
    version,
    about = "Extract the source declaration enclosing one file location"
)]
pub(crate) struct Cli {
    /// The transport to run.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// One transport over the same extraction operation.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Print the declaration enclosing one location.
    Extract(ExtractArgs),
    /// Serve the extraction tool over stdio MCP.
    Mcp,
}

/// Everything `extract` needs to answer one question.
#[derive(Args, Debug)]
pub(crate) struct ExtractArgs {
    /// File to read, absolute or relative to the working directory.
    #[arg(long)]
    pub(crate) file: PathBuf,
    /// One-based line number.
    #[arg(long)]
    pub(crate) line: usize,
    /// One-based UTF-8 byte offset within the line.
    #[arg(long)]
    pub(crate) column: Option<usize>,
    /// How to print the result.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub(crate) format: Format,
}

/// How `extract` prints its result.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum Format {
    /// The `{ "unit": ... }` envelope, with a trailing newline.
    Json,
    /// The declaration's exact text, with nothing added.
    Text,
}
