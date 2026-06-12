//! CLI interface for the pedant linter and capability analyzer.

mod analysis;
mod command;
mod config;
mod explain;
mod output;
mod reporter;
mod supply_chain;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use crate::config::Cli;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessError {
    #[error("failed to read stdin: {0}")]
    StdinRead(#[source] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] pedant_core::ParseError),
    #[error("failed to read diff input {path}: {source}")]
    DiffRead {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse diff input {path}: {source}")]
    DiffParse {
        path: Box<str>,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to compute current timestamp: {source}")]
    Timestamp {
        #[source]
        source: std::time::SystemTimeError,
    },
    #[error("failed for crate root {crate_root}: {source}")]
    BuildScriptDiscovery {
        crate_root: Box<str>,
        #[source]
        source: pedant_core::lint::LintError,
    },
}

pub(crate) fn report_error(stderr: &mut impl Write, msg: std::fmt::Arguments<'_>) {
    let _ = writeln!(stderr, "{msg}");
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stderr = io::stderr().lock();
    command::run(cli.command, &mut stderr)
}
