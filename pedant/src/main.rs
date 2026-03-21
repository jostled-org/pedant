mod config;
mod reporter;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

use clap::Parser;
use pedant_core::AnalysisResult;
use pedant_core::check_config::{CheckConfig, ConfigFile, find_config_file, load_config_file};
use pedant_core::checks::ALL_CHECKS;
use pedant_core::hash::compute_source_hash;
use pedant_core::lint::analyze;
use pedant_core::violation::{Violation, lookup_rationale};
use pedant_types::{
    AnalysisTier, AttestationContent, CapabilityDiff, CapabilityFinding, CapabilityProfile,
};

use crate::config::Cli;
use crate::reporter::Reporter;

#[derive(Debug, thiserror::Error)]
enum ProcessError {
    #[error("failed to read stdin: {0}")]
    StdinRead(#[source] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] pedant_core::ParseError),
    #[error("failed to read file {path}: {source}")]
    FileRead {
        path: Box<str>,
        #[source]
        source: std::io::Error,
    },
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
}

struct AnalysisAccumulator {
    violations: Vec<Violation>,
    findings: Vec<CapabilityFinding>,
    had_error: bool,
}

fn report_error(stderr: &mut impl Write, msg: std::fmt::Arguments<'_>) {
    let _ = writeln!(stderr, "{msg}");
}

impl AnalysisAccumulator {
    fn new() -> Self {
        Self {
            violations: Vec::new(),
            findings: Vec::new(),
            had_error: false,
        }
    }

    fn handle(
        &mut self,
        result: Result<AnalysisResult, ProcessError>,
        context: &str,
        stderr: &mut impl Write,
    ) {
        match result {
            Ok(r) => {
                self.violations.extend(r.violations);
                self.findings.extend(r.capabilities.findings);
            }
            Err(e) => {
                report_error(stderr, format_args!("{context}: {e}"));
                self.had_error = true;
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stderr = io::stderr().lock();

    if cli.list_checks {
        return run_print_checks_list(&mut stderr);
    }

    if let Some(ref code) = cli.explain {
        return print_explain(code, &mut stderr);
    }

    if cli.diff.len() == 2 {
        return run_diff(&cli.diff, &mut stderr);
    }

    let file_config = load_file_config(&cli, &mut stderr);
    let base_config = cli.to_check_config(file_config.as_ref());
    let mut acc = AnalysisAccumulator::new();

    let source_hash = match (cli.attestation, cli.stdin) {
        (true, true) => attest_stdin(&base_config, &mut acc, &mut stderr),
        (true, false) => Some(attest_files(
            &cli,
            &base_config,
            file_config.as_ref(),
            &mut acc,
            &mut stderr,
        )),
        (false, true) => {
            acc.handle(process_stdin(&base_config), "error", &mut stderr);
            None
        }
        (false, false) => {
            process_files(
                &cli,
                &base_config,
                file_config.as_ref(),
                &mut acc,
                &mut stderr,
            );
            None
        }
    };

    let reporter = Reporter::new(cli.format, cli.quiet);
    let mut stdout = io::stdout().lock();
    if let Err(e) = reporter.report(&acc.violations, &mut stdout) {
        report_error(&mut stderr, format_args!("error writing output: {e}"));
        return ExitCode::from(2);
    }

    let output_result = match (cli.attestation, cli.capabilities) {
        (true, _) => {
            let Some(hash) = source_hash else {
                return ExitCode::from(2);
            };
            let Some(crate_name) = cli.crate_name.as_deref() else {
                return ExitCode::from(2);
            };
            let Some(crate_version) = cli.crate_version.as_deref() else {
                return ExitCode::from(2);
            };
            write_attestation(
                &mut stdout,
                &mut stderr,
                acc.findings,
                hash,
                Box::from(crate_name),
                Box::from(crate_version),
            )
        }
        (false, true) => write_capabilities(&mut stdout, &mut stderr, acc.findings),
        (false, false) => Ok(()),
    };
    if let Err(exit) = output_result {
        return exit;
    }

    match (acc.had_error, acc.violations.is_empty()) {
        (true, _) => ExitCode::from(2),
        (false, false) => ExitCode::from(1),
        (false, true) => ExitCode::from(0),
    }
}

fn attest_stdin(
    config: &CheckConfig,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    let source = match read_stdin_source() {
        Ok(s) => s,
        Err(e) => {
            report_error(stderr, format_args!("error: {e}"));
            acc.had_error = true;
            return None;
        }
    };
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("<stdin>"), Arc::from(source.as_str()));
    acc.handle(
        analyze("<stdin>", &source, config).map_err(ProcessError::from),
        "error",
        stderr,
    );
    Some(compute_source_hash(&sources))
}

fn attest_files(
    cli: &Cli,
    base_config: &CheckConfig,
    file_config: Option<&ConfigFile>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Box<str> {
    let mut sources = BTreeMap::new();
    for file_path in &cli.files {
        let Some(cfg) = base_config.resolve_for_path(file_path, file_config) else {
            continue;
        };
        read_and_analyze(file_path, &cfg, &mut sources, acc, stderr);
    }
    compute_source_hash(&sources)
}

fn read_and_analyze(
    file_path: &str,
    config: &CheckConfig,
    sources: &mut BTreeMap<Arc<str>, Arc<str>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let source = match fs::read_to_string(file_path) {
        Ok(s) => s,
        Err(e) => {
            report_error(
                stderr,
                format_args!("{file_path}: failed to read file: {e}"),
            );
            acc.had_error = true;
            return;
        }
    };
    sources.insert(Arc::from(file_path), Arc::from(source.as_str()));
    acc.handle(
        analyze(file_path, &source, config).map_err(ProcessError::from),
        file_path,
        stderr,
    );
}

fn process_files(
    cli: &Cli,
    base_config: &CheckConfig,
    file_config: Option<&ConfigFile>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    for file_path in &cli.files {
        let Some(cfg) = base_config.resolve_for_path(file_path, file_config) else {
            continue;
        };
        acc.handle(process_file(file_path, &cfg), file_path, stderr);
    }
}

fn load_file_config(cli: &Cli, stderr: &mut impl Write) -> Option<ConfigFile> {
    let config_path = cli
        .config
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(find_config_file)?;

    match load_config_file(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            report_error(stderr, format_args!("warning: {e}"));
            None
        }
    }
}

fn read_stdin_source() -> Result<String, ProcessError> {
    let mut source = String::new();
    io::stdin()
        .read_to_string(&mut source)
        .map_err(ProcessError::StdinRead)?;
    Ok(source)
}

fn process_stdin(config: &CheckConfig) -> Result<AnalysisResult, ProcessError> {
    let source = read_stdin_source()?;
    Ok(analyze("<stdin>", &source, config)?)
}

fn process_file(file_path: &str, config: &CheckConfig) -> Result<AnalysisResult, ProcessError> {
    let source = fs::read_to_string(file_path).map_err(|e| ProcessError::FileRead {
        path: file_path.into(),
        source: e,
    })?;
    Ok(analyze(file_path, &source, config)?)
}

const SPEC_VERSION: &str = "0.1.0";

/// Returns seconds since Unix epoch. Falls back to 0 if the system clock
/// is before 1970, which cannot happen on any supported platform.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_attestation(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
    source_hash: Box<str>,
    crate_name: Box<str>,
    crate_version: Box<str>,
) -> Result<(), ExitCode> {
    let attestation = AttestationContent {
        spec_version: Box::from(SPEC_VERSION),
        source_hash,
        crate_name,
        crate_version,
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: current_timestamp(),
        profile: CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
    };
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, &attestation) {
        report_error(stderr, format_args!("error writing attestation: {e}"));
        return Err(ExitCode::from(2));
    }
    let _ = writeln!(stdout);
    Ok(())
}

fn write_capabilities(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
) -> Result<(), ExitCode> {
    let profile = CapabilityProfile {
        findings: findings.into_boxed_slice(),
    };
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, &profile) {
        report_error(stderr, format_args!("error writing capabilities: {e}"));
        return Err(ExitCode::from(2));
    }
    let _ = writeln!(stdout);
    Ok(())
}

fn run_print_checks_list(stderr: &mut impl Write) -> ExitCode {
    match print_checks_list() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(stderr, format_args!("error writing output: {e}"));
            ExitCode::from(2)
        }
    }
}

fn print_checks_list() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Available checks:\n")?;
    writeln!(stdout, "{:<20} {:<8} DESCRIPTION", "CODE", "LLM?")?;
    writeln!(stdout, "{:-<20} {:-<8} {:-<30}", "", "", "")?;

    for check in ALL_CHECKS {
        let llm_marker = match check.llm_specific {
            true => "yes",
            false => "",
        };
        writeln!(
            stdout,
            "{:<20} {:<8} {}",
            check.code, llm_marker, check.description
        )?;
    }

    writeln!(stdout)?;
    writeln!(stdout, "Use --explain <CODE> for detailed rationale.")
}

fn print_explain(code: &str, stderr: &mut impl Write) -> ExitCode {
    let Some(rationale) = lookup_rationale(code) else {
        report_error(stderr, format_args!("Unknown check: {code}"));
        report_error(
            stderr,
            format_args!("Use --list-checks to see available checks."),
        );
        return ExitCode::from(1);
    };

    let result = write_explain(code, &rationale);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(stderr, format_args!("error writing output: {e}"));
            ExitCode::from(2)
        }
    }
}

fn load_profile(path: &str) -> Result<CapabilityProfile, ProcessError> {
    let data = fs::read_to_string(path).map_err(|e| ProcessError::DiffRead {
        path: path.into(),
        source: e,
    })?;

    let value: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| ProcessError::DiffParse {
            path: path.into(),
            source: e,
        })?;

    match value.get("spec_version") {
        Some(_) => {
            let att: AttestationContent =
                serde_json::from_value(value).map_err(|e| ProcessError::DiffParse {
                    path: path.into(),
                    source: e,
                })?;
            Ok(att.profile)
        }
        None => serde_json::from_value(value).map_err(|e| ProcessError::DiffParse {
            path: path.into(),
            source: e,
        }),
    }
}

fn load_diff_profiles(
    old_path: &str,
    new_path: &str,
    stderr: &mut impl Write,
) -> Option<(CapabilityProfile, CapabilityProfile)> {
    let old = load_profile(old_path)
        .map_err(|e| report_error(stderr, format_args!("{e}")))
        .ok()?;
    let new = load_profile(new_path)
        .map_err(|e| report_error(stderr, format_args!("{e}")))
        .ok()?;
    Some((old, new))
}

fn run_diff(paths: &[String], stderr: &mut impl Write) -> ExitCode {
    let Some((old, new)) = load_diff_profiles(&paths[0], &paths[1], stderr) else {
        return ExitCode::from(2);
    };

    let diff = CapabilityDiff::compute(&old, &new);
    let mut stdout = io::stdout().lock();

    if let Err(e) = serde_json::to_writer_pretty(&mut stdout, &diff) {
        report_error(stderr, format_args!("error writing diff: {e}"));
        return ExitCode::from(2);
    }
    let _ = writeln!(stdout);

    match diff.is_empty() {
        true => ExitCode::from(0),
        false => ExitCode::from(1),
    }
}

fn write_explain(code: &str, rationale: &pedant_core::violation::CheckRationale) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Check: {code}\n")?;
    writeln!(stdout, "Problem:")?;
    writeln!(stdout, "  {}\n", rationale.problem)?;
    writeln!(stdout, "Fix:")?;
    writeln!(stdout, "  {}\n", rationale.fix)?;
    writeln!(stdout, "Exception:")?;
    writeln!(stdout, "  {}\n", rationale.exception)?;
    let llm_note = match rationale.llm_specific {
        true => "Yes - particularly relevant for LLM-generated code",
        false => "No - general code quality check",
    };
    writeln!(stdout, "LLM-specific: {llm_note}")
}
