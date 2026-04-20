//! CLI interface for the pedant linter and capability analyzer.

mod analysis;
mod config;
mod explain;
mod output;
mod reporter;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use pedant_core::check_config::{find_config_file, load_config_file};
use pedant_core::gate::{self, GateInputSummary, evaluate_gate_rules};
use pedant_types::Language;

use crate::analysis::{AnalysisAccumulator, AnalysisContext, run_analysis};
use crate::config::Cli;
use crate::config::OutputFormat;
use crate::reporter::Reporter;

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

    if cli.list_checks {
        return explain::run_print_checks_list(&mut stderr);
    }

    if let Some(ref code) = cli.explain {
        return explain::print_explain(code, &mut stderr);
    }

    if let [old_path, new_path] = cli.diff.as_slice() {
        return output::run_diff(old_path, new_path, &mut stderr);
    }

    let file_config = match load_file_config(&cli, &mut stderr) {
        Ok(cfg) => cfg,
        Err(exit) => return exit,
    };
    let base_config = cli.to_check_config(file_config.as_ref());
    let mut acc = AnalysisAccumulator::with_capacity(cli.files.len());

    let semantic = analysis::load_semantic_if_requested(&cli, &mut stderr);

    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: file_config.as_ref(),
        semantic: semantic.as_ref(),
    };

    let source_hash = run_analysis(&cli, &ctx, &mut acc, &mut stderr);
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);

    // Evaluate gate rules before findings are consumed by attestation/capabilities output.
    let default_gate = pedant_core::GateConfig::default();
    let gate_verdicts = match cli.gate {
        true => {
            let gate_config = file_config.as_ref().map_or(&default_gate, |fc| &fc.gate);
            evaluate_gate(
                &acc.findings,
                &acc.data_flows,
                gate_config,
                cli.cross_language,
            )
        }
        false => Box::new([]),
    };

    let reporter = Reporter::new(cli.quiet);
    let mut stdout = io::stdout().lock();
    match cli.format {
        OutputFormat::Json => {
            return write_json_exit(
                &cli,
                source_hash,
                acc,
                analysis_tier,
                &gate_verdicts,
                &mut stdout,
                &mut stderr,
            );
        }
        OutputFormat::Text => {}
    }

    // When attestation or capabilities will produce JSON on stdout,
    // send violation and gate text to stderr to keep stdout clean.
    let json_on_stdout = cli.attestation || cli.capabilities;
    let violation_result = match json_on_stdout {
        true => reporter.report(&acc.violations, &mut stderr),
        false => reporter.report(&acc.violations, &mut stdout),
    };
    if let Err(e) = violation_result {
        report_error(&mut stderr, format_args!("error writing output: {e}"));
        return ExitCode::from(2);
    }

    if let Err(exit) = output::dispatch_output(
        &cli,
        source_hash,
        acc.findings,
        analysis_tier,
        &mut stdout,
        &mut stderr,
    ) {
        return exit;
    }

    let gate_result = match json_on_stdout {
        true => reporter.report_gate(&gate_verdicts, &mut stderr),
        false => reporter.report_gate(&gate_verdicts, &mut stdout),
    };
    if let (true, Err(e)) = (cli.gate, gate_result) {
        report_error(&mut stderr, format_args!("error writing gate output: {e}"));
        return ExitCode::from(2);
    }

    output::compute_exit_code(acc.had_error, acc.violations.is_empty(), &gate_verdicts)
}

fn write_json_exit(
    cli: &Cli,
    source_hash: Option<Box<str>>,
    acc: AnalysisAccumulator,
    analysis_tier: pedant_types::AnalysisTier,
    gate_verdicts: &[pedant_core::gate::GateVerdict],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCode {
    let result = output::write_json_analysis_output(
        output::JsonOutputContext {
            cli,
            source_hash,
            violations: &acc.violations,
            findings: acc.findings,
            analysis_tier,
            gate_verdicts,
            had_error: acc.had_error,
        },
        stdout,
        stderr,
    );
    match result {
        Ok(()) => {
            output::compute_exit_code(acc.had_error, acc.violations.is_empty(), gate_verdicts)
        }
        Err(exit) => exit,
    }
}

fn load_file_config(
    cli: &Cli,
    stderr: &mut impl Write,
) -> Result<Option<pedant_core::check_config::ConfigFile>, ExitCode> {
    let explicit = cli.config.is_some();
    let config_path = match (cli.config.as_deref(), find_config_file()) {
        (Some(path), _) => Some(std::path::PathBuf::from(path)),
        (None, Ok(path)) => path,
        (None, Err(error)) => {
            report_error(stderr, format_args!("warning: {error}"));
            return Ok(None);
        }
    };

    let Some(config_path) = config_path else {
        return Ok(None);
    };

    match (load_config_file(&config_path), explicit) {
        (Ok(cfg), _) => Ok(Some(cfg)),
        (Err(e), true) => {
            report_error(stderr, format_args!("error: {e}"));
            Err(ExitCode::from(2))
        }
        (Err(e), false) => {
            report_error(stderr, format_args!("warning: {e}"));
            Ok(None)
        }
    }
}

/// Evaluate gate rules, grouping by language unless `cross_language` is set.
///
/// Per-language evaluation prevents findings from different languages from
/// combining to trigger false-positive capability-combination rules.
fn evaluate_gate(
    findings: &[pedant_types::CapabilityFinding],
    flows: &[pedant_core::ir::DataFlowFact],
    config: &pedant_core::GateConfig,
    cross_language: bool,
) -> Box<[gate::GateVerdict]> {
    match cross_language {
        true => {
            let summary = GateInputSummary::from_analysis(findings, flows);
            evaluate_gate_rules(&summary, config)
        }
        false => evaluate_gate_per_language(findings, flows, config),
    }
}

/// Group findings by language and evaluate gate rules independently per group.
///
/// Data flows are only included in the Rust (language=None) group since flow
/// analysis is only available for Rust source.
fn evaluate_gate_per_language(
    findings: &[pedant_types::CapabilityFinding],
    flows: &[pedant_core::ir::DataFlowFact],
    config: &pedant_core::GateConfig,
) -> Box<[gate::GateVerdict]> {
    let mut groups: BTreeMap<Option<Language>, Vec<&pedant_types::CapabilityFinding>> =
        BTreeMap::new();
    for finding in findings {
        groups.entry(finding.language).or_default().push(finding);
    }

    let mut all_verdicts = Vec::new();
    for (language, group_findings) in &groups {
        // Data flows come from Rust analysis only (language=None).
        let group_flows: &[pedant_core::ir::DataFlowFact] = match language {
            None => flows,
            Some(_) => &[],
        };
        let summary = GateInputSummary::from_refs(group_findings, group_flows);
        all_verdicts.extend(evaluate_gate_rules(&summary, config).into_vec());
    }
    all_verdicts.into_boxed_slice()
}
