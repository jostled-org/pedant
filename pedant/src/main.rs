//! CLI interface for the pedant linter and capability analyzer.

mod analysis;
mod config;
mod explain;
mod output;
mod reporter;
mod supply_chain;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use pedant_core::check_config::{CheckConfig, ConfigFile, find_config_file, load_config_file};
use pedant_core::gate::{self, GateInputSummary, evaluate_gate_rules};
use pedant_types::Language;

use crate::analysis::{AnalysisAccumulator, AnalysisContext, AnalysisRequest, run_analysis};
use crate::config::{
    AttestationArgs, CapabilitiesArgs, CheckArgs, Cli, Command, ConfigArgs, GateArgs,
    SupplyChainCommand,
};

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

    match cli.command {
        Command::ListChecks => explain::run_print_checks_list(&mut stderr),
        Command::Explain(args) => explain::print_explain(&args.code, &mut stderr),
        Command::Diff(args) => output::run_diff(&args.old, &args.new, &mut stderr),
        Command::Check(args) => run_check(args, &mut stderr),
        Command::Capabilities(args) => run_capabilities(args, &mut stderr),
        Command::Attestation(args) => run_attestation(args, &mut stderr),
        Command::Gate(args) => run_gate(args, &mut stderr),
        Command::SupplyChain(args) => run_supply_chain(args.command, &mut stderr),
    }
}

fn run_supply_chain(command: SupplyChainCommand, stderr: &mut impl Write) -> ExitCode {
    match command {
        SupplyChainCommand::Init(write) => supply_chain::run_init(&write.baseline_path, stderr),
        SupplyChainCommand::Update(write) => supply_chain::run_update(&write.baseline_path, stderr),
        SupplyChainCommand::Verify(verify) => supply_chain::run_verify(
            &verify.baseline_path,
            verify.fail_on,
            verify.debug_package.as_deref(),
            stderr,
        ),
    }
}

fn run_check(args: CheckArgs, stderr: &mut impl Write) -> ExitCode {
    let file_config = match load_file_config(args.config.config.as_deref(), stderr) {
        Ok(cfg) => cfg,
        Err(exit) => return exit,
    };
    let base_config = args.config.to_check_config(file_config.as_ref());
    let mut acc = AnalysisAccumulator::with_capacity(args.input.files.len());
    let semantic = analysis::load_semantic_if_requested(
        semantic_enabled_check(&args),
        &args.input.files,
        stderr,
    );
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: file_config.as_ref(),
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &args.input.files,
        stdin: args.input.stdin,
        collect_source_hash: false,
    };
    let _ = run_analysis(&request, &ctx, &mut acc, stderr);
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let mut stdout = io::stdout().lock();
    if let Err(exit) = output::write_check_output(
        args.format,
        args.quiet,
        analysis_tier,
        acc.had_error,
        &acc.violations,
        &mut stdout,
        stderr,
    ) {
        return exit;
    }
    output::compute_exit_code(acc.had_error, acc.violations.is_empty(), &[])
}

fn run_capabilities(args: CapabilitiesArgs, stderr: &mut impl Write) -> ExitCode {
    let base_config = CheckConfig::default();
    let mut acc = AnalysisAccumulator::with_capacity(args.input.files.len());
    let semantic = analysis::load_semantic_if_requested(
        semantic_enabled_capabilities(&args),
        &args.input.files,
        stderr,
    );
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: None,
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &args.input.files,
        stdin: args.input.stdin,
        collect_source_hash: false,
    };
    let _ = run_analysis(&request, &ctx, &mut acc, stderr);
    let mut stdout = io::stdout().lock();
    if let Err(exit) = output::write_capabilities(&mut stdout, stderr, acc.findings) {
        return exit;
    }
    bool_exit_code(acc.had_error)
}

fn run_attestation(args: AttestationArgs, stderr: &mut impl Write) -> ExitCode {
    let base_config = CheckConfig::default();
    let mut acc = AnalysisAccumulator::with_capacity(args.input.files.len());
    let semantic = analysis::load_semantic_if_requested(
        semantic_enabled_attestation(&args),
        &args.input.files,
        stderr,
    );
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: None,
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &args.input.files,
        stdin: args.input.stdin,
        collect_source_hash: true,
    };
    let source_hash = run_analysis(&request, &ctx, &mut acc, stderr);
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let mut stdout = io::stdout().lock();
    if let Err(exit) = output::write_attestation_output(
        source_hash,
        acc.findings,
        &args.crate_name,
        &args.crate_version,
        analysis_tier,
        &mut stdout,
        stderr,
    ) {
        return exit;
    }
    bool_exit_code(acc.had_error)
}

fn run_gate(args: GateArgs, stderr: &mut impl Write) -> ExitCode {
    let file_config = match load_file_config(args.config.as_deref(), stderr) {
        Ok(cfg) => cfg,
        Err(exit) => return exit,
    };
    let base_config = ConfigArgs {
        max_depth: 3,
        config: None,
        no_nested_if: false,
        no_if_in_match: false,
        no_nested_match: false,
        no_match_in_if: false,
        no_else_chain: false,
    }
    .to_check_config(file_config.as_ref());
    let mut acc = AnalysisAccumulator::with_capacity(args.input.files.len());
    let semantic = analysis::load_semantic_if_requested(
        semantic_enabled_gate(&args),
        &args.input.files,
        stderr,
    );
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: file_config.as_ref(),
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &args.input.files,
        stdin: args.input.stdin,
        collect_source_hash: false,
    };
    let _ = run_analysis(&request, &ctx, &mut acc, stderr);
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let default_gate = pedant_core::GateConfig::default();
    let gate_config = file_config.as_ref().map_or(&default_gate, |cfg| &cfg.gate);
    let verdicts = evaluate_gate(
        &acc.findings,
        &acc.data_flows,
        gate_config,
        args.cross_language,
    );
    let mut stdout = io::stdout().lock();
    if let Err(exit) = output::write_gate_output(
        args.format,
        analysis_tier,
        acc.had_error,
        &verdicts,
        &mut stdout,
        stderr,
    ) {
        return exit;
    }
    output::compute_exit_code(acc.had_error, true, &verdicts)
}

fn load_file_config(
    explicit_config: Option<&str>,
    stderr: &mut impl Write,
) -> Result<Option<ConfigFile>, ExitCode> {
    let explicit = explicit_config.is_some();
    let config_path = match (explicit_config, find_config_file()) {
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
        (Err(error), true) => {
            report_error(stderr, format_args!("error: {error}"));
            Err(ExitCode::from(2))
        }
        (Err(error), false) => {
            report_error(stderr, format_args!("warning: {error}"));
            Ok(None)
        }
    }
}

#[cfg(feature = "semantic")]
fn semantic_enabled_check(args: &CheckArgs) -> bool {
    args.semantic
}

#[cfg(not(feature = "semantic"))]
fn semantic_enabled_check(_args: &CheckArgs) -> bool {
    false
}

#[cfg(feature = "semantic")]
fn semantic_enabled_capabilities(args: &CapabilitiesArgs) -> bool {
    args.semantic
}

#[cfg(not(feature = "semantic"))]
fn semantic_enabled_capabilities(_args: &CapabilitiesArgs) -> bool {
    false
}

#[cfg(feature = "semantic")]
fn semantic_enabled_attestation(args: &AttestationArgs) -> bool {
    args.semantic
}

#[cfg(not(feature = "semantic"))]
fn semantic_enabled_attestation(_args: &AttestationArgs) -> bool {
    false
}

#[cfg(feature = "semantic")]
fn semantic_enabled_gate(args: &GateArgs) -> bool {
    args.semantic
}

#[cfg(not(feature = "semantic"))]
fn semantic_enabled_gate(_args: &GateArgs) -> bool {
    false
}

fn bool_exit_code(had_error: bool) -> ExitCode {
    match had_error {
        true => ExitCode::from(2),
        false => ExitCode::from(0),
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
        let group_flows: &[pedant_core::ir::DataFlowFact] = match language {
            None => flows,
            Some(_) => &[],
        };
        let summary = GateInputSummary::from_refs(group_findings, group_flows);
        all_verdicts.extend(evaluate_gate_rules(&summary, config).into_vec());
    }
    all_verdicts.into_boxed_slice()
}
