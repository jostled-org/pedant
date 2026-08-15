//! Gate dispatch and the unchanged file/stdin capability owner.
//!
//! Dispatch is the first thing that happens: a project run never touches the
//! file analyzer, and a file or stdin run never loads a project, builds a
//! graph, or names a topology type.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::process::ExitCode;

use pedant_core::GateConfig;
use pedant_core::gate::{GateInputSummary, GateVerdict, evaluate_gate_rules};
use pedant_types::Language;

use crate::analysis::{AnalysisAccumulator, AnalysisContext, AnalysisRequest, run_analysis};
use crate::config::GateArgs;

use super::project;

/// Run the gate in whichever of its three input modes the caller selected.
pub(crate) fn run(args: GateArgs, stderr: &mut impl Write) -> ExitCode {
    match args.input.project.as_deref() {
        Some(root) => run_project(root, &args, stderr),
        None => run_files(args, stderr),
    }
}

/// The Cargo-project mode: judge declared module boundaries, or exit 2.
fn run_project(root: &str, args: &GateArgs, stderr: &mut impl Write) -> ExitCode {
    let report = match project::evaluate(
        root,
        args.config.as_deref(),
        crate::command::semantic_enabled(args),
    ) {
        Ok(report) => report,
        Err(error) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            return ExitCode::from(2);
        }
    };
    let mut stdout = io::stdout().lock();
    if let Err(exit) = crate::output::write_project_gate_output(
        args.format,
        report.tier,
        &report.targets,
        &report.verdicts,
        &mut stdout,
        stderr,
    ) {
        return exit;
    }
    crate::output::compute_exit_code(false, false, &report.verdicts)
}

/// The file and stdin mode: capability and data-flow rules, unchanged.
fn run_files(args: GateArgs, stderr: &mut impl Write) -> ExitCode {
    let file_config = match crate::command::load_file_config(args.config.as_deref(), stderr) {
        Ok(cfg) => cfg,
        Err(exit) => return exit,
    };
    let base_config = crate::command::check_config_from(file_config.as_ref());
    let files =
        match crate::command::resolve_input_files(&args.input.files, args.input.stdin, stderr) {
            Ok(files) => files,
            Err(exit) => return exit,
        };
    let mut acc = AnalysisAccumulator::with_capacity(files.len());
    let semantic = crate::analysis::load_semantic_if_requested(
        crate::command::semantic_enabled(&args),
        &files,
        stderr,
    );
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: file_config.as_ref(),
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &files,
        stdin: args.input.stdin,
        collect_source_hash: false,
    };
    std::mem::drop(run_analysis(&request, &ctx, &mut acc, stderr));
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let defaults = GateConfig::default();
    let gate_config = file_config.as_ref().map_or(&defaults, |cfg| &cfg.gate);
    let verdicts = evaluate_gate(
        &acc.findings,
        &acc.data_flows,
        gate_config,
        args.cross_language,
    );
    let mut stdout = io::stdout().lock();
    if let Err(exit) = crate::output::write_gate_output(
        args.format,
        analysis_tier,
        acc.had_error,
        &verdicts,
        &mut stdout,
        stderr,
    ) {
        return exit;
    }
    crate::output::compute_exit_code(acc.had_error, false, &verdicts)
}

fn evaluate_gate(
    findings: &[pedant_types::CapabilityFinding],
    flows: &[pedant_core::ir::DataFlowFact],
    config: &GateConfig,
    cross_language: bool,
) -> Box<[GateVerdict]> {
    match cross_language {
        true => {
            let summary = GateInputSummary::from_analysis(findings, flows);
            evaluate_gate_rules(&summary, config)
        }
        false => evaluate_gate_per_language(findings, flows, config),
    }
}

fn evaluate_gate_per_language(
    findings: &[pedant_types::CapabilityFinding],
    flows: &[pedant_core::ir::DataFlowFact],
    config: &GateConfig,
) -> Box<[GateVerdict]> {
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
