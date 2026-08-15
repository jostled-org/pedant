use std::io::{self, Write};
use std::process::ExitCode;

use pedant_core::check_config::{CheckConfig, ConfigFile, find_config_file, load_config_file};

use crate::analysis::{AnalysisAccumulator, AnalysisContext, AnalysisRequest, run_analysis};
use crate::config::{
    AttestationArgs, CapabilitiesArgs, CheckArgs, Command, GateArgs, SupplyChainCommand,
};

pub(crate) trait SemanticArgs {
    fn semantic_enabled(&self) -> bool;
}

#[cfg(feature = "semantic")]
macro_rules! impl_semantic_args {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl SemanticArgs for $ty {
                fn semantic_enabled(&self) -> bool {
                    self.semantic
                }
            }
        )+
    };
}

#[cfg(not(feature = "semantic"))]
macro_rules! impl_semantic_args {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl SemanticArgs for $ty {
                fn semantic_enabled(&self) -> bool {
                    false
                }
            }
        )+
    };
}

impl_semantic_args!(CheckArgs, CapabilitiesArgs, AttestationArgs, GateArgs);

pub(crate) fn run(command: Command, stderr: &mut impl Write) -> ExitCode {
    match command {
        Command::ListChecks => crate::explain::run_print_checks_list(stderr),
        Command::Explain(args) => crate::explain::print_explain(&args.code, stderr),
        Command::Diff(args) => crate::output::run_diff(&args.old, &args.new, stderr),
        Command::Check(args) => run_check(args, stderr),
        Command::Capabilities(args) => run_capabilities(args, stderr),
        Command::Attestation(args) => run_attestation(args, stderr),
        Command::Gate(args) => crate::gate::run(args, stderr),
        Command::SupplyChain(args) => run_supply_chain(args.command, stderr),
    }
}

pub(crate) fn semantic_enabled(args: &impl SemanticArgs) -> bool {
    args.semantic_enabled()
}

/// Expand the caller's path arguments into the concrete file list to analyze.
///
/// Yields an empty list in stdin mode, where there are no paths to resolve.
pub(crate) fn resolve_input_files(
    files: &[String],
    stdin: bool,
    stderr: &mut impl Write,
) -> Result<Vec<String>, ExitCode> {
    match stdin {
        true => Ok(Vec::new()),
        false => crate::input::resolve(files).map_err(|error| {
            crate::report_error(stderr, format_args!("error: {error}"));
            ExitCode::from(2)
        }),
    }
}

/// The style configuration a command with no style flags of its own runs under.
pub(crate) fn check_config_from(file_config: Option<&ConfigFile>) -> CheckConfig {
    file_config.map_or_else(CheckConfig::default, CheckConfig::from_config_file)
}

fn run_supply_chain(command: SupplyChainCommand, stderr: &mut impl Write) -> ExitCode {
    match command {
        SupplyChainCommand::Init(write) => {
            crate::supply_chain::run_init(&write.baseline_path, stderr)
        }
        SupplyChainCommand::Update(write) => {
            crate::supply_chain::run_update(&write.baseline_path, stderr)
        }
        SupplyChainCommand::Verify(verify) => crate::supply_chain::run_verify(
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
    let files = match resolve_input_files(&args.input.files, args.input.stdin, stderr) {
        Ok(files) => files,
        Err(exit) => return exit,
    };
    let mut acc = AnalysisAccumulator::with_capacity(files.len());
    let semantic =
        crate::analysis::load_semantic_if_requested(semantic_enabled(&args), &files, stderr);
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
    if !args.input.stdin {
        crate::analysis::run_project_checks(&files, &base_config, &mut acc, stderr);
    }
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let mut stdout = io::stdout().lock();
    if let Err(exit) = crate::output::write_check_output(
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
    let has_deny_violation = acc.violations.iter().any(|v| v.severity.is_deny());
    crate::output::compute_exit_code(acc.had_error, has_deny_violation, &[])
}

fn run_capabilities(args: CapabilitiesArgs, stderr: &mut impl Write) -> ExitCode {
    let base_config = CheckConfig::default();
    let files = match resolve_input_files(&args.input.files, args.input.stdin, stderr) {
        Ok(files) => files,
        Err(exit) => return exit,
    };
    let mut acc = AnalysisAccumulator::with_capacity(files.len());
    let semantic =
        crate::analysis::load_semantic_if_requested(semantic_enabled(&args), &files, stderr);
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: None,
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &files,
        stdin: args.input.stdin,
        collect_source_hash: false,
    };
    std::mem::drop(run_analysis(&request, &ctx, &mut acc, stderr));
    let mut stdout = io::stdout().lock();
    if let Err(exit) = crate::output::write_capabilities(&mut stdout, stderr, acc.findings) {
        return exit;
    }
    bool_exit_code(acc.had_error)
}

fn run_attestation(args: AttestationArgs, stderr: &mut impl Write) -> ExitCode {
    let base_config = CheckConfig::default();
    let files = match resolve_input_files(&args.input.files, args.input.stdin, stderr) {
        Ok(files) => files,
        Err(exit) => return exit,
    };
    let mut acc = AnalysisAccumulator::with_capacity(files.len());
    let semantic =
        crate::analysis::load_semantic_if_requested(semantic_enabled(&args), &files, stderr);
    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: None,
        semantic: semantic.as_ref(),
    };
    let request = AnalysisRequest {
        files: &files,
        stdin: args.input.stdin,
        collect_source_hash: true,
    };
    let source_hash = run_analysis(&request, &ctx, &mut acc, stderr);
    let analysis_tier = pedant_core::determine_analysis_tier(semantic.as_ref(), &acc.data_flows);
    let mut stdout = io::stdout().lock();
    if let Err(exit) = crate::output::write_attestation_output(
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

pub(crate) fn load_file_config(
    explicit_config: Option<&str>,
    stderr: &mut impl Write,
) -> Result<Option<ConfigFile>, ExitCode> {
    let explicit = explicit_config.is_some();
    let config_path = match (explicit_config, find_config_file()) {
        (Some(path), _) => Some(std::path::PathBuf::from(path)),
        (None, Ok(path)) => path,
        (None, Err(error)) => {
            crate::report_error(stderr, format_args!("warning: {error}"));
            return Ok(None);
        }
    };

    let Some(config_path) = config_path else {
        return Ok(None);
    };

    match (load_config_file(&config_path), explicit) {
        (Ok(cfg), _) => Ok(Some(cfg)),
        (Err(error), true) => {
            crate::report_error(stderr, format_args!("error: {error}"));
            Err(ExitCode::from(2))
        }
        (Err(error), false) => {
            crate::report_error(stderr, format_args!("warning: {error}"));
            Ok(None)
        }
    }
}

fn bool_exit_code(had_error: bool) -> ExitCode {
    match had_error {
        true => ExitCode::from(2),
        false => ExitCode::from(0),
    }
}
