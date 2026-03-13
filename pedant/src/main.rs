use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

use clap::Parser;
use pedant::AnalysisResult;
use pedant::checks::ALL_CHECKS;
use pedant::config::{
    Cli, ConfigFile, NamingOverride, PatternCheck, PatternOverride, check_path_override,
    find_config_file, load_config_file,
};
use pedant::hash::compute_source_hash;
use pedant::reporter::Reporter;
use pedant::violation::{Violation, lookup_rationale};
use pedant::visitor::{CheckConfig, analyze};
use pedant_types::{AnalysisTier, AttestationContent, CapabilityFinding, CapabilityProfile};

#[derive(Debug, thiserror::Error)]
enum ProcessError {
    #[error("failed to read stdin: {0}")]
    StdinRead(#[source] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] syn::Error),
    #[error("failed to read file {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
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

    let reporter = Reporter::new(cli.output_format(), cli.quiet);
    let mut stdout = io::stdout().lock();
    if let Err(e) = reporter.report(&acc.violations, &mut stdout) {
        report_error(&mut stderr, format_args!("error writing output: {e}"));
        return ExitCode::from(2);
    }

    let output_err = match (cli.attestation, cli.capabilities) {
        (true, _) => {
            let Some(hash) = source_hash else {
                return ExitCode::from(2);
            };
            write_attestation(
                &mut stdout,
                &mut stderr,
                acc.findings,
                hash,
                Arc::from(cli.crate_name.as_deref().unwrap_or("")),
                Arc::from(cli.crate_version.as_deref().unwrap_or("")),
            )
        }
        (false, true) => write_capabilities(&mut stdout, &mut stderr, acc.findings),
        (false, false) => None,
    };
    if let Some(exit) = output_err {
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
) -> Option<Arc<str>> {
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
) -> Arc<str> {
    let mut sources = BTreeMap::new();
    for file_path in &cli.files {
        let config = resolve_config_for_path(file_path, base_config, file_config);
        let Some(cfg) = config else { continue };
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
        let config = resolve_config_for_path(file_path, base_config, file_config);
        let Some(cfg) = config else { continue };
        acc.handle(process_file(file_path, &cfg), file_path, stderr);
    }
}

fn load_file_config(cli: &Cli, stderr: &mut impl Write) -> Option<ConfigFile> {
    let config_path = cli
        .config
        .as_ref()
        .map(Path::new)
        .map(Path::to_path_buf)
        .or_else(find_config_file)?;

    match load_config_file(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            report_error(stderr, format_args!("warning: {e}"));
            None
        }
    }
}

fn resolve_config_for_path(
    file_path: &str,
    base_config: &CheckConfig,
    file_config: Option<&ConfigFile>,
) -> Option<CheckConfig> {
    let Some(fc) = file_config else {
        return Some(base_config.clone());
    };

    let Some(override_cfg) = check_path_override(file_path, fc) else {
        return Some(base_config.clone());
    };

    if override_cfg.enabled == Some(false) {
        return None;
    }

    let mut config = base_config.clone();
    if let Some(max_depth) = override_cfg.max_depth {
        config.max_depth = max_depth;
    }

    apply_pattern_override(
        &mut config.forbid_attributes,
        &override_cfg.forbid_attributes,
    );
    apply_pattern_override(&mut config.forbid_types, &override_cfg.forbid_types);
    apply_pattern_override(&mut config.forbid_calls, &override_cfg.forbid_calls);
    apply_pattern_override(&mut config.forbid_macros, &override_cfg.forbid_macros);
    if let Some(forbid_else) = override_cfg.forbid_else {
        config.forbid_else = forbid_else;
    }
    if let Some(forbid_unsafe) = override_cfg.forbid_unsafe {
        config.forbid_unsafe = forbid_unsafe;
    }
    if let Some(v) = override_cfg.check_dyn_return {
        config.check_dyn_return = v;
    }
    if let Some(v) = override_cfg.check_dyn_param {
        config.check_dyn_param = v;
    }
    if let Some(v) = override_cfg.check_vec_box_dyn {
        config.check_vec_box_dyn = v;
    }
    if let Some(v) = override_cfg.check_dyn_field {
        config.check_dyn_field = v;
    }
    if let Some(v) = override_cfg.check_clone_in_loop {
        config.check_clone_in_loop = v;
    }
    if let Some(v) = override_cfg.check_default_hasher {
        config.check_default_hasher = v;
    }
    if let Some(v) = override_cfg.check_mixed_concerns {
        config.check_mixed_concerns = v;
    }
    if let Some(v) = override_cfg.check_inline_tests {
        config.check_inline_tests = v;
    }
    apply_naming_override(&mut config.check_naming, &override_cfg.check_naming);

    Some(config)
}

fn apply_pattern_override(check: &mut PatternCheck, override_opt: &Option<PatternOverride>) {
    let Some(ovr) = override_opt else { return };

    if let Some(enabled) = ovr.enabled {
        check.enabled = enabled;
    }

    if !ovr.patterns.is_empty() {
        check.patterns = ovr.patterns.clone();
    }
}

fn apply_naming_override(
    check: &mut pedant::config::NamingCheck,
    override_opt: &Option<NamingOverride>,
) {
    let Some(ovr) = override_opt else { return };

    if let Some(enabled) = ovr.enabled {
        check.enabled = enabled;
    }
    if let Some(ref names) = ovr.generic_names {
        check.generic_names = names.clone();
    }
    if let Some(ratio) = ovr.max_generic_ratio {
        check.max_generic_ratio = ratio;
    }
    if let Some(count) = ovr.min_generic_count {
        check.min_generic_count = count;
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
        path: file_path.to_string(),
        source: e,
    })?;
    Ok(analyze(file_path, &source, config)?)
}

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
    source_hash: Arc<str>,
    crate_name: Arc<str>,
    crate_version: Arc<str>,
) -> Option<ExitCode> {
    let attestation = AttestationContent {
        spec_version: Arc::from("0.1.0"),
        source_hash,
        crate_name,
        crate_version,
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: current_timestamp(),
        profile: CapabilityProfile { findings },
    };
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, &attestation) {
        report_error(stderr, format_args!("error writing attestation: {e}"));
        return Some(ExitCode::from(2));
    }
    let _ = writeln!(stdout);
    None
}

fn write_capabilities(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
) -> Option<ExitCode> {
    let profile = CapabilityProfile { findings };
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, &profile) {
        report_error(stderr, format_args!("error writing capabilities: {e}"));
        return Some(ExitCode::from(2));
    }
    let _ = writeln!(stdout);
    None
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

fn write_explain(code: &str, rationale: &pedant::violation::CheckRationale) -> io::Result<()> {
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
