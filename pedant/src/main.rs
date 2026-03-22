//! CLI interface for the pedant linter and capability analyzer.

mod config;
mod reporter;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
#[cfg(feature = "semantic")]
use std::time::Instant;
use std::time::SystemTime;

use clap::Parser;
use pedant_core::AnalysisResult;
use pedant_core::SemanticContext;
use pedant_core::check_config::{CheckConfig, ConfigFile, find_config_file, load_config_file};
use pedant_core::checks::ALL_CHECKS;
use pedant_core::gate::{GateSeverity, evaluate_gate_rules};
use pedant_core::hash::compute_source_hash;
use pedant_core::lint::{analyze, analyze_build_script, discover_build_script};
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

struct AnalysisContext<'a> {
    base_config: &'a CheckConfig,
    file_config: Option<&'a ConfigFile>,
    semantic: Option<&'a SemanticContext>,
}

struct AnalysisAccumulator {
    violations: Vec<Violation>,
    findings: Vec<CapabilityFinding>,
    had_error: bool,
}

fn report_error(stderr: &mut impl Write, msg: std::fmt::Arguments<'_>) {
    match writeln!(stderr, "{msg}") {
        Ok(()) | Err(_) => {}
    }
}

impl AnalysisAccumulator {
    fn with_capacity(file_count: usize) -> Self {
        Self {
            violations: Vec::with_capacity(file_count),
            findings: Vec::with_capacity(file_count),
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

    if let [old_path, new_path] = cli.diff.as_slice() {
        return run_diff(old_path, new_path, &mut stderr);
    }

    let file_config = match load_file_config(&cli, &mut stderr) {
        Ok(cfg) => cfg,
        Err(exit) => return exit,
    };
    let base_config = cli.to_check_config(file_config.as_ref());
    let mut acc = AnalysisAccumulator::with_capacity(cli.files.len());

    let semantic = load_semantic_if_requested(&cli, &mut stderr);
    let analysis_tier = match semantic.is_some() {
        true => AnalysisTier::Semantic,
        false => AnalysisTier::Syntactic,
    };

    let ctx = AnalysisContext {
        base_config: &base_config,
        file_config: file_config.as_ref(),
        semantic: semantic.as_ref(),
    };

    let source_hash = run_analysis(&cli, &ctx, &mut acc, &mut stderr);

    let reporter = Reporter::new(cli.format, cli.quiet);
    let mut stdout = io::stdout().lock();
    if let Err(e) = reporter.report(&acc.violations, &mut stdout) {
        report_error(&mut stderr, format_args!("error writing output: {e}"));
        return ExitCode::from(2);
    }

    // Evaluate gate rules before findings are consumed by attestation/capabilities output.
    let default_gate = pedant_core::GateConfig::default();
    let gate_verdicts = match cli.gate {
        true => {
            let gate_config = file_config.as_ref().map_or(&default_gate, |fc| &fc.gate);
            evaluate_gate_rules(&acc.findings, gate_config)
        }
        false => Box::new([]),
    };

    if let Err(exit) = dispatch_output(
        &cli,
        source_hash,
        acc.findings,
        analysis_tier,
        &mut stdout,
        &mut stderr,
    ) {
        return exit;
    }

    if let (true, Err(e)) = (cli.gate, reporter.report_gate(&gate_verdicts, &mut stdout)) {
        report_error(&mut stderr, format_args!("error writing gate output: {e}"));
        return ExitCode::from(2);
    }

    compute_exit_code(acc.had_error, acc.violations.is_empty(), &gate_verdicts)
}

/// Select the input source (stdin vs files) and run analysis, returning a source
/// hash when attestation mode requires one.
fn run_analysis(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Option<Box<str>> {
    match (cli.attestation, cli.stdin) {
        (true, true) => attest_stdin(ctx.base_config, acc, stderr),
        (true, false) => Some(attest_files(cli, ctx, acc, stderr)),
        (false, true) => {
            acc.handle(process_stdin(ctx.base_config), "error", stderr);
            None
        }
        (false, false) => {
            analyze_file_list(cli, ctx, None, acc, stderr);
            None
        }
    }
}

/// Dispatch output based on mode: attestation JSON, capabilities JSON, or nothing.
fn dispatch_output(
    cli: &Cli,
    source_hash: Option<Box<str>>,
    findings: Vec<CapabilityFinding>,
    analysis_tier: AnalysisTier,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), ExitCode> {
    match (cli.attestation, cli.capabilities) {
        (true, _) => {
            let Some(hash) = source_hash else {
                return Err(ExitCode::from(2));
            };
            let Some(crate_name) = cli.crate_name.as_deref() else {
                report_error(
                    stderr,
                    format_args!("error: --crate-name required for attestation"),
                );
                return Err(ExitCode::from(2));
            };
            let Some(crate_version) = cli.crate_version.as_deref() else {
                report_error(
                    stderr,
                    format_args!("error: --crate-version required for attestation"),
                );
                return Err(ExitCode::from(2));
            };
            write_attestation(
                stdout,
                stderr,
                findings,
                hash,
                Box::from(crate_name),
                Box::from(crate_version),
                analysis_tier,
            )
        }
        (false, true) => write_capabilities(stdout, stderr, findings),
        (false, false) => Ok(()),
    }
}

/// Compute the process exit code from error state, violations, and gate verdicts.
fn compute_exit_code(
    had_error: bool,
    violations_empty: bool,
    gate_verdicts: &[pedant_core::gate::GateVerdict],
) -> ExitCode {
    let has_deny = gate_verdicts
        .iter()
        .any(|v| v.severity == GateSeverity::Deny);

    match (had_error, violations_empty, has_deny) {
        (true, _, _) => ExitCode::from(2),
        (_, false, _) | (_, _, true) => ExitCode::from(1),
        (false, true, false) => ExitCode::from(0),
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
    sources.insert(Box::<str>::from("<stdin>"), source.clone());
    acc.handle(
        analyze("<stdin>", &source, config, None).map_err(ProcessError::from),
        "error",
        stderr,
    );
    Some(compute_source_hash(&sources))
}

fn attest_files(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) -> Box<str> {
    let mut sources = BTreeMap::new();
    analyze_file_list(cli, ctx, Some(&mut sources), acc, stderr);
    compute_source_hash(&sources)
}

fn analyze_file_list(
    cli: &Cli,
    ctx: &AnalysisContext<'_>,
    mut sources: Option<&mut BTreeMap<Box<str>, String>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let mut seen_build_roots: BTreeSet<Box<Path>> = BTreeSet::new();
    for file_path in &cli.files {
        let Some(cfg) = ctx.base_config.resolve_for_path(file_path, ctx.file_config) else {
            continue;
        };
        analyze_single_file(
            file_path,
            analyze,
            &cfg,
            ctx.semantic,
            sources.as_deref_mut(),
            acc,
            stderr,
        );
        discover_and_analyze_build_script(
            file_path,
            &cfg,
            sources.as_deref_mut(),
            &mut seen_build_roots,
            acc,
            stderr,
        );
    }
}

/// Find the crate root by walking up from a file path to locate `Cargo.toml`.
fn find_crate_root(file_path: &str) -> Option<&Path> {
    let mut dir = Path::new(file_path).parent()?;
    loop {
        match dir.join("Cargo.toml").is_file() {
            true => return Some(dir),
            false => dir = dir.parent()?,
        }
    }
}

#[cfg(feature = "semantic")]
/// Find the workspace root by walking up from the first file argument.
///
/// Looks for a `Cargo.toml` containing `[workspace]`, or falls back to the
/// nearest `Cargo.toml` with `[package]`.
fn find_workspace_root(files: &[String]) -> Option<Box<Path>> {
    let first = files.first()?;
    let mut dir = Path::new(first.as_str()).parent()?;
    let mut fallback: Option<&Path> = None;
    loop {
        // Some(true) = workspace, Some(false) = package, None = absent
        match (is_cargo_workspace(dir), fallback) {
            (Some(true), _) => return Some(Box::from(dir)),
            (Some(false), None) => fallback = Some(dir),
            (Some(false), Some(_)) | (None, _) => {}
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return fallback.map(Box::from),
        }
    }
}

#[cfg(feature = "semantic")]
/// Check whether a directory contains a Cargo workspace, package, or neither.
///
/// Returns `Some(true)` for `[workspace]`, `Some(false)` for `[package]`-only,
/// `None` if no readable `Cargo.toml`.
fn is_cargo_workspace(dir: &Path) -> Option<bool> {
    use io::BufRead;
    let file = fs::File::open(dir.join("Cargo.toml")).ok()?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim_start().starts_with("[workspace]") {
            return Some(true);
        }
    }
    Some(false)
}

/// Load `SemanticContext` when `--semantic` is requested.
///
/// Returns `None` (with a stderr warning) if loading fails or the flag is absent.
#[cfg(feature = "semantic")]
fn load_semantic_if_requested(cli: &Cli, stderr: &mut impl Write) -> Option<SemanticContext> {
    if !cli.semantic {
        return None;
    }

    let Some(root) = find_workspace_root(&cli.files) else {
        report_error(
            stderr,
            format_args!(
                "warning: --semantic: no Cargo.toml found, falling back to syntactic analysis"
            ),
        );
        return None;
    };

    let start = Instant::now();
    let ctx = SemanticContext::load(&root);
    let elapsed = start.elapsed();

    match ctx {
        Some(c) => {
            report_error(
                stderr,
                format_args!(
                    "semantic: loaded workspace in {:.1}s",
                    elapsed.as_secs_f64()
                ),
            );
            Some(c)
        }
        None => {
            report_error(
                stderr,
                format_args!(
                    "warning: --semantic: failed to load workspace at {}, falling back to syntactic analysis",
                    root.display()
                ),
            );
            None
        }
    }
}

/// Stub when the `semantic` feature is disabled — always returns `None`.
#[cfg(not(feature = "semantic"))]
fn load_semantic_if_requested(_cli: &Cli, _stderr: &mut impl Write) -> Option<SemanticContext> {
    None
}

fn discover_and_analyze_build_script(
    file_path: &str,
    config: &CheckConfig,
    sources: Option<&mut BTreeMap<Box<str>, String>>,
    seen_roots: &mut BTreeSet<Box<Path>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let Some(crate_root) = find_crate_root(file_path) else {
        return;
    };
    if seen_roots.contains(crate_root) {
        return;
    }
    seen_roots.insert(Box::from(crate_root));
    let build_path = match discover_build_script(crate_root) {
        Ok(Some(path)) => path,
        Ok(None) => return,
        Err(e) => {
            report_error(stderr, format_args!("build script discovery: {e}"));
            return;
        }
    };
    let Some(build_path_str) = build_path.to_str() else {
        report_error(
            stderr,
            format_args!(
                "build script path is not valid UTF-8: {}",
                build_path.display()
            ),
        );
        return;
    };
    analyze_single_file(
        build_path_str,
        analyze_build_script,
        config,
        None,
        sources,
        acc,
        stderr,
    );
}

fn analyze_single_file(
    file_path: &str,
    analyze_fn: fn(
        &str,
        &str,
        &CheckConfig,
        Option<&SemanticContext>,
    ) -> Result<AnalysisResult, pedant_core::ParseError>,
    config: &CheckConfig,
    semantic: Option<&SemanticContext>,
    sources: Option<&mut BTreeMap<Box<str>, String>>,
    acc: &mut AnalysisAccumulator,
    stderr: &mut impl Write,
) {
    let source = match fs::read_to_string(file_path) {
        Ok(s) => s,
        Err(e) => {
            report_error(stderr, format_args!("{file_path}: {e}"));
            acc.had_error = true;
            return;
        }
    };
    if let Some(sources) = sources {
        sources.insert(Box::from(file_path), source.clone());
    }
    acc.handle(
        analyze_fn(file_path, &source, config, semantic).map_err(ProcessError::from),
        file_path,
        stderr,
    );
}

fn load_file_config(cli: &Cli, stderr: &mut impl Write) -> Result<Option<ConfigFile>, ExitCode> {
    let explicit = cli.config.is_some();
    let config_path = cli
        .config
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(find_config_file);

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

fn read_stdin_source() -> Result<String, ProcessError> {
    let mut source = String::new();
    io::stdin()
        .read_to_string(&mut source)
        .map_err(ProcessError::StdinRead)?;
    Ok(source)
}

fn process_stdin(config: &CheckConfig) -> Result<AnalysisResult, ProcessError> {
    let source = read_stdin_source()?;
    Ok(analyze("<stdin>", &source, config, None)?)
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

fn write_json(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    payload: &impl serde::Serialize,
    context: &str,
) -> Result<(), ExitCode> {
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, payload) {
        report_error(stderr, format_args!("error writing {context}: {e}"));
        return Err(ExitCode::from(2));
    }
    if let Err(e) = writeln!(stdout) {
        report_error(
            stderr,
            format_args!("error writing trailing newline for {context}: {e}"),
        );
        return Err(ExitCode::from(2));
    }
    Ok(())
}

fn write_attestation(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
    source_hash: Box<str>,
    crate_name: Box<str>,
    crate_version: Box<str>,
    analysis_tier: AnalysisTier,
) -> Result<(), ExitCode> {
    let attestation = AttestationContent {
        spec_version: Box::from(SPEC_VERSION),
        source_hash,
        crate_name,
        crate_version,
        analysis_tier,
        timestamp: current_timestamp(),
        profile: CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
    };
    write_json(stdout, stderr, &attestation, "attestation")
}

fn write_capabilities(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
) -> Result<(), ExitCode> {
    let profile = CapabilityProfile {
        findings: findings.into_boxed_slice(),
    };
    write_json(stdout, stderr, &profile, "capabilities")
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
    let raw_json = fs::read_to_string(path).map_err(|e| ProcessError::DiffRead {
        path: path.into(),
        source: e,
    })?;

    // Try as attestation (has spec_version); fall back to bare profile.
    serde_json::from_str::<AttestationContent>(&raw_json)
        .map(|att| att.profile)
        .or_else(|_| serde_json::from_str(&raw_json))
        .map_err(|e| ProcessError::DiffParse {
            path: path.into(),
            source: e,
        })
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

fn run_diff(old_path: &str, new_path: &str, stderr: &mut impl Write) -> ExitCode {
    let Some((old, new)) = load_diff_profiles(old_path, new_path, stderr) else {
        return ExitCode::from(2);
    };

    let diff = CapabilityDiff::compute(&old, &new);
    let mut stdout = io::stdout().lock();

    if let Err(exit) = write_json(&mut stdout, stderr, &diff, "diff") {
        return exit;
    }

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
