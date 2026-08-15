use std::fs;
use std::io::Write;
use std::time::SystemTime;

use pedant_core::gate::{GateEvidence, GateLocation, GateSeverity, GateVerdict};
use pedant_core::json_format::JsonViolation;
use pedant_core::violation::Violation;
use pedant_types::{
    AnalysisTier, AttestationContent, CapabilityDiff, CapabilityFinding, CapabilityProfile,
};
use serde::Serialize;

use crate::ProcessError;
use crate::attestation_inputs::AttestationInputs;
use crate::config::OutputFormat;

const SPEC_VERSION: &str = "0.1.0";

#[derive(Serialize)]
struct JsonOutput<'a> {
    analysis_tier: AnalysisTier,
    had_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    violations: Option<Vec<JsonViolation<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate_verdicts: Option<&'a [GateVerdict]>,
    /// Project mode only: every analyzed root target, in selection order.
    #[serde(skip_serializing_if = "Option::is_none")]
    analyzed_targets: Option<Box<[&'a str]>>,
}

/// The lower-snake-case token one tier is spelled by, equal to its JSON form.
pub(crate) fn tier_token(tier: AnalysisTier) -> &'static str {
    match tier {
        AnalysisTier::Syntactic => "syntactic",
        AnalysisTier::Semantic => "semantic",
        AnalysisTier::DataFlow => "data_flow",
    }
}

/// One value as its compact JSON spelling.
///
/// Text and GitHub records spell evidence through the JSON contract rather than
/// through a second delimiter grammar, so this is the sole serialization owner
/// for all three formats. A value that cannot be serialized is a write failure
/// and reaches the same exit-2 owner as a broken pipe.
pub(crate) fn compact(value: &(impl Serialize + ?Sized)) -> std::io::Result<String> {
    serde_json::to_string(value).map_err(std::io::Error::other)
}

/// The module-boundary evidence one verdict carries, when it carries any.
fn module_boundary(verdict: &GateVerdict) -> Option<&pedant_core::gate::ModuleBoundaryEvidence> {
    match verdict.evidence.as_ref() {
        Some(GateEvidence::ModuleBoundary(evidence)) => Some(evidence),
        None => None,
    }
}

/// The `; target=…; subject=…; measurement=…` suffix text and GitHub share.
pub(crate) fn evidence_fields(verdict: &GateVerdict) -> std::io::Result<String> {
    let Some(evidence) = module_boundary(verdict) else {
        return Ok(String::new());
    };
    Ok(format!(
        "; target={}; subject={}; measurement={}",
        compact(evidence.target())?,
        compact(evidence.subject())?,
        compact(evidence.measurement())?,
    ))
}

/// The reported target list, borrowed from the labels the run selected.
///
/// The JSON envelope and the GitHub summary notice name one projection, so the
/// two cannot report a different target list for one run.
pub(crate) fn target_labels(targets: &[std::sync::Arc<str>]) -> Box<[&str]> {
    targets.iter().map(|target| &**target).collect()
}

/// The source anchor a GitHub annotation attaches one verdict to.
pub(crate) fn subject_location(verdict: &GateVerdict) -> Option<&GateLocation> {
    module_boundary(verdict).and_then(|evidence| evidence.subject().location())
}

/// Returns seconds since Unix epoch.
fn current_timestamp() -> Result<u64, ProcessError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|source| ProcessError::Timestamp { source })
}

fn write_json(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    payload: &impl serde::Serialize,
    context: &str,
) -> Result<(), std::process::ExitCode> {
    if let Err(e) = serde_json::to_writer_pretty(&mut *stdout, payload) {
        crate::report_error(stderr, format_args!("error writing {context}: {e}"));
        return Err(std::process::ExitCode::from(2));
    }
    if let Err(e) = writeln!(stdout) {
        crate::report_error(
            stderr,
            format_args!("error writing trailing newline for {context}: {e}"),
        );
        return Err(std::process::ExitCode::from(2));
    }
    Ok(())
}

/// Map a writer failure to the process error exit code, reporting it on stderr.
fn map_io_error(
    result: std::io::Result<()>,
    context: &str,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    result.map_err(|error| {
        crate::report_error(stderr, format_args!("error writing {context}: {error}"));
        std::process::ExitCode::from(2)
    })
}

fn require_attestation_inputs(
    crate_name: Option<&str>,
    crate_version: Option<&str>,
    source_hash: Option<Box<str>>,
    stderr: &mut impl Write,
) -> Result<AttestationInputs, std::process::ExitCode> {
    let Some(source_hash) = source_hash else {
        crate::report_error(
            stderr,
            format_args!("error: source hash required for attestation"),
        );
        return Err(std::process::ExitCode::from(2));
    };
    let Some(crate_name) = crate_name else {
        crate::report_error(
            stderr,
            format_args!("error: --crate-name required for attestation"),
        );
        return Err(std::process::ExitCode::from(2));
    };
    let Some(crate_version) = crate_version else {
        crate::report_error(
            stderr,
            format_args!("error: --crate-version required for attestation"),
        );
        return Err(std::process::ExitCode::from(2));
    };

    Ok((source_hash, Box::from(crate_name), Box::from(crate_version)))
}

fn capability_profile(findings: Vec<CapabilityFinding>) -> CapabilityProfile {
    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

fn build_attestation(
    stderr: &mut impl Write,
    profile: CapabilityProfile,
    source_hash: Box<str>,
    crate_name: Box<str>,
    crate_version: Box<str>,
    analysis_tier: AnalysisTier,
) -> Result<AttestationContent, std::process::ExitCode> {
    let timestamp = current_timestamp().map_err(|error| {
        crate::report_error(stderr, format_args!("error creating attestation: {error}"));
        std::process::ExitCode::from(2)
    })?;

    Ok(AttestationContent {
        spec_version: Box::from(SPEC_VERSION),
        source_hash,
        crate_name,
        crate_version,
        analysis_tier,
        timestamp,
        analysis_completeness: None,
        rust_version: None,
        profile,
    })
}

pub(crate) fn write_attestation(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
    source_hash: Box<str>,
    crate_name: Box<str>,
    crate_version: Box<str>,
    analysis_tier: AnalysisTier,
) -> Result<(), std::process::ExitCode> {
    let attestation = build_attestation(
        stderr,
        capability_profile(findings),
        source_hash,
        crate_name,
        crate_version,
        analysis_tier,
    )?;
    write_json(stdout, stderr, &attestation, "attestation")
}

pub(crate) fn write_capabilities(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    findings: Vec<CapabilityFinding>,
) -> Result<(), std::process::ExitCode> {
    let profile = capability_profile(findings);
    write_json(stdout, stderr, &profile, "capabilities")
}

pub(crate) fn write_check_output(
    format: OutputFormat,
    quiet: bool,
    analysis_tier: AnalysisTier,
    had_error: bool,
    violations: &[Violation],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    match format {
        OutputFormat::Text => map_io_error(
            crate::reporter::Reporter::new(quiet).report(violations, stdout),
            "output",
            stderr,
        ),
        OutputFormat::Github => map_io_error(
            crate::github::write_violations(violations, stdout),
            "output",
            stderr,
        ),
        OutputFormat::Json => {
            let output = JsonOutput {
                analysis_tier,
                had_error,
                violations: Some(violations.iter().map(JsonViolation::from).collect()),
                gate_verdicts: None,
                analyzed_targets: None,
            };
            write_json(stdout, stderr, &output, "analysis output")
        }
    }
}

pub(crate) fn write_gate_output(
    format: OutputFormat,
    analysis_tier: AnalysisTier,
    had_error: bool,
    gate_verdicts: &[GateVerdict],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    match format {
        OutputFormat::Text => map_io_error(
            crate::reporter::Reporter::new(true).report_gate(gate_verdicts, stdout),
            "gate output",
            stderr,
        ),
        OutputFormat::Github => map_io_error(
            crate::github::write_gate_verdicts(gate_verdicts, stdout),
            "gate output",
            stderr,
        ),
        OutputFormat::Json => {
            let output = JsonOutput {
                analysis_tier,
                had_error,
                violations: None,
                gate_verdicts: Some(gate_verdicts),
                analyzed_targets: None,
            };
            write_json(stdout, stderr, &output, "gate output")
        }
    }
}

/// Emit one project-mode gate result in the requested format.
///
/// Text and GitHub state the tier and every analyzed target before any verdict.
/// JSON carries both in the same envelope, appending `analyzed_targets` after
/// `gate_verdicts`. A run that produced no verdict is observable in all three.
pub(crate) fn write_project_gate_output(
    format: OutputFormat,
    tier: AnalysisTier,
    targets: &[std::sync::Arc<str>],
    verdicts: &[GateVerdict],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    match format {
        OutputFormat::Text => map_io_error(
            crate::reporter::report_project_gate(tier, targets, verdicts, stdout),
            "gate output",
            stderr,
        ),
        OutputFormat::Github => map_io_error(
            crate::github::write_project_gate(tier, targets, verdicts, stdout),
            "gate output",
            stderr,
        ),
        OutputFormat::Json => {
            let output = JsonOutput {
                analysis_tier: tier,
                had_error: false,
                violations: None,
                gate_verdicts: Some(verdicts),
                analyzed_targets: Some(target_labels(targets)),
            };
            write_json(stdout, stderr, &output, "gate output")
        }
    }
}

pub(crate) fn write_attestation_output(
    source_hash: Option<Box<str>>,
    findings: Vec<CapabilityFinding>,
    crate_name: &str,
    crate_version: &str,
    analysis_tier: AnalysisTier,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    let (hash, crate_name, crate_version) =
        require_attestation_inputs(Some(crate_name), Some(crate_version), source_hash, stderr)?;
    write_attestation(
        stdout,
        stderr,
        findings,
        hash,
        crate_name,
        crate_version,
        analysis_tier,
    )
}

/// Compute the process exit code from error state, blocking violations, and
/// gate verdicts. `Warn`-severity violations are advisory and do not fail.
pub(crate) fn compute_exit_code(
    had_error: bool,
    has_deny_violation: bool,
    gate_verdicts: &[GateVerdict],
) -> std::process::ExitCode {
    let has_deny_gate = gate_verdicts
        .iter()
        .any(|v| v.severity == GateSeverity::Deny);

    match (had_error, has_deny_violation || has_deny_gate) {
        (true, _) => std::process::ExitCode::from(2),
        (_, true) => std::process::ExitCode::from(1),
        (false, false) => std::process::ExitCode::from(0),
    }
}

fn load_profile(path: &str) -> Result<CapabilityProfile, ProcessError> {
    let raw_json = fs::read_to_string(path).map_err(|e| ProcessError::DiffRead {
        path: path.into(),
        source: e,
    })?;

    let raw_value = serde_json::from_str::<serde_json::Value>(&raw_json).map_err(|source| {
        ProcessError::DiffParse {
            path: path.into(),
            source,
        }
    })?;

    let has_spec_version = raw_value
        .as_object()
        .is_some_and(|object| object.contains_key("spec_version"));

    match has_spec_version {
        true => serde_json::from_value::<AttestationContent>(raw_value).map(|att| att.profile),
        false => serde_json::from_value::<CapabilityProfile>(raw_value),
    }
    .map_err(|source| ProcessError::DiffParse {
        path: path.into(),
        source,
    })
}

fn load_diff_profiles(
    old_path: &str,
    new_path: &str,
) -> Result<(CapabilityProfile, CapabilityProfile), ProcessError> {
    let old = load_profile(old_path)?;
    let new = load_profile(new_path)?;
    Ok((old, new))
}

pub(crate) fn run_diff(
    old_path: &str,
    new_path: &str,
    stderr: &mut impl Write,
) -> std::process::ExitCode {
    let (old, new) = match load_diff_profiles(old_path, new_path) {
        Ok(profiles) => profiles,
        Err(error) => {
            crate::report_error(stderr, format_args!("{error}"));
            return std::process::ExitCode::from(2);
        }
    };

    let diff = CapabilityDiff::compute(&old, &new);
    let mut stdout = std::io::stdout().lock();

    if let Err(exit) = write_json(&mut stdout, stderr, &diff, "diff") {
        return exit;
    }

    match diff.is_empty() {
        true => std::process::ExitCode::from(0),
        false => std::process::ExitCode::from(1),
    }
}
