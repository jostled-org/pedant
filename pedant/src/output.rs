use std::fs;
use std::io::Write;
use std::time::SystemTime;

use pedant_core::gate::GateSeverity;
use pedant_core::json_format::JsonViolation;
use pedant_core::violation::Violation;
use pedant_types::{
    AnalysisTier, AttestationContent, CapabilityDiff, CapabilityFinding, CapabilityProfile,
};
use serde::Serialize;

use crate::ProcessError;
use crate::config::OutputFormat;

const SPEC_VERSION: &str = "0.1.0";

type AttestationInputs = (Box<str>, Box<str>, Box<str>);

#[derive(Serialize)]
struct JsonOutput<'a> {
    analysis_tier: AnalysisTier,
    had_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    violations: Option<Vec<JsonViolation<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate_verdicts: Option<&'a [pedant_core::gate::GateVerdict]>,
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
        OutputFormat::Text => crate::reporter::Reporter::new(quiet)
            .report(violations, stdout)
            .map_err(|error| {
                crate::report_error(stderr, format_args!("error writing output: {error}"));
                std::process::ExitCode::from(2)
            }),
        OutputFormat::Json => {
            let output = JsonOutput {
                analysis_tier,
                had_error,
                violations: Some(violations.iter().map(JsonViolation::from).collect()),
                gate_verdicts: None,
            };
            write_json(stdout, stderr, &output, "analysis output")
        }
    }
}

pub(crate) fn write_gate_output(
    format: OutputFormat,
    analysis_tier: AnalysisTier,
    had_error: bool,
    gate_verdicts: &[pedant_core::gate::GateVerdict],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), std::process::ExitCode> {
    match format {
        OutputFormat::Text => crate::reporter::Reporter::new(true)
            .report_gate(gate_verdicts, stdout)
            .map_err(|error| {
                crate::report_error(stderr, format_args!("error writing gate output: {error}"));
                std::process::ExitCode::from(2)
            }),
        OutputFormat::Json => {
            let output = JsonOutput {
                analysis_tier,
                had_error,
                violations: None,
                gate_verdicts: Some(gate_verdicts),
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

/// Compute the process exit code from error state, violations, and gate verdicts.
pub(crate) fn compute_exit_code(
    had_error: bool,
    violations_empty: bool,
    gate_verdicts: &[pedant_core::gate::GateVerdict],
) -> std::process::ExitCode {
    let has_deny = gate_verdicts
        .iter()
        .any(|v| v.severity == GateSeverity::Deny);

    match (had_error, violations_empty, has_deny) {
        (true, _, _) => std::process::ExitCode::from(2),
        (_, false, _) | (_, _, true) => std::process::ExitCode::from(1),
        (false, true, false) => std::process::ExitCode::from(0),
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
