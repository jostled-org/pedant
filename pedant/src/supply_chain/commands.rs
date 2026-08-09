use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::config::FailOn;

use super::attestation::{CrateAttestation, collect_attestations};
use super::baseline::{prune_stale_baselines, write_baseline_file};
use super::compare::compare_attestation;
use super::debug_output::emit_debug_package;
use super::error::SupplyChainError;
use super::github_output::emit_github_output;
use super::report::{Report, should_fail};
use super::vendor::{current_workspace_root, vendor_cargo_deps};

pub(crate) fn run_init(baseline_path: &str, stderr: &mut impl Write) -> ExitCode {
    run_write_mode(
        "initialized",
        baseline_path,
        stderr,
        write_current_baselines,
    )
}

pub(crate) fn run_update(baseline_path: &str, stderr: &mut impl Write) -> ExitCode {
    run_write_mode("updated", baseline_path, stderr, update_current_baselines)
}

pub(crate) fn run_verify(
    baseline_path: &str,
    fail_on: FailOn,
    debug_package: Option<&str>,
    stderr: &mut impl Write,
) -> ExitCode {
    match verify_current_workspace(Path::new(baseline_path), debug_package, stderr) {
        Ok(report) => finalize_verify(report, fail_on, stderr),
        Err(error) => report_failure(stderr, &error),
    }
}

/// Init and update differ only in the writer and the verb they report.
fn run_write_mode(
    verb: &str,
    baseline_path: &str,
    stderr: &mut impl Write,
    write: impl FnOnce(&Path) -> Result<usize, SupplyChainError>,
) -> ExitCode {
    match write(Path::new(baseline_path)) {
        Ok(count) => {
            std::mem::drop(writeln!(
                std::io::stdout().lock(),
                "{verb} {count} cargo baseline(s)"
            ));
            ExitCode::from(0)
        }
        Err(error) => report_failure(stderr, &error),
    }
}

fn report_failure(stderr: &mut impl Write, error: &SupplyChainError) -> ExitCode {
    crate::report_error(stderr, format_args!("error: {error}"));
    ExitCode::from(2)
}

/// Vendor the locked dependency set and write a baseline for every crate.
fn refresh_baselines(baseline_root: &Path) -> Result<Box<[CrateAttestation]>, SupplyChainError> {
    let attestations = attest_current_workspace()?;
    for attestation in &attestations {
        write_baseline_file(baseline_root, attestation)?;
    }
    Ok(attestations)
}

fn write_current_baselines(baseline_root: &Path) -> Result<usize, SupplyChainError> {
    Ok(refresh_baselines(baseline_root)?.len())
}

/// Update additionally drops baselines the current dependency set no longer has.
fn update_current_baselines(baseline_root: &Path) -> Result<usize, SupplyChainError> {
    let attestations = refresh_baselines(baseline_root)?;
    prune_stale_baselines(baseline_root, &attestations)?;
    Ok(attestations.len())
}

fn attest_current_workspace() -> Result<Box<[CrateAttestation]>, SupplyChainError> {
    let workspace_root = current_workspace_root()?;
    let vendor = vendor_cargo_deps(&workspace_root)?;
    collect_attestations(&vendor.vendor_root())
}

fn verify_current_workspace(
    baseline_root: &Path,
    debug_package: Option<&str>,
    stderr: &mut impl Write,
) -> Result<Report, SupplyChainError> {
    let attestations = attest_current_workspace()?;
    let mut findings = Vec::new();
    let mut emitted_debug = false;

    for attestation in &attestations {
        if debug_package.is_some_and(|name| name == attestation.name.as_ref()) {
            emit_debug_package(stderr, attestation);
            emitted_debug = true;
        }
        findings.extend(compare_attestation(baseline_root, attestation)?);
    }

    if let (Some(name), false) = (debug_package, emitted_debug) {
        std::mem::drop(writeln!(
            stderr,
            "debug-package: {name} not found in vendored Cargo dependencies"
        ));
    }

    Ok(Report { findings })
}

/// Print the findings, publish them, and pick the exit code.
fn finalize_verify(report: Report, fail_on: FailOn, stderr: &mut impl Write) -> ExitCode {
    if let Err(error) = emit_github_output(&report) {
        return report_failure(stderr, &error);
    }

    if report.findings.is_empty() {
        std::mem::drop(writeln!(
            std::io::stdout().lock(),
            "All dependencies match baselines."
        ));
        return ExitCode::from(0);
    }

    print_findings(&report);
    match should_fail(&report.findings, fail_on) {
        true => ExitCode::from(1),
        false => ExitCode::from(0),
    }
}

/// Findings double as GitHub workflow commands, so Actions annotates the run.
fn print_findings(report: &Report) {
    let mut stdout = std::io::stdout().lock();
    std::mem::drop(writeln!(
        stdout,
        "=== Supply Chain Check: {} finding(s) ===",
        report.findings.len()
    ));
    for finding in &report.findings {
        std::mem::drop(writeln!(
            stdout,
            "::{}::[{}] {}@{} — {}",
            finding.level.annotation_level().command(),
            finding.ecosystem,
            finding.name,
            finding.version,
            finding.detail
        ));
    }
}
