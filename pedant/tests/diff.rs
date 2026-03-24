use std::io::Write;
use std::sync::Arc;

use pedant_types::{
    AnalysisTier, AttestationContent, CapabilityDiff, CapabilityFinding, CapabilityProfile,
    SourceLocation,
};
use tempfile::NamedTempFile;

mod common;

fn write_json_file(value: &impl serde::Serialize) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp file");
    serde_json::to_writer(&mut f, value).expect("failed to write json");
    f
}

fn make_profile(findings: Vec<CapabilityFinding>) -> CapabilityProfile {
    CapabilityProfile {
        findings: findings.into_boxed_slice(),
    }
}

fn make_attestation(profile: CapabilityProfile) -> AttestationContent {
    AttestationContent {
        spec_version: Box::from("0.1.0"),
        source_hash: Box::from("deadbeef"),
        crate_name: Box::from("test"),
        crate_version: Box::from("0.0.1"),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: 0,
        profile,
    }
}

fn net_finding() -> CapabilityFinding {
    CapabilityFinding {
        capability: pedant_types::Capability::Network,
        location: SourceLocation {
            file: Arc::from("lib.rs"),
            line: 1,
            column: 0,
        },
        evidence: Arc::from("use std::net::TcpStream"),
        build_script: false,
        reachable: None,
    }
}

fn fs_finding() -> CapabilityFinding {
    CapabilityFinding {
        capability: pedant_types::Capability::FileRead,
        location: SourceLocation {
            file: Arc::from("lib.rs"),
            line: 1,
            column: 0,
        },
        evidence: Arc::from("use std::fs::read"),
        build_script: false,
        reachable: None,
    }
}

#[test]
fn identical_profiles_exit_0() {
    let profile = make_profile(vec![net_finding()]);
    let old = write_json_file(&profile);
    let new = write_json_file(&profile);

    let output = common::run_pedant(
        &[
            "--diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(0));

    let diff: CapabilityDiff = serde_json::from_slice(&output.stdout).unwrap();
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.new_capabilities.is_empty());
    assert!(diff.dropped_capabilities.is_empty());
}

#[test]
fn different_profiles_exit_1() {
    let old = write_json_file(&make_profile(vec![net_finding()]));
    let new = write_json_file(&make_profile(vec![fs_finding()]));

    let output = common::run_pedant(
        &[
            "--diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1));

    let diff: CapabilityDiff = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!diff.added.is_empty());
    assert!(!diff.removed.is_empty());
    assert!(!diff.new_capabilities.is_empty());
    assert!(!diff.dropped_capabilities.is_empty());
}

#[test]
fn attestation_format_input() {
    let old_att = make_attestation(make_profile(vec![net_finding()]));
    let new_att = make_attestation(make_profile(vec![fs_finding()]));
    let old = write_json_file(&old_att);
    let new = write_json_file(&new_att);

    let output = common::run_pedant(
        &[
            "--diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1));

    let diff: CapabilityDiff = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!diff.added.is_empty());
}

#[test]
fn mixed_attestation_and_bare_profile() {
    let old_att = make_attestation(make_profile(vec![net_finding()]));
    let new_profile = make_profile(vec![fs_finding()]);
    let old = write_json_file(&old_att);
    let new = write_json_file(&new_profile);

    let output = common::run_pedant(
        &[
            "--diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1));

    let diff: CapabilityDiff = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!diff.added.is_empty());
    assert!(!diff.removed.is_empty());
}

#[test]
fn missing_file_exit_2() {
    let existing = write_json_file(&make_profile(vec![]));

    let output = common::run_pedant(
        &[
            "--diff",
            existing.path().to_str().unwrap(),
            "/nonexistent/file.json",
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to read diff input"));
}

#[test]
fn invalid_json_exit_2() {
    let mut bad = NamedTempFile::new().unwrap();
    bad.write_all(b"not json at all").unwrap();
    let good = write_json_file(&make_profile(vec![]));

    let output = common::run_pedant(
        &[
            "--diff",
            good.path().to_str().unwrap(),
            bad.path().to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to parse diff input"));
}

#[test]
fn no_args_after_diff_flag() {
    let output = common::run_pedant(&["--diff"], None);
    assert!(!output.status.success());
}
