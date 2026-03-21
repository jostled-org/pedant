use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_core::hash::compute_source_hash;
use pedant_types::{AnalysisTier, AttestationContent, CapabilityProfile};

mod common;

// --- Hash unit tests ---

#[test]
fn test_source_hash_deterministic() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("a.rs"), Arc::from("fn main() {}"));
    sources.insert(Arc::from("b.rs"), Arc::from("fn helper() {}"));

    let hash1 = compute_source_hash(&sources);
    let hash2 = compute_source_hash(&sources);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_source_hash_sorted_order() {
    let mut sources_a = BTreeMap::new();
    sources_a.insert(Arc::from("b.rs"), Arc::from("second"));
    sources_a.insert(Arc::from("a.rs"), Arc::from("first"));

    let mut sources_b = BTreeMap::new();
    sources_b.insert(Arc::from("a.rs"), Arc::from("first"));
    sources_b.insert(Arc::from("b.rs"), Arc::from("second"));

    assert_eq!(
        compute_source_hash(&sources_a),
        compute_source_hash(&sources_b)
    );
}

#[test]
fn test_source_hash_known_value() {
    let mut sources = BTreeMap::new();
    sources.insert(Arc::from("test.rs"), Arc::from("hello"));

    let hash = compute_source_hash(&sources);
    // SHA-256 of "hello"
    assert_eq!(
        hash.as_ref(),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn test_source_hash_empty() {
    let sources: BTreeMap<Arc<str>, Arc<str>> = BTreeMap::new();
    let hash = compute_source_hash(&sources);
    // SHA-256 of empty string
    assert_eq!(
        hash.as_ref(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// --- CLI integration tests ---

#[test]
fn test_attestation_cli_missing_args() {
    let output = common::run_pedant(&["--stdin", "--attestation"], None);
    assert!(!output.status.success());
}

#[test]
fn test_attestation_cli_output_structure() {
    let output = common::run_pedant(
        &[
            "--stdin",
            "--attestation",
            "--crate-name",
            "test-crate",
            "--crate-version",
            "0.1.0",
        ],
        Some("fn main() {}\n"),
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let attestation: AttestationContent =
        serde_json::from_slice(&output.stdout).expect("should parse as AttestationContent");

    assert_eq!(attestation.spec_version.as_ref(), "0.1.0");
    assert_eq!(attestation.analysis_tier, AnalysisTier::Syntactic);
    assert_eq!(attestation.crate_name.as_ref(), "test-crate");
    assert_eq!(attestation.crate_version.as_ref(), "0.1.0");
    assert_eq!(attestation.source_hash.len(), 64);
    assert!(
        attestation
            .source_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn test_attestation_has_findings() {
    let output = common::run_pedant(
        &[
            "--stdin",
            "--attestation",
            "--crate-name",
            "net-crate",
            "--crate-version",
            "1.0.0",
        ],
        Some("use std::net::TcpStream;\n"),
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let attestation: AttestationContent = serde_json::from_slice(&output.stdout).unwrap();

    assert!(
        attestation
            .profile
            .findings
            .iter()
            .any(|f| f.capability == pedant_types::Capability::Network)
    );
}

#[test]
fn test_capabilities_flag_unchanged() {
    let output = common::run_pedant(
        &["--stdin", "--capabilities"],
        Some("use std::net::TcpStream;\n"),
    );

    assert!(output.status.success());

    let profile: CapabilityProfile = serde_json::from_slice(&output.stdout)
        .expect("--capabilities should output CapabilityProfile, not AttestationContent");

    assert!(!profile.findings.is_empty());
}

#[test]
fn test_attestation_timestamp_reasonable() {
    let output = common::run_pedant(
        &[
            "--stdin",
            "--attestation",
            "--crate-name",
            "ts-crate",
            "--crate-version",
            "0.0.1",
        ],
        Some("fn main() {}\n"),
    );

    let attestation: AttestationContent = serde_json::from_slice(&output.stdout).unwrap();

    // 2024-01-01 to 2030-01-01 in unix seconds
    let min_ts: u64 = 1_704_067_200;
    let max_ts: u64 = 1_893_456_000;
    assert!(
        attestation.timestamp >= min_ts && attestation.timestamp <= max_ts,
        "timestamp {} not in reasonable range",
        attestation.timestamp
    );
}
