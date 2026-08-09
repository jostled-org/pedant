//! The attestation envelope and the completeness record it carries.
//!
//! An attestation is written once and read back much later, so an omitted
//! optional field and an older document that never had the field must both
//! decode to the same value.

use pedant_types::{
    AnalysisCompleteness, AnalysisTier, AttestationContent, Capability, CapabilityProfile,
    SkippedAnalysis,
};

use crate::finding_fixture::sample_finding;

#[test]
fn attestation_round_trip() {
    let attestation = AttestationContent {
        spec_version: Box::from("1.0"),
        source_hash: Box::from("abc123"),
        crate_name: Box::from("my-crate"),
        crate_version: Box::from("0.1.0"),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: 1_700_000_000,
        analysis_completeness: Some(AnalysisCompleteness {
            analyzed_files: 1,
            skipped_files: 0,
            skipped_paths: Box::default(),
            skipped_details: Box::default(),
        }),
        rust_version: None,
        profile: CapabilityProfile {
            findings: vec![sample_finding(Capability::Ffi, "src/lib.rs", 5)].into_boxed_slice(),
        },
    };
    let json = serde_json::to_string(&attestation).unwrap();
    let back: AttestationContent = serde_json::from_str(&json).unwrap();
    assert_eq!(attestation, back);
    assert!(
        !json.contains("rust_version"),
        "JSON should omit rust_version when None, got: {json}"
    );
}

#[test]
fn attestation_content_round_trips_optional_rust_version() {
    let attestation = AttestationContent {
        spec_version: Box::from("0.1.0"),
        source_hash: Box::from("abc123"),
        crate_name: Box::from("with-msrv"),
        crate_version: Box::from("0.2.0"),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: 1_700_000_000,
        analysis_completeness: Some(AnalysisCompleteness::default()),
        rust_version: Some(Box::from("1.70")),
        profile: CapabilityProfile::default(),
    };
    let json = serde_json::to_string(&attestation).unwrap();
    assert!(
        json.contains(r#""rust_version":"1.70""#),
        "JSON should contain rust_version: 1.70, got: {json}"
    );
    let back: AttestationContent = serde_json::from_str(&json).unwrap();
    assert_eq!(attestation, back);
    assert_eq!(back.rust_version.as_deref(), Some("1.70"));

    // Backward-compatible decode: baseline without rust_version still parses with None.
    let legacy_json = r#"{
        "spec_version": "0.1.0",
        "source_hash": "abc123",
        "crate_name": "legacy",
        "crate_version": "0.1.0",
        "analysis_tier": "syntactic",
        "timestamp": 1700000000,
        "profile": {"findings": []}
    }"#;
    let legacy: AttestationContent = serde_json::from_str(legacy_json).unwrap();
    assert!(legacy.rust_version.is_none());
}

#[test]
fn analysis_completeness_round_trip() {
    let completeness = AnalysisCompleteness {
        analyzed_files: 2,
        skipped_files: 1,
        skipped_paths: vec![Box::from("./src/lib.rs")].into_boxed_slice(),
        skipped_details: vec![SkippedAnalysis {
            path: Box::from("./src/lib.rs"),
            error: Box::from("expected ';'"),
        }]
        .into_boxed_slice(),
    };
    let json = serde_json::to_string(&completeness).unwrap();
    let back: AnalysisCompleteness = serde_json::from_str(&json).unwrap();
    assert_eq!(completeness, back);
    assert!(!back.is_complete());
}
