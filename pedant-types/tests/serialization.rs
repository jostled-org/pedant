use std::sync::Arc;

use pedant_types::{
    AnalysisTier, AttestationContent, Capability, CapabilityDiff, CapabilityFinding,
    CapabilityProfile, SourceLocation, TypeError,
};

fn sample_finding(capability: Capability, file: &str, line: usize) -> CapabilityFinding {
    CapabilityFinding {
        capability,
        location: SourceLocation {
            file: Arc::from(file),
            line,
            column: 1,
        },
        evidence: Arc::from("test evidence"),
    }
}

#[test]
fn capability_serializes_to_snake_case() {
    let json = serde_json::to_string(&Capability::FileRead).unwrap();
    assert_eq!(json, "\"file_read\"");

    let json = serde_json::to_string(&Capability::ProcessExec).unwrap();
    assert_eq!(json, "\"process_exec\"");

    let json = serde_json::to_string(&Capability::UnsafeCode).unwrap();
    assert_eq!(json, "\"unsafe_code\"");

    let json = serde_json::to_string(&Capability::SystemTime).unwrap();
    assert_eq!(json, "\"system_time\"");

    let json = serde_json::to_string(&Capability::ProcMacro).unwrap();
    assert_eq!(json, "\"proc_macro\"");
}

#[test]
fn capability_round_trip() {
    let variants = [
        Capability::Network,
        Capability::FileRead,
        Capability::FileWrite,
        Capability::ProcessExec,
        Capability::EnvAccess,
        Capability::UnsafeCode,
        Capability::Ffi,
        Capability::Crypto,
        Capability::SystemTime,
        Capability::ProcMacro,
    ];
    for cap in variants {
        let json = serde_json::to_string(&cap).unwrap();
        let back: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, back);
    }
}

#[test]
fn source_location_round_trip() {
    let loc = SourceLocation {
        file: Arc::from("src/main.rs"),
        line: 42,
        column: 5,
    };
    let json = serde_json::to_string(&loc).unwrap();
    let back: SourceLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(loc, back);
}

#[test]
fn capability_finding_round_trip() {
    let finding = sample_finding(Capability::Network, "src/lib.rs", 10);
    let json = serde_json::to_string(&finding).unwrap();
    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn profile_capabilities_deduplicates_and_sorts() {
    let profile = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
            sample_finding(Capability::Network, "c.rs", 3),
        ],
    };
    let caps = profile.capabilities();
    assert_eq!(caps, vec![Capability::Network, Capability::FileRead]);
}

#[test]
fn profile_findings_for_filters() {
    let profile = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
            sample_finding(Capability::Network, "c.rs", 3),
        ],
    };
    let net = profile.findings_for(Capability::Network);
    assert_eq!(net.len(), 2);
    let fr = profile.findings_for(Capability::FileRead);
    assert_eq!(fr.len(), 1);
    let empty = profile.findings_for(Capability::Crypto);
    assert!(empty.is_empty());
}

#[test]
fn empty_profile_round_trip() {
    let profile = CapabilityProfile::default();
    let json = serde_json::to_string(&profile).unwrap();
    let back: CapabilityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
    assert!(back.capabilities().is_empty());
}

#[test]
fn attestation_round_trip() {
    let attestation = AttestationContent {
        spec_version: Arc::from("1.0"),
        source_hash: Arc::from("abc123"),
        crate_name: Arc::from("my-crate"),
        crate_version: Arc::from("0.1.0"),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: 1_700_000_000,
        profile: CapabilityProfile {
            findings: vec![sample_finding(Capability::Ffi, "src/lib.rs", 5)],
        },
    };
    let json = serde_json::to_string(&attestation).unwrap();
    let back: AttestationContent = serde_json::from_str(&json).unwrap();
    assert_eq!(attestation, back);
}

#[test]
fn analysis_tier_round_trip() {
    for tier in [
        AnalysisTier::Syntactic,
        AnalysisTier::Semantic,
        AnalysisTier::DataFlow,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let back: AnalysisTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, back);
    }
}

#[test]
fn diff_overlapping_profiles() {
    let old = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
        ],
    };
    let new = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::Crypto, "c.rs", 3),
        ],
    };
    let diff = CapabilityDiff::compute(&old, &new);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].capability, Capability::Crypto);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].capability, Capability::FileRead);
    assert_eq!(&*diff.new_capabilities, &[Capability::Crypto]);
    assert_eq!(&*diff.dropped_capabilities, &[Capability::FileRead]);
}

#[test]
fn diff_disjoint_profiles() {
    let old = CapabilityProfile {
        findings: vec![sample_finding(Capability::Network, "a.rs", 1)],
    };
    let new = CapabilityProfile {
        findings: vec![sample_finding(Capability::FileWrite, "b.rs", 2)],
    };
    let diff = CapabilityDiff::compute(&old, &new);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(&*diff.new_capabilities, &[Capability::FileWrite]);
    assert_eq!(&*diff.dropped_capabilities, &[Capability::Network]);
}

#[test]
fn diff_empty_profiles() {
    let empty = CapabilityProfile::default();
    let diff = CapabilityDiff::compute(&empty, &empty);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.new_capabilities.is_empty());
    assert!(diff.dropped_capabilities.is_empty());
}

#[test]
fn diff_round_trip() {
    let old = CapabilityProfile {
        findings: vec![sample_finding(Capability::Network, "a.rs", 1)],
    };
    let new = CapabilityProfile {
        findings: vec![sample_finding(Capability::Crypto, "b.rs", 2)],
    };
    let diff = CapabilityDiff::compute(&old, &new);
    let json = serde_json::to_string(&diff).unwrap();
    let back: CapabilityDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, back);
}

#[test]
fn type_error_wraps_json() {
    let bad_json = "not json";
    let result: Result<Capability, _> = serde_json::from_str(bad_json);
    match result {
        Err(e) => {
            let te = TypeError::Json(e);
            let msg = format!("{te}");
            assert!(msg.contains("json error:"));
        }
        Ok(_) => panic!("expected error"),
    }
}
