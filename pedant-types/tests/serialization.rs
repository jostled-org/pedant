use std::sync::Arc;

use pedant_types::{
    AnalysisTier, AttestationContent, Capability, CapabilityDiff, CapabilityFinding,
    CapabilityProfile, ExecutionContext, FindingOrigin, Language, SourceLocation,
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
        origin: None,
        language: None,
        execution_context: None,
        reachable: None,
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
        ]
        .into_boxed_slice(),
    };
    let caps = profile.capabilities();
    assert_eq!(
        caps,
        vec![Capability::Network, Capability::FileRead].into_boxed_slice()
    );
}

#[test]
fn profile_findings_for_filters() {
    let profile = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
            sample_finding(Capability::Network, "c.rs", 3),
        ]
        .into_boxed_slice(),
    };
    assert_eq!(profile.findings_for(Capability::Network).count(), 2);
    assert_eq!(profile.findings_for(Capability::FileRead).count(), 1);
    assert_eq!(profile.findings_for(Capability::Crypto).count(), 0);
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
        spec_version: Box::from("1.0"),
        source_hash: Box::from("abc123"),
        crate_name: Box::from("my-crate"),
        crate_version: Box::from("0.1.0"),
        analysis_tier: AnalysisTier::Syntactic,
        timestamp: 1_700_000_000,
        profile: CapabilityProfile {
            findings: vec![sample_finding(Capability::Ffi, "src/lib.rs", 5)].into_boxed_slice(),
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
        ]
        .into_boxed_slice(),
    };
    let new = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::Crypto, "c.rs", 3),
        ]
        .into_boxed_slice(),
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
        findings: vec![sample_finding(Capability::Network, "a.rs", 1)].into_boxed_slice(),
    };
    let new = CapabilityProfile {
        findings: vec![sample_finding(Capability::FileWrite, "b.rs", 2)].into_boxed_slice(),
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
        findings: vec![sample_finding(Capability::Network, "a.rs", 1)].into_boxed_slice(),
    };
    let new = CapabilityProfile {
        findings: vec![sample_finding(Capability::Crypto, "b.rs", 2)].into_boxed_slice(),
    };
    let diff = CapabilityDiff::compute(&old, &new);
    let json = serde_json::to_string(&diff).unwrap();
    let back: CapabilityDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, back);
}

#[test]
fn capability_finding_reachable_none_omitted() {
    let finding = sample_finding(Capability::Network, "src/lib.rs", 10);
    assert!(finding.reachable.is_none());

    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        !json.contains("reachable"),
        "JSON should not contain 'reachable' when None, got: {json}"
    );

    // Round-trip: deserializing JSON without reachable yields None
    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert!(back.reachable.is_none());
}

#[test]
fn capability_finding_reachable_some_serialized() {
    let finding = CapabilityFinding {
        reachable: Some(true),
        ..sample_finding(Capability::Network, "src/lib.rs", 10)
    };
    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        json.contains(r#""reachable":true"#),
        "JSON should contain reachable: true, got: {json}"
    );

    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.reachable, Some(true));

    // Also test Some(false)
    let finding_false = CapabilityFinding {
        reachable: Some(false),
        ..sample_finding(Capability::FileRead, "src/lib.rs", 5)
    };
    let json_false = serde_json::to_string(&finding_false).unwrap();
    assert!(
        json_false.contains(r#""reachable":false"#),
        "JSON should contain reachable: false, got: {json_false}"
    );

    let back_false: CapabilityFinding = serde_json::from_str(&json_false).unwrap();
    assert_eq!(back_false.reachable, Some(false));
}

// --- Step 1 tests: Language, ExecutionContext, migration ---

#[test]
fn language_enum_round_trip() {
    let variants = [
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Go,
        Language::Bash,
    ];
    for lang in variants {
        let json = serde_json::to_string(&lang).unwrap();
        let back: Language = serde_json::from_str(&json).unwrap();
        assert_eq!(lang, back);
    }
}

#[test]
fn execution_context_round_trip() {
    let variants = [
        ExecutionContext::Runtime,
        ExecutionContext::BuildHook,
        ExecutionContext::InstallHook,
        ExecutionContext::Generator,
    ];
    for ctx in variants {
        let json = serde_json::to_string(&ctx).unwrap();
        let back: ExecutionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }
}

#[test]
fn capability_finding_language_none_omitted() {
    let finding = sample_finding(Capability::Network, "src/lib.rs", 10);
    assert!(finding.language.is_none());
    assert!(finding.execution_context.is_none());

    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        !json.contains("language"),
        "JSON should not contain 'language' when None, got: {json}"
    );
    assert!(
        !json.contains("execution_context"),
        "JSON should not contain 'execution_context' when None, got: {json}"
    );
    assert!(
        !json.contains("build_script"),
        "JSON should not contain 'build_script' (field removed), got: {json}"
    );

    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn capability_finding_language_some_serialized() {
    let finding = CapabilityFinding {
        language: Some(Language::Python),
        execution_context: Some(ExecutionContext::InstallHook),
        ..sample_finding(Capability::ProcessExec, "setup.py", 5)
    };
    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        json.contains(r#""language":"python""#),
        "JSON should contain language: python, got: {json}"
    );
    assert!(
        json.contains(r#""execution_context":"install_hook""#),
        "JSON should contain execution_context: install_hook, got: {json}"
    );

    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn capability_finding_origin_none_omitted() {
    let finding = sample_finding(Capability::Network, "src/lib.rs", 10);
    assert!(finding.origin.is_none());

    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        !json.contains("origin"),
        "JSON should not contain 'origin' when None, got: {json}"
    );

    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert!(back.origin.is_none());
}

#[test]
fn capability_finding_origin_round_trip() {
    let variants = [
        FindingOrigin::Import,
        FindingOrigin::StringLiteral,
        FindingOrigin::Attribute,
        FindingOrigin::CodeSite,
        FindingOrigin::ManifestHook,
    ];
    for origin in variants {
        let json = serde_json::to_string(&origin).unwrap();
        let back: FindingOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(origin, back, "round-trip failed for {origin:?}");
    }
}

#[test]
fn capability_finding_with_origin_serialized() {
    let finding = CapabilityFinding {
        origin: Some(FindingOrigin::Import),
        ..sample_finding(Capability::Crypto, "src/lib.rs", 5)
    };
    let json = serde_json::to_string(&finding).unwrap();
    assert!(
        json.contains(r#""origin":"import""#),
        "JSON should contain origin: import, got: {json}"
    );

    let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn capability_finding_origin_all_variants_in_finding() {
    let origins = [
        (FindingOrigin::Import, "import"),
        (FindingOrigin::StringLiteral, "string_literal"),
        (FindingOrigin::Attribute, "attribute"),
        (FindingOrigin::CodeSite, "code_site"),
        (FindingOrigin::ManifestHook, "manifest_hook"),
    ];
    for (origin, expected_str) in origins {
        let finding = CapabilityFinding {
            origin: Some(origin),
            ..sample_finding(Capability::Network, "src/lib.rs", 1)
        };
        let json = serde_json::to_string(&finding).unwrap();
        let expected = format!(r#""origin":"{expected_str}""#);
        assert!(
            json.contains(&expected),
            "expected {expected} in JSON, got: {json}"
        );
        let back: CapabilityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }
}

#[test]
fn capability_display_matches_from_str() {
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
        let display = cap.to_string();
        let parsed: Capability = display.parse().unwrap();
        assert_eq!(cap, parsed, "Display/FromStr mismatch for {cap:?}");
    }
}

#[test]
fn capability_finding_build_script_migration() {
    // Legacy JSON with "build_script": true should deserialize to BuildHook
    let legacy_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true
    }"#;
    let finding: CapabilityFinding = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(
        finding.execution_context,
        Some(ExecutionContext::BuildHook),
        "build_script: true should map to ExecutionContext::BuildHook"
    );
    assert!(finding.language.is_none());

    // Legacy JSON with "build_script": false should deserialize to None
    let legacy_false = r#"{
        "capability": "file_read",
        "location": {"file": "src/lib.rs", "line": 5, "column": 1},
        "evidence": "std::fs::read",
        "build_script": false
    }"#;
    let finding_false: CapabilityFinding = serde_json::from_str(legacy_false).unwrap();
    assert_eq!(finding_false.execution_context, None);

    // Consistent legacy and new fields may coexist.
    let both_consistent_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true,
        "execution_context": "build_hook"
    }"#;
    let finding_both: CapabilityFinding = serde_json::from_str(both_consistent_json).unwrap();
    assert_eq!(
        finding_both.execution_context,
        Some(ExecutionContext::BuildHook)
    );

    // Contradictory legacy and new fields are rejected.
    let both_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": true,
        "execution_context": "runtime"
    }"#;
    let error = serde_json::from_str::<CapabilityFinding>(both_json)
        .expect_err("contradictory execution_context and build_script should fail");
    assert!(
        error
            .to_string()
            .contains("contradicts legacy build_script=true"),
        "unexpected error: {error}"
    );
}

#[test]
fn capability_finding_rejects_build_hook_with_legacy_false() {
    let contradictory_json = r#"{
        "capability": "network",
        "location": {"file": "build.rs", "line": 10, "column": 1},
        "evidence": "reqwest::get",
        "build_script": false,
        "execution_context": "build_hook"
    }"#;

    let error = serde_json::from_str::<CapabilityFinding>(contradictory_json)
        .expect_err("build_hook with build_script=false should fail");
    assert!(
        error
            .to_string()
            .contains("contradicts legacy build_script=false"),
        "unexpected error: {error}"
    );
}
