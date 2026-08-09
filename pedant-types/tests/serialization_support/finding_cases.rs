//! One capability finding, and what its optional fields do on the wire.
//!
//! Every optional field is skipped when absent. That is what keeps a stored
//! attestation from growing nulls it never had, so each field asserts both the
//! omission and the value it carries when present.

use std::sync::Arc;

use pedant_types::{
    Capability, CapabilityFinding, ExecutionContext, FindingOrigin, Language, SourceLocation,
};

use crate::finding_fixture::sample_finding;

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
