//! Every closed enum's text spelling, in both directions.
//!
//! These are the tokens other tools read. A variant renamed in Rust is a source
//! change; a variant renamed on the wire is a break for every consumer of a
//! stored attestation, so each spelling is asserted rather than inferred from a
//! round trip alone.

use pedant_types::{AnalysisTier, Capability, ExecutionContext, FindingOrigin, Language};

/// Every capability, so a new variant that skips a round trip is visible here.
const ALL_CAPABILITIES: [Capability; 10] = [
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
    for cap in ALL_CAPABILITIES {
        let json = serde_json::to_string(&cap).unwrap();
        let back: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, back);
    }
}

#[test]
fn capability_display_matches_from_str() {
    for cap in ALL_CAPABILITIES {
        let display = cap.to_string();
        let parsed: Capability = display.parse().unwrap();
        assert_eq!(cap, parsed, "Display/FromStr mismatch for {cap:?}");
    }
}

#[test]
fn language_enum_round_trip() {
    let variants = [
        Language::Rust,
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
