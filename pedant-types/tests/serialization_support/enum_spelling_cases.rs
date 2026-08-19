//! Every closed enum's text spelling, in both directions.
//!
//! These are the tokens other tools read. A variant renamed in Rust is a source
//! change; a variant renamed on the wire is a break for every consumer of a
//! stored attestation, so each spelling is asserted rather than inferred from a
//! round trip alone.

use pedant_types::resolution::{ReferenceKind, SymbolKind};
use pedant_types::{AnalysisTier, Capability, ExecutionContext, FindingOrigin, Language};

/// Every definition kind a resolution report can state, beside its exact wire
/// token.
///
/// The shared report vocabulary is one closed set for every language it carries,
/// so a Go definition kind and a Rust one are spelled here together. A token is
/// a break for every consumer of a stored report, which is why each is written
/// out rather than derived from the variant name a round trip would agree with.
const RESOLUTION_SYMBOL_KINDS: [(SymbolKind, &str); 15] = [
    (SymbolKind::Module, "module"),
    (SymbolKind::Function, "function"),
    (SymbolKind::Method, "method"),
    (SymbolKind::Struct, "struct"),
    (SymbolKind::Enum, "enum"),
    (SymbolKind::Union, "union"),
    (SymbolKind::Trait, "trait"),
    (SymbolKind::TypeAlias, "type_alias"),
    (SymbolKind::Constant, "constant"),
    (SymbolKind::Static, "static"),
    (SymbolKind::Package, "package"),
    (SymbolKind::Interface, "interface"),
    (SymbolKind::DefinedType, "defined_type"),
    (SymbolKind::Variable, "variable"),
    (SymbolKind::Field, "field"),
];

/// Every reference kind a resolution report can state, beside its exact wire
/// token.
const RESOLUTION_REFERENCE_KINDS: [(ReferenceKind, &str); 6] = [
    (ReferenceKind::Module, "module"),
    (ReferenceKind::Import, "import"),
    (ReferenceKind::Call, "call"),
    (ReferenceKind::Type, "type"),
    (ReferenceKind::Implementation, "implementation"),
    (ReferenceKind::Value, "value"),
];

/// The ten definition and five reference kinds the Rust-only vocabulary
/// published, which no later language may respell or reorder.
const PUBLISHED_SYMBOL_KINDS: usize = 10;
const PUBLISHED_REFERENCE_KINDS: usize = 5;

/// Every resolution kind serializes to its exact token and reads back.
///
/// The published prefix is held in place as a prefix: a Go kind inserted among
/// the Rust ones would keep every token spelled correctly while changing the
/// order the derived comparison and the sorted collections read, so the earlier
/// spellings are asserted in position rather than as a set.
pub fn assert_resolution_vocabulary_spellings() {
    for (kind, token) in RESOLUTION_SYMBOL_KINDS {
        assert_round_trip(kind, token);
    }
    for (kind, token) in RESOLUTION_REFERENCE_KINDS {
        assert_round_trip(kind, token);
    }

    let published: Box<[&str]> = RESOLUTION_SYMBOL_KINDS[..PUBLISHED_SYMBOL_KINDS]
        .iter()
        .map(|(_, token)| *token)
        .collect();
    assert_eq!(
        *published,
        [
            "module",
            "function",
            "method",
            "struct",
            "enum",
            "union",
            "trait",
            "type_alias",
            "constant",
            "static",
        ],
        "the published definition spellings keep their tokens and their order"
    );
    let published: Box<[&str]> = RESOLUTION_REFERENCE_KINDS[..PUBLISHED_REFERENCE_KINDS]
        .iter()
        .map(|(_, token)| *token)
        .collect();
    assert_eq!(
        *published,
        ["module", "import", "call", "type", "implementation"],
        "the published reference spellings keep their tokens and their order"
    );

    assert!(
        RESOLUTION_SYMBOL_KINDS[PUBLISHED_SYMBOL_KINDS..]
            .iter()
            .any(|(kind, _)| *kind == SymbolKind::Package),
        "the Go definition vocabulary is stated after the published prefix"
    );
    assert!(
        RESOLUTION_REFERENCE_KINDS[PUBLISHED_REFERENCE_KINDS..]
            .iter()
            .any(|(kind, _)| *kind == ReferenceKind::Value),
        "the Go reference vocabulary is stated after the published prefix"
    );
}

/// One closed-vocabulary value spells `token` on the wire and reads back equal.
fn assert_round_trip<T>(value: T, token: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug + Copy,
{
    let encoded = serde_json::to_string(&value).expect("a closed enum serializes");
    assert_eq!(
        encoded,
        format!("\"{token}\""),
        "{value:?} must spell itself {token}"
    );
    let restored: T = serde_json::from_str(&encoded).expect("its own token deserializes");
    assert_eq!(restored, value, "{value:?} round trips through {token}");
}

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
