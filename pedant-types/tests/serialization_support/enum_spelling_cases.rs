//! Every closed enum's text spelling, in both directions.
//!
//! These are the tokens other tools read. A variant renamed in Rust is a source
//! change; a variant renamed on the wire is a break for every consumer of a
//! stored attestation, so each spelling is asserted rather than inferred from a
//! round trip alone.

use pedant_types::resolution::{ReferenceKind, SymbolKind};
use pedant_types::{
    AnalysisTier, Capability, ExecutionContext, FindingOrigin, Language, StructureKind,
};

/// Declare one vocabulary's variant list and its exhaustive spelling from a
/// single written-down table.
///
/// A hand-written array of listed variants keeps compiling when the model gains
/// one: only an exhaustive match breaks, and the array silently stays a row
/// short. Generating both from one list closes that. The match fails to compile
/// until the new variant is listed, listing it grows the array, and the array is
/// then what the model's own published list is measured against.
macro_rules! stated_vocabulary {
    ($enum:ident, $listed:ident, $spelling:ident, $($variant:ident => $token:literal),+ $(,)?) => {
        /// Every variant this root states for the vocabulary, in the order the
        /// model declares them.
        const $listed: [$enum; [$(stringify!($variant)),+].len()] = [$($enum::$variant),+];

        /// The token this root states for one variant, independently of the
        /// model's own `token` method.
        fn $spelling(value: $enum) -> &'static str {
            match value {
                $($enum::$variant => $token),+
            }
        }
    };
}

stated_vocabulary!(
    StructureKind,
    STATED_STRUCTURE_KINDS,
    structure_kind_spelling,
    Module => "module",
    Function => "function",
    Method => "method",
    Struct => "struct",
    Enum => "enum",
    Union => "union",
    Trait => "trait",
    TypeAlias => "type_alias",
    Impl => "impl",
    Class => "class",
    Interface => "interface",
    DefinedType => "defined_type",
    Constant => "constant",
    Static => "static",
    Variable => "variable",
    Field => "field",
    Package => "package",
);

stated_vocabulary!(
    Language,
    STATED_LANGUAGES,
    language_spelling,
    Rust => "rust",
    Python => "python",
    JavaScript => "java_script",
    TypeScript => "type_script",
    Go => "go",
    Bash => "bash",
);

/// The published structure vocabulary is the whole model, in order, and every
/// token it claims is the token serde writes.
#[test]
fn structure_kind_publishes_every_variant_and_its_wire_token() {
    assert_published(
        &STATED_STRUCTURE_KINDS,
        &StructureKind::ALL,
        structure_kind_spelling,
        StructureKind::token,
        "StructureKind",
    );
}

/// The published language vocabulary is the whole model, in order, and every
/// token it claims is the token serde writes.
#[test]
fn language_publishes_every_variant_and_its_wire_token() {
    assert_published(
        &STATED_LANGUAGES,
        &Language::ALL,
        language_spelling,
        Language::token,
        "Language",
    );
}

/// One published vocabulary states exactly the variants this root lists, in the
/// same order, each claiming the token serde spells it with.
///
/// The length is asserted against the generated list rather than a written
/// number, because a number is what a new variant leaves stale. A schema built
/// from a list one variant short accepts a token it never advertised, which is
/// the failure this guard exists for.
fn assert_published<T>(
    listed: &[T],
    published: &[T],
    stated: fn(T) -> &'static str,
    claimed: fn(T) -> &'static str,
    vocabulary: &str,
) where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug + Copy,
{
    assert_eq!(
        published.len(),
        listed.len(),
        "{vocabulary}::ALL publishes one entry per declared variant"
    );
    for (position, value) in listed.iter().copied().enumerate() {
        assert_eq!(
            published[position], value,
            "{vocabulary}::ALL states {value:?} at position {position}"
        );
        let token = stated(value);
        assert_eq!(
            claimed(value),
            token,
            "{vocabulary}::token claims the spelling this root states for {value:?}"
        );
        assert_round_trip(value, token);
    }
}

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
