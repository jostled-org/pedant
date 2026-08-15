//! The shared capability-analysis envelope: wire shape, decode boundary, merge.
//!
//! A library consumer reads this envelope to learn which callable owns a
//! finding, so its field order, enum tokens, and unknown-field refusal are the
//! contract — not an implementation detail. The flat `CapabilityProfile` inside
//! it stays byte-identical to the one attestations and baselines already store.
//!
//! Decoding checks structure only. The subset, uniqueness, and non-empty rules
//! the spec states are guarantees for analyses Pedant emits; producer tests own
//! them. A structurally valid external document may state inconsistent facts,
//! exactly as an external `CapabilityProfile` may today, so the cases below fix
//! that boundary rather than leaving it to a reader's assumption.

use std::fmt::Debug;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use pedant_types::{
    Capability, CapabilityAnalysis, CapabilityFinding, CapabilityProfile, CapabilitySymbol,
    CapabilitySymbolKind, Language, SourceLocation, SymbolAttributionStatus,
    SymbolCapabilityProfile,
};

use crate::finding_fixture::sample_finding;

/// Every attribution status, so a new variant that skips a case is visible here.
const ALL_STATUSES: [SymbolAttributionStatus; 3] = [
    SymbolAttributionStatus::Complete,
    SymbolAttributionStatus::Unavailable,
    SymbolAttributionStatus::NotApplicable,
];

/// The one flat finding both the standalone and nested shape assertions use.
const NETWORK_FINDING_JSON: &str = r#"{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}"#;

/// The second flat finding, owned by no symbol in the sample envelope.
const FILE_READ_FINDING_JSON: &str = r#"{"capability":"file_read","location":{"file":"a.py","line":7,"column":1},"evidence":"test evidence"}"#;

/// The complete sample envelope, stated once so field order cannot be inferred.
const SAMPLE_ANALYSIS_JSON: &str = r#"{"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"},{"capability":"file_read","location":{"file":"a.py","line":7,"column":1},"evidence":"test evidence"}]},"symbol_attribution":"complete","symbols":[{"symbol":{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]}}]}"#;

/// A Python callable declared at `line` in `a.py`.
fn symbol(kind: CapabilitySymbolKind, name: &str, line: usize) -> CapabilitySymbol {
    CapabilitySymbol {
        language: Language::Python,
        kind,
        name: Box::from(name),
        declaration: SourceLocation {
            file: Arc::from("a.py"),
            line,
            column: 1,
        },
    }
}

/// One callable holding exactly `findings`.
fn owned(symbol: CapabilitySymbol, findings: Vec<CapabilityFinding>) -> SymbolCapabilityProfile {
    SymbolCapabilityProfile {
        symbol,
        profile: CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
    }
}

/// An envelope over exactly these flat findings, status, and symbol profiles.
fn analysis(
    findings: Vec<CapabilityFinding>,
    symbol_attribution: SymbolAttributionStatus,
    symbols: Vec<SymbolCapabilityProfile>,
) -> CapabilityAnalysis {
    CapabilityAnalysis {
        profile: CapabilityProfile {
            findings: findings.into_boxed_slice(),
        },
        symbol_attribution,
        symbols: symbols.into_boxed_slice(),
    }
}

/// The envelope `SAMPLE_ANALYSIS_JSON` spells out.
fn sample_analysis() -> CapabilityAnalysis {
    analysis(
        vec![
            sample_finding(Capability::Network, "a.py", 3),
            sample_finding(Capability::FileRead, "a.py", 7),
        ],
        SymbolAttributionStatus::Complete,
        vec![owned(
            symbol(CapabilitySymbolKind::Function, "fetch", 2),
            vec![sample_finding(Capability::Network, "a.py", 3)],
        )],
    )
}

/// Each envelope type is a cloneable, comparable, serializable fact bag.
///
/// The bound is the assertion: a derive dropped from any of the five types
/// stops this call from compiling.
fn assert_capability_wire_type<T>()
where
    T: Serialize + DeserializeOwned + Clone + Debug + PartialEq + Eq,
{
}

/// `json` decodes back to the value it was written from.
fn assert_round_trip<T>(value: &T, json: &str)
where
    T: Serialize + DeserializeOwned + Debug + PartialEq,
{
    assert_eq!(serde_json::to_string(value).unwrap(), json);
    let back: T = serde_json::from_str(json).unwrap();
    assert_eq!(&back, value);
}

/// A field the struct does not declare is a decode error, not a silent drop.
fn assert_unknown_field_is_refused<T: DeserializeOwned + Debug>(json: &str, label: &str) {
    let error = serde_json::from_str::<T>(json).expect_err(label);
    assert!(
        error.to_string().contains("unknown field"),
        "{label}: expected an unknown-field refusal, got {error}"
    );
}

/// The tokens a non-Rust consumer reads for each new closed enum.
fn assert_enum_tokens() {
    assert_eq!(
        serde_json::to_string(&CapabilitySymbolKind::Function).unwrap(),
        "\"function\""
    );
    assert_eq!(
        serde_json::to_string(&CapabilitySymbolKind::Method).unwrap(),
        "\"method\""
    );
    assert_eq!(
        serde_json::to_string(&SymbolAttributionStatus::Complete).unwrap(),
        "\"complete\""
    );
    assert_eq!(
        serde_json::to_string(&SymbolAttributionStatus::Unavailable).unwrap(),
        "\"unavailable\""
    );
    assert_eq!(
        serde_json::to_string(&SymbolAttributionStatus::NotApplicable).unwrap(),
        "\"not_applicable\""
    );

    for kind in [CapabilitySymbolKind::Function, CapabilitySymbolKind::Method] {
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(
            serde_json::from_str::<CapabilitySymbolKind>(&json).unwrap(),
            kind
        );
    }
    for status in ALL_STATUSES {
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<SymbolAttributionStatus>(&json).unwrap(),
            status
        );
    }
}

/// Exact field names and order at every level of the envelope.
fn assert_exact_wire_shape() {
    let value = sample_analysis();
    assert_round_trip(&value, SAMPLE_ANALYSIS_JSON);
    assert_round_trip(
        &value.symbols[0],
        r#"{"symbol":{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]}}"#,
    );
    assert_round_trip(
        &value.symbols[0].symbol,
        r#"{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}}"#,
    );
}

/// The flat profile and finding shapes attestations store did not change.
fn assert_flat_shapes_are_unchanged() {
    let finding = sample_finding(Capability::Network, "a.py", 3);
    assert_round_trip(&finding, NETWORK_FINDING_JSON);
    assert_round_trip(
        &sample_finding(Capability::FileRead, "a.py", 7),
        FILE_READ_FINDING_JSON,
    );

    let profile = sample_analysis().into_profile();
    assert_round_trip(
        &profile,
        &format!("{{\"findings\":[{NETWORK_FINDING_JSON},{FILE_READ_FINDING_JSON}]}}"),
    );
    assert!(
        SAMPLE_ANALYSIS_JSON.contains(NETWORK_FINDING_JSON),
        "the nested flat finding must use the unchanged finding shape"
    );
}

/// Every new struct rejects a field it does not declare.
fn assert_unknown_fields_are_refused() {
    assert_unknown_field_is_refused::<CapabilitySymbol>(
        r#"{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1},"qualified_path":"a.fetch"}"#,
        "CapabilitySymbol carries no qualified path",
    );
    assert_unknown_field_is_refused::<SymbolCapabilityProfile>(
        r#"{"symbol":{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[]},"definition_id":4}"#,
        "SymbolCapabilityProfile carries no resolution identity",
    );
    assert_unknown_field_is_refused::<CapabilityAnalysis>(
        r#"{"profile":{"findings":[]},"symbol_attribution":"complete","symbols":[],"tier":"semantic"}"#,
        "CapabilityAnalysis carries no analysis tier",
    );
}

/// Borrowed parts, delegated flat queries, and the consuming flat projection.
fn assert_accessors_and_queries() {
    let value = sample_analysis();
    assert_eq!(value.profile(), &value.profile);
    assert_eq!(
        value.symbol_attribution(),
        SymbolAttributionStatus::Complete
    );
    assert_eq!(value.symbols(), &*value.symbols);

    assert_eq!(
        &*value.capabilities(),
        &[Capability::Network, Capability::FileRead]
    );
    assert_eq!(value.findings_for(Capability::Network).count(), 1);
    assert_eq!(value.findings_for(Capability::FileRead).count(), 1);
    assert_eq!(value.findings_for(Capability::Crypto).count(), 0);

    let expected = value.profile.clone();
    assert_eq!(value.into_profile(), expected);
}

#[test]
fn capability_analysis_wire_shape_and_accessors_are_exact() {
    assert_capability_wire_type::<CapabilitySymbolKind>();
    assert_capability_wire_type::<CapabilitySymbol>();
    assert_capability_wire_type::<SymbolAttributionStatus>();
    assert_capability_wire_type::<SymbolCapabilityProfile>();
    assert_capability_wire_type::<CapabilityAnalysis>();

    assert_enum_tokens();
    assert_exact_wire_shape();
    assert_flat_shapes_are_unchanged();
    assert_unknown_fields_are_refused();
    assert_accessors_and_queries();
}

#[test]
fn capability_analysis_decode_is_structural_not_relational() {
    // A symbol owns a finding the flat profile never states.
    let orphan = r#"{"profile":{"findings":[]},"symbol_attribution":"complete","symbols":[{"symbol":{"language":"python","kind":"method","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]}}]}"#;
    let decoded: CapabilityAnalysis = serde_json::from_str(orphan).unwrap();
    assert!(decoded.profile.findings.is_empty());
    assert_eq!(decoded.symbols[0].profile.findings.len(), 1);
    assert_eq!(decoded.symbols[0].symbol.kind, CapabilitySymbolKind::Method);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), orphan);

    // A symbol profile holds no finding at all.
    let empty = r#"{"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]},"symbol_attribution":"complete","symbols":[{"symbol":{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[]}}]}"#;
    let decoded: CapabilityAnalysis = serde_json::from_str(empty).unwrap();
    assert!(decoded.symbols[0].profile.findings.is_empty());
    assert_eq!(serde_json::to_string(&decoded).unwrap(), empty);

    // Two symbols claim the same single flat occurrence.
    let duplicate = r#"{"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]},"symbol_attribution":"complete","symbols":[{"symbol":{"language":"python","kind":"function","name":"fetch","declaration":{"file":"a.py","line":2,"column":1}},"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]}},{"symbol":{"language":"python","kind":"function","name":"send","declaration":{"file":"a.py","line":9,"column":1}},"profile":{"findings":[{"capability":"network","location":{"file":"a.py","line":3,"column":1},"evidence":"test evidence"}]}}]}"#;
    let decoded: CapabilityAnalysis = serde_json::from_str(duplicate).unwrap();
    assert_eq!(decoded.profile.findings.len(), 1);
    assert_eq!(decoded.symbols.len(), 2);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), duplicate);
}

/// Every ordered status pair, and the one closed precedence merge applies.
fn assert_status_precedence() {
    use SymbolAttributionStatus::{Complete, NotApplicable, Unavailable};

    let pairs = [
        (Complete, Complete, Complete),
        (Complete, Unavailable, Unavailable),
        (Complete, NotApplicable, Complete),
        (Unavailable, Complete, Unavailable),
        (Unavailable, Unavailable, Unavailable),
        (Unavailable, NotApplicable, Unavailable),
        (NotApplicable, Complete, Complete),
        (NotApplicable, Unavailable, Unavailable),
        (NotApplicable, NotApplicable, NotApplicable),
    ];
    assert_eq!(pairs.len(), ALL_STATUSES.len() * ALL_STATUSES.len());

    for (left, right, expected) in pairs {
        let merged = analysis(vec![], left, vec![]).merge(analysis(vec![], right, vec![]));
        assert_eq!(
            merged.symbol_attribution, expected,
            "{left:?} merged with {right:?}"
        );
    }
}

/// An `Unavailable` result keeps the evidence a complete operand proved.
fn assert_unavailable_retains_proven_symbols() {
    let complete = analysis(
        vec![sample_finding(Capability::Network, "a.py", 3)],
        SymbolAttributionStatus::Complete,
        vec![owned(
            symbol(CapabilitySymbolKind::Function, "fetch", 2),
            vec![sample_finding(Capability::Network, "a.py", 3)],
        )],
    );
    let unavailable = analysis(
        vec![sample_finding(Capability::FileRead, "b.py", 4)],
        SymbolAttributionStatus::Unavailable,
        vec![],
    );

    let merged = complete.merge(unavailable);
    assert_eq!(
        merged.symbol_attribution,
        SymbolAttributionStatus::Unavailable
    );
    assert_eq!(merged.symbols.len(), 1);
    assert_eq!(&*merged.symbols[0].symbol.name, "fetch");
    assert_eq!(merged.profile.findings.len(), 2);
}

/// The capabilities a profile states, in the order it states them.
fn capability_sequence(profile: &CapabilityProfile) -> Box<[Capability]> {
    profile
        .findings
        .iter()
        .map(|finding| finding.capability)
        .collect()
}

/// What distinguishes one merged symbol from the next.
fn symbol_identities(merged: &CapabilityAnalysis) -> Box<[(CapabilitySymbolKind, &str, usize)]> {
    merged
        .symbols
        .iter()
        .map(|entry| {
            (
                entry.symbol.kind,
                &*entry.symbol.name,
                entry.symbol.declaration.line,
            )
        })
        .collect()
}

/// Two callables sharing a name at different declarations.
fn merge_left_operand() -> CapabilityAnalysis {
    analysis(
        vec![
            sample_finding(Capability::Network, "a.py", 3),
            sample_finding(Capability::FileRead, "a.py", 10),
        ],
        SymbolAttributionStatus::Complete,
        vec![
            owned(
                symbol(CapabilitySymbolKind::Function, "fetch", 2),
                vec![sample_finding(Capability::Network, "a.py", 3)],
            ),
            owned(
                symbol(CapabilitySymbolKind::Function, "fetch", 9),
                vec![sample_finding(Capability::FileRead, "a.py", 10)],
            ),
        ],
    )
}

/// One exact collision with `fetch@2`, and one callable of the other kind that
/// is otherwise identical to it.
fn merge_right_operand() -> CapabilityAnalysis {
    analysis(
        vec![
            sample_finding(Capability::Crypto, "a.py", 5),
            sample_finding(Capability::EnvAccess, "a.py", 21),
        ],
        SymbolAttributionStatus::Complete,
        vec![
            owned(
                symbol(CapabilitySymbolKind::Function, "fetch", 2),
                vec![sample_finding(Capability::Crypto, "a.py", 5)],
            ),
            owned(
                symbol(CapabilitySymbolKind::Method, "fetch", 2),
                vec![sample_finding(Capability::EnvAccess, "a.py", 21)],
            ),
        ],
    )
}

/// Operand order, declaration order, and finding order inside one profile.
fn assert_merge_order_and_identity() {
    let merged = merge_left_operand().merge(merge_right_operand());

    assert_eq!(
        &*capability_sequence(&merged.profile),
        &[
            Capability::Network,
            Capability::FileRead,
            Capability::Crypto,
            Capability::EnvAccess
        ],
        "flat findings keep operand order"
    );
    assert_eq!(
        &*symbol_identities(&merged),
        &[
            (CapabilitySymbolKind::Function, "fetch", 2),
            (CapabilitySymbolKind::Function, "fetch", 9),
            (CapabilitySymbolKind::Method, "fetch", 2),
        ],
        "collisions coalesce in place; every other identity appends in order"
    );
    assert_eq!(
        &*capability_sequence(&merged.symbols[0].profile),
        &[Capability::Network, Capability::Crypto],
        "a coalesced profile keeps its position and appends the second findings"
    );
    assert_eq!(merged.symbols[1].profile.findings.len(), 1);
    assert_eq!(merged.symbols[2].profile.findings.len(), 1);
}

/// Merge counts occurrences; it never deduplicates an equal finding.
fn assert_equal_occurrences_are_retained() {
    let repeated = || {
        analysis(
            vec![sample_finding(Capability::Network, "a.py", 3)],
            SymbolAttributionStatus::Complete,
            vec![owned(
                symbol(CapabilitySymbolKind::Function, "fetch", 2),
                vec![sample_finding(Capability::Network, "a.py", 3)],
            )],
        )
    };

    let merged = repeated().merge(repeated());
    assert_eq!(merged.profile.findings.len(), 2);
    assert_eq!(merged.profile.findings[0], merged.profile.findings[1]);
    assert_eq!(merged.symbols.len(), 1);
    assert_eq!(merged.symbols[0].profile.findings.len(), 2);
    assert_eq!(&*merged.capabilities(), &[Capability::Network]);
}

#[test]
fn capability_analysis_merge_order_status_and_identity_are_exact() {
    assert_status_precedence();
    assert_unavailable_retains_proven_symbols();
    assert_merge_order_and_identity();
    assert_equal_occurrences_are_retained();
}
