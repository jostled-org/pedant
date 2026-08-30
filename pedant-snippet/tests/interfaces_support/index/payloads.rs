//! Changing what one input carries changes the claim, kind by kind.
//!
//! One pair per kind that carries anything: the kind is held constant and the
//! payload moves, which is the half [`claims`](super::claims) cannot see. That
//! table proves each kind is separately tagged; this one proves each tag's
//! payload reaches the digest.
//!
//! The pairs are stated in three tables and the enumerations in a fourth,
//! because one table of every payload is a body no reader can hold at once.
//! Which table a pair sits in changes nothing: each is walked the same way and
//! hands back the kinds it moved. Those kinds are held to
//! [`Kind::ALL`](super::claims), because "one pair per kind" was a sentence here
//! and nowhere in the code — a kind added to the registry earns a `witness` row
//! next door by the compiler, and would otherwise arrive with its payload never
//! perturbed and nothing red.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;

use pedant_snippet::{
    AdmittedPathKind, IndexRevision, IssueCode, IssueScope, IssueStage, PagedQuery, QueryField,
    RevisionClaim, RevisionClaimInput, StateRevision,
};
use pedant_types::Language;

use super::claims::{Held, Kind, assert_distinct_digests, field, held, kind_of, sealed};

/// Everything one input carries reaches the claim, and every kind has a row.
pub(super) fn every_payload_reaches_the_claim() {
    let held = held();
    let other_digest = [0xAA_u8; 32];
    let other_identity = perturbed().seal_index();
    let other_published = perturbed().seal_state();
    let other_scope = IssueScope::Project {
        authority: Arc::from("a"),
    };

    let moved: BTreeSet<Kind> = [
        assert_pairs_move(&corpus_payloads(&held, &other_digest)),
        assert_pairs_move(&project_and_issue_payloads(
            &held,
            &other_identity,
            &other_scope,
        )),
        assert_pairs_move(&cursor_payloads(&held, &other_published)),
        every_closed_enumeration_claims_its_own_bytes(),
    ]
    .iter()
    .flat_map(|kinds| kinds.iter().copied())
    .collect();

    assert_eq!(
        moved,
        Kind::ALL.into_iter().collect::<BTreeSet<Kind>>(),
        "every kind the registry states has a row here that moves its payload"
    );
}

/// The payloads that name which page of which query a cursor continues.
///
/// A cursor is not a revision, but it is claimed through the same registry and
/// answers the same rule. The presence pair is the one a revision claim never
/// needs — a filter nobody stated and one stated as the empty string select
/// different results, so they cannot claim the same bytes.
fn cursor_payloads<'claim>(
    held: &'claim Held,
    other_published: &'claim StateRevision,
) -> [(
    &'static str,
    RevisionClaimInput<'claim>,
    RevisionClaimInput<'claim>,
); 6] {
    [
        (
            "the state a cursor is taken over",
            RevisionClaimInput::StateIdentity(held.published()),
            RevisionClaimInput::StateIdentity(other_published),
        ),
        (
            "which paged query",
            RevisionClaimInput::QueryKind(PagedQuery::Projects),
            RevisionClaimInput::QueryKind(PagedQuery::Symbols),
        ),
        (
            "which query parameter",
            RevisionClaimInput::QueryParameter {
                field: QueryField::OwnerName,
                value: Some("a"),
            },
            RevisionClaimInput::QueryParameter {
                field: QueryField::PathPrefix,
                value: Some("a"),
            },
        ),
        (
            "whether a parameter was stated at all",
            RevisionClaimInput::QueryParameter {
                field: QueryField::OwnerName,
                value: Some(""),
            },
            RevisionClaimInput::QueryParameter {
                field: QueryField::OwnerName,
                value: None,
            },
        ),
        (
            "which numeric query parameter",
            RevisionClaimInput::QueryNumber {
                field: QueryField::PageSize,
                value: 1,
            },
            RevisionClaimInput::QueryNumber {
                field: QueryField::Offset,
                value: 1,
            },
        ),
        (
            "what the number holds",
            RevisionClaimInput::QueryNumber {
                field: QueryField::PageSize,
                value: 1,
            },
            RevisionClaimInput::QueryNumber {
                field: QueryField::PageSize,
                value: 2,
            },
        ),
    ]
}

/// Every pair holds its kind constant, claims two different digests, and names
/// the kind it moved.
///
/// The kind equality is what makes the digest difference a statement about the
/// payload: a pair whose sides were different kinds separates on the tag alone,
/// so it goes green over a field the encoder never wrote — the failure this
/// table exists to catch, now written into the table. An empty table refuses,
/// because a walk with no rows asserts nothing while reading as though it did.
fn assert_pairs_move(
    pairs: &[(&str, RevisionClaimInput<'_>, RevisionClaimInput<'_>)],
) -> Box<[Kind]> {
    assert!(!pairs.is_empty(), "a payload table states a pair");
    pairs
        .iter()
        .map(|(label, left, right)| {
            let kind = kind_of(left);
            assert_eq!(
                kind,
                kind_of(right),
                "{label}: a pair holds its kind constant, so what moved is the payload"
            );
            assert_ne!(
                sealed(&[*left]),
                sealed(&[*right]),
                "{label}: a claim that does not move is a claim that does not hold it"
            );
            kind
        })
        .collect()
}

/// The payloads that name what the corpus admitted: its schema, its languages,
/// its ceilings, its paths, and its bytes.
fn corpus_payloads<'claim>(
    held: &'claim Held,
    other_digest: &'claim [u8; 32],
) -> [(
    &'static str,
    RevisionClaimInput<'claim>,
    RevisionClaimInput<'claim>,
); 9] {
    [
        (
            "schema version",
            RevisionClaimInput::SchemaVersion(1),
            RevisionClaimInput::SchemaVersion(2),
        ),
        (
            "enabled language",
            RevisionClaimInput::EnabledLanguage(Language::Rust),
            RevisionClaimInput::EnabledLanguage(Language::Go),
        ),
        (
            "graph coverage",
            RevisionClaimInput::GraphCoverage(Language::Rust),
            RevisionClaimInput::GraphCoverage(Language::Go),
        ),
        (
            "which ceiling",
            RevisionClaimInput::Limit {
                field: field(0),
                value: 1,
            },
            RevisionClaimInput::Limit {
                field: field(1),
                value: 1,
            },
        ),
        (
            "what the ceiling holds",
            RevisionClaimInput::Limit {
                field: field(0),
                value: 1,
            },
            RevisionClaimInput::Limit {
                field: field(0),
                value: 2,
            },
        ),
        (
            "which kind of path was admitted",
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: "a",
            },
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Authority,
                path: "a",
            },
        ),
        (
            "the admitted path itself",
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: "a",
            },
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: "b",
            },
        ),
        (
            "source language",
            RevisionClaimInput::SourceLanguage(Language::Rust),
            RevisionClaimInput::SourceLanguage(Language::Python),
        ),
        (
            "digest",
            RevisionClaimInput::Digest(held.digest()),
            RevisionClaimInput::Digest(other_digest),
        ),
    ]
}

/// The payloads that name which project answered and what it had to say: its
/// keys, the index a state is taken over, and one issue's scope and message.
fn project_and_issue_payloads<'claim>(
    held: &'claim Held,
    other_identity: &'claim IndexRevision,
    other_scope: &'claim IssueScope,
) -> [(
    &'static str,
    RevisionClaimInput<'claim>,
    RevisionClaimInput<'claim>,
); 6] {
    [
        (
            "project language",
            RevisionClaimInput::ProjectLanguage(Language::Rust),
            RevisionClaimInput::ProjectLanguage(Language::Go),
        ),
        (
            "project authority",
            RevisionClaimInput::ProjectAuthority("a"),
            RevisionClaimInput::ProjectAuthority("b"),
        ),
        (
            "project unit",
            RevisionClaimInput::ProjectUnit("a"),
            RevisionClaimInput::ProjectUnit("b"),
        ),
        (
            "the index a state is taken over",
            RevisionClaimInput::IndexIdentity(held.identity()),
            RevisionClaimInput::IndexIdentity(other_identity),
        ),
        (
            "issue scope",
            RevisionClaimInput::IssueScope(held.scope()),
            RevisionClaimInput::IssueScope(other_scope),
        ),
        (
            "issue message",
            RevisionClaimInput::IssueMessage("a"),
            RevisionClaimInput::IssueMessage("b"),
        ),
    ]
}

/// Every issue code production declares, in the order it declares them.
///
/// None of these enumerations publishes a list of its own, so each is held by
/// the pair [`assert_closed`] describes: a written list, an exhaustive
/// `ordinal`.
const ISSUE_CODES: [IssueCode; 12] = [
    IssueCode::SymlinkEscape,
    IssueCode::PathEscape,
    IssueCode::PathEncoding,
    IssueCode::SourceUnreadable,
    IssueCode::SourceEncoding,
    IssueCode::InventoryIncomplete,
    IssueCode::LanguageUnavailable,
    IssueCode::AuthorityUnreadable,
    IssueCode::SnapshotRefused,
    IssueCode::ResolutionRefused,
    IssueCode::GraphRefused,
    IssueCode::CapacityRefused,
];

/// This code's own position in [`ISSUE_CODES`].
fn issue_code_ordinal(code: IssueCode) -> usize {
    match code {
        IssueCode::SymlinkEscape => 0,
        IssueCode::PathEscape => 1,
        IssueCode::PathEncoding => 2,
        IssueCode::SourceUnreadable => 3,
        IssueCode::SourceEncoding => 4,
        IssueCode::InventoryIncomplete => 5,
        IssueCode::LanguageUnavailable => 6,
        IssueCode::AuthorityUnreadable => 7,
        IssueCode::SnapshotRefused => 8,
        IssueCode::ResolutionRefused => 9,
        IssueCode::GraphRefused => 10,
        IssueCode::CapacityRefused => 11,
    }
}

/// Every build stage production declares, in the order it declares them.
const ISSUE_STAGES: [IssueStage; 8] = [
    IssueStage::Confinement,
    IssueStage::Discovery,
    IssueStage::Authority,
    IssueStage::Source,
    IssueStage::Inventory,
    IssueStage::Snapshot,
    IssueStage::Resolution,
    IssueStage::Graph,
];

/// This stage's own position in [`ISSUE_STAGES`].
fn issue_stage_ordinal(stage: IssueStage) -> usize {
    match stage {
        IssueStage::Confinement => 0,
        IssueStage::Discovery => 1,
        IssueStage::Authority => 2,
        IssueStage::Source => 3,
        IssueStage::Inventory => 4,
        IssueStage::Snapshot => 5,
        IssueStage::Resolution => 6,
        IssueStage::Graph => 7,
    }
}

/// Every paged operation a cursor may continue, in declaration order.
const PAGED_QUERIES: [PagedQuery; 3] = [
    PagedQuery::Projects,
    PagedQuery::Symbols,
    PagedQuery::Relations,
];

/// This query's own position in [`PAGED_QUERIES`].
fn paged_query_ordinal(query: PagedQuery) -> usize {
    match query {
        PagedQuery::Projects => 0,
        PagedQuery::Symbols => 1,
        PagedQuery::Relations => 2,
    }
}

/// Every normalized query parameter a cursor records, in declaration order.
const QUERY_FIELDS: [QueryField; 14] = [
    QueryField::MatchMode,
    QueryField::QueryText,
    QueryField::Language,
    QueryField::Kind,
    QueryField::OwnerName,
    QueryField::PathPrefix,
    QueryField::PageSize,
    QueryField::Offset,
    QueryField::Seed,
    QueryField::Project,
    QueryField::Direction,
    QueryField::EdgeKinds,
    QueryField::Certainties,
    QueryField::MaxDepth,
];

/// This parameter's own position in [`QUERY_FIELDS`].
fn query_field_ordinal(parameter: QueryField) -> usize {
    match parameter {
        QueryField::MatchMode => 0,
        QueryField::QueryText => 1,
        QueryField::Language => 2,
        QueryField::Kind => 3,
        QueryField::OwnerName => 4,
        QueryField::PathPrefix => 5,
        QueryField::PageSize => 6,
        QueryField::Offset => 7,
        QueryField::Seed => 8,
        QueryField::Project => 9,
        QueryField::Direction => 10,
        QueryField::EdgeKinds => 11,
        QueryField::Certainties => 12,
        QueryField::MaxDepth => 13,
    }
}

/// Both states an issue's staleness flag holds.
const STALENESS: [bool; 2] = [false, true];

/// This flag's own position in [`STALENESS`].
fn staleness_ordinal(stale: bool) -> usize {
    match stale {
        false => 0,
        true => 1,
    }
}

/// The closed enumerations, every stated value against its neighbour. A token
/// table that started rendering two of them the same way would leave two states
/// indistinguishable, so each is walked rather than sampled.
fn every_closed_enumeration_claims_its_own_bytes() -> Box<[Kind]> {
    [
        assert_closed(
            &ISSUE_STAGES,
            issue_stage_ordinal,
            RevisionClaimInput::IssueStage,
        ),
        assert_closed(
            &ISSUE_CODES,
            issue_code_ordinal,
            RevisionClaimInput::IssueCode,
        ),
        assert_closed(
            &STALENESS,
            staleness_ordinal,
            RevisionClaimInput::IssueStale,
        ),
        assert_closed(
            &PAGED_QUERIES,
            paged_query_ordinal,
            RevisionClaimInput::QueryKind,
        ),
        assert_closed(&QUERY_FIELDS, query_field_ordinal, |parameter| {
            RevisionClaimInput::QueryParameter {
                field: parameter,
                value: Some("a"),
            }
        }),
    ]
    .into()
}

/// One closed enumeration: every value claims its position, then its own bytes.
///
/// The written list and its `ordinal` are two halves of one statement and
/// neither is the guard alone. `ordinal` is exhaustive, so a variant added to
/// the enumeration must claim an index, and the walk asserts that index leads
/// back to the value that claimed it — so the only way to satisfy both is to
/// put the variant in the list. The same device [`Kind::ordinal`](super::claims)
/// uses, for the same reason: four of these five lists were written without it,
/// and a walk that merely lists eleven of twelve codes goes green while the
/// twelfth is never claimed. The label is the registry kind the walk claims
/// through, not a string beside the call that can name another list.
fn assert_closed<Value: Copy + Debug + PartialEq>(
    all: &[Value],
    ordinal: fn(Value) -> usize,
    input: fn(Value) -> RevisionClaimInput<'static>,
) -> Kind {
    assert!(!all.is_empty(), "a closed enumeration states a value");
    let kind = kind_of(&input(all[0]));
    let claimed: Box<[(String, String)]> = all
        .iter()
        .map(|value| {
            assert_eq!(
                all.get(ordinal(*value)),
                Some(value),
                "{kind:?}: {value:?} claims the position it holds in the walked list"
            );
            let stated = input(*value);
            (format!("{stated:?}"), sealed(&[stated]))
        })
        .collect();
    assert_distinct_digests(&format!("{kind:?}"), &claimed);
    kind
}

/// One written claim that is not the empty one [`held`] seals.
///
/// Sealed by its caller rather than twice here: the index and state identities
/// differed only in which sealer ran, and two copies of the perturbation were
/// two chances for one to stop differing from `held`'s — a row that compares a
/// revision with itself and passes.
fn perturbed() -> RevisionClaim {
    let mut claim = RevisionClaim::new();
    claim.write(RevisionClaimInput::SchemaVersion(2));
    claim
}
