//! The closed claim registry: every kind, and everything each kind carries.
//!
//! Every identity this crate publishes is a claim over a list of
//! [`RevisionClaimInput`] values, and the promise of that list is that the kind
//! and the payload of every entry reach the digest. A repository fixture cannot
//! show that on its own: it cannot hold a path constant while changing the kind
//! it was admitted under, and it cannot state a stale issue at all before the
//! live index exists. So this table writes the same registry production writes,
//! one input at a time. [`framing`](super::framing) takes the other half of the
//! promise — where one input ends and how many there are.
//!
//! These rows and the repository fixtures' rows are the two halves of one
//! claim. These prove each input is separately claimed; those prove production
//! actually writes it.

use std::collections::BTreeMap;
use std::sync::Arc;

use pedant_snippet::{
    AdmittedPathKind, IndexRevision, IssueCode, IssueScope, IssueStage, LimitField, PagedQuery,
    QueryField, RevisionClaim, RevisionClaimInput, StateRevision,
};
use pedant_types::Language;

/// Every kind the closed registry states.
///
/// Written as its own closed list so the three matches below can sandwich the
/// registry: [`kind_of`] stops compiling when a variant is added to
/// `RevisionClaimInput`, [`Kind::ordinal`] stops compiling when a variant is
/// added here, and [`witness`] stops compiling until that new kind has an input
/// this table can perturb.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Kind {
    SchemaVersion,
    EnabledLanguage,
    GraphCoverage,
    Limit,
    AdmittedPath,
    SourceLanguage,
    Digest,
    ProjectLanguage,
    ProjectAuthority,
    ProjectUnit,
    IndexIdentity,
    IssueScope,
    IssueStage,
    IssueCode,
    IssueMessage,
    IssueStale,
    StateIdentity,
    PagedQueryName,
    QueryParameter,
    QueryNumber,
}

impl Kind {
    /// Every kind the walk below claims, in the order the registry declares
    /// them.
    ///
    /// The list and [`Kind::ordinal`] are two halves of one statement, and
    /// neither is the guard alone. A successor chain was the guard before this
    /// pair, and an exhaustive `next` proves only that every kind has an arm:
    /// a variant added beside the existing terminal one, spelled `Self::New =>
    /// None`, compiles, earns its `kind_of` and `witness` rows, and is never
    /// sealed or compared — which is exactly what the module doc above says
    /// cannot happen.
    ///
    /// Under this pair a new variant must claim an index, because `ordinal` is
    /// exhaustive; the index must be in range and must map back to the variant
    /// that claimed it, because the walk asserts the round trip. The only way
    /// to satisfy both is to put the variant in this list.
    pub(super) const ALL: [Self; 20] = [
        Self::SchemaVersion,
        Self::EnabledLanguage,
        Self::GraphCoverage,
        Self::Limit,
        Self::AdmittedPath,
        Self::SourceLanguage,
        Self::Digest,
        Self::ProjectLanguage,
        Self::ProjectAuthority,
        Self::ProjectUnit,
        Self::IndexIdentity,
        Self::IssueScope,
        Self::IssueStage,
        Self::IssueCode,
        Self::IssueMessage,
        Self::IssueStale,
        Self::StateIdentity,
        Self::PagedQueryName,
        Self::QueryParameter,
        Self::QueryNumber,
    ];

    /// This kind's own position in [`Kind::ALL`].
    fn ordinal(self) -> usize {
        match self {
            Self::SchemaVersion => 0,
            Self::EnabledLanguage => 1,
            Self::GraphCoverage => 2,
            Self::Limit => 3,
            Self::AdmittedPath => 4,
            Self::SourceLanguage => 5,
            Self::Digest => 6,
            Self::ProjectLanguage => 7,
            Self::ProjectAuthority => 8,
            Self::ProjectUnit => 9,
            Self::IndexIdentity => 10,
            Self::IssueScope => 11,
            Self::IssueStage => 12,
            Self::IssueCode => 13,
            Self::IssueMessage => 14,
            Self::IssueStale => 15,
            Self::StateIdentity => 16,
            Self::PagedQueryName => 17,
            Self::QueryParameter => 18,
            Self::QueryNumber => 19,
        }
    }
}

/// The owned values the borrowing inputs point at.
///
/// Read through accessors rather than as fields, because the payload tables
/// live in a sibling module and a table that could assemble its own witness
/// would no longer be perturbing the one the registry row states.
pub(super) struct Held {
    identity: IndexRevision,
    published: StateRevision,
    digest: [u8; 32],
    scope: IssueScope,
}

impl Held {
    /// The index identity a state claim is taken over.
    pub(super) fn identity(&self) -> &IndexRevision {
        &self.identity
    }

    /// The state identity a cursor claim is taken over.
    pub(super) fn published(&self) -> &StateRevision {
        &self.published
    }

    /// The digest one admitted source claims.
    pub(super) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The scope one issue is about.
    pub(super) fn scope(&self) -> &IssueScope {
        &self.scope
    }
}

/// Every input kind is separately claimed, and so is everything it carries.
pub fn claim_registry_is_closed_and_tagged() {
    every_kind_claims_its_own_bytes();
    super::payloads::every_payload_reaches_the_claim();
}

/// Every kind is on the walked list, and no two of them claim the same bytes.
///
/// That every kind is *on* the list is what the round trip states, and it is
/// the claim a successor chain could not make: `ordinal` is exhaustive, so a
/// new variant must name an index, and the index it names has to be in range
/// and has to lead back to it. Nothing here restates the length, which is a
/// number the list already owns.
///
/// The payloads are deliberately identical wherever the types allow it — `"a"`
/// for every path-shaped input, `Rust` for every language-shaped one — because
/// two same-width fields written without a tag would be interchangeable, and
/// equal payloads are the only way to see that.
fn every_kind_claims_its_own_bytes() {
    let held = held();
    let rows: Box<[(String, String)]> = Kind::ALL
        .into_iter()
        .map(|kind| {
            assert_eq!(
                Kind::ALL.get(kind.ordinal()).copied(),
                Some(kind),
                "{kind:?}: a kind claims the position it holds in the walked list"
            );
            let input = witness(kind, &held);
            assert_eq!(
                kind_of(&input),
                kind,
                "{kind:?}: the witness for a kind is an input of that kind"
            );
            (format!("{kind:?}"), sealed(&[input]))
        })
        .collect();

    assert_distinct_digests("claim kinds", &rows);
}

/// One claim over `inputs`, sealed as an index identity.
pub(crate) fn sealed(inputs: &[RevisionClaimInput<'_>]) -> String {
    let mut claim = RevisionClaim::new();
    for input in inputs {
        claim.write(*input);
    }
    claim.seal_index().to_string()
}

/// No two labelled digests are equal.
///
/// The rows are read through [`AsRef<str>`], so a caller hands over whatever it
/// already holds. A borrowed pair alone forced every caller to collect its
/// owned rows and then rebuild a second list of references into them — the copy
/// this guard exists not to need, written out at three call sites.
///
/// An empty list refuses rather than passing. Distinctness is trivially true of
/// no rows, so a caller whose walk collected nothing — a filtered corpus, a
/// table under a feature that linked none of its cases — would read this guard
/// as having checked its set.
pub fn assert_distinct_digests<Name: AsRef<str>, Digest: AsRef<str>>(
    label: &str,
    rows: &[(Name, Digest)],
) {
    assert!(
        !rows.is_empty(),
        "{label}: a distinctness claim over no rows states nothing"
    );
    let mut claimed: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, digest) in rows {
        if let Some(previous) = claimed.insert(digest.as_ref(), name.as_ref()) {
            panic!(
                "{label}: {} and {previous} claim the same bytes",
                name.as_ref()
            );
        }
    }
}

/// One registry row by position, which is how the claim orders them.
pub(super) fn field(position: usize) -> LimitField {
    *LimitField::ALL
        .get(position)
        .expect("this profile states at least two ceilings")
}

/// The owned values every borrowing witness points at.
pub(super) fn held() -> Held {
    Held {
        identity: RevisionClaim::new().seal_index(),
        published: RevisionClaim::new().seal_state(),
        digest: [0x11; 32],
        scope: IssueScope::File {
            path: Arc::from("a"),
        },
    }
}

/// The kind one input is.
///
/// Exhaustive on purpose: a variant added to `RevisionClaimInput` stops this
/// function compiling, and the [`Kind`] it then needs stops [`witness`]
/// compiling until the new kind has a row in this table.
///
/// Published to the index tree because [`payloads`](super::payloads) asks the
/// same question of the inputs its own tables state: that every pair holds its
/// kind constant, and that the kinds its tables move are all of [`Kind::ALL`].
/// A second classifier there would be a second table to keep in step with the
/// registry, and the one that fell behind would be the one nothing compares.
pub(super) fn kind_of(input: &RevisionClaimInput<'_>) -> Kind {
    match input {
        RevisionClaimInput::SchemaVersion(_) => Kind::SchemaVersion,
        RevisionClaimInput::EnabledLanguage(_) => Kind::EnabledLanguage,
        RevisionClaimInput::GraphCoverage(_) => Kind::GraphCoverage,
        RevisionClaimInput::Limit { .. } => Kind::Limit,
        RevisionClaimInput::AdmittedPath { .. } => Kind::AdmittedPath,
        RevisionClaimInput::SourceLanguage(_) => Kind::SourceLanguage,
        RevisionClaimInput::Digest(_) => Kind::Digest,
        RevisionClaimInput::ProjectLanguage(_) => Kind::ProjectLanguage,
        RevisionClaimInput::ProjectAuthority(_) => Kind::ProjectAuthority,
        RevisionClaimInput::ProjectUnit(_) => Kind::ProjectUnit,
        RevisionClaimInput::IndexIdentity(_) => Kind::IndexIdentity,
        RevisionClaimInput::IssueScope(_) => Kind::IssueScope,
        RevisionClaimInput::IssueStage(_) => Kind::IssueStage,
        RevisionClaimInput::IssueCode(_) => Kind::IssueCode,
        RevisionClaimInput::IssueMessage(_) => Kind::IssueMessage,
        RevisionClaimInput::IssueStale(_) => Kind::IssueStale,
        RevisionClaimInput::StateIdentity(_) => Kind::StateIdentity,
        RevisionClaimInput::QueryKind(_) => Kind::PagedQueryName,
        RevisionClaimInput::QueryParameter { .. } => Kind::QueryParameter,
        RevisionClaimInput::QueryNumber { .. } => Kind::QueryNumber,
    }
}

/// One input of each kind, carrying the same payload wherever the types allow.
fn witness(kind: Kind, held: &Held) -> RevisionClaimInput<'_> {
    match kind {
        Kind::SchemaVersion => RevisionClaimInput::SchemaVersion(1),
        Kind::EnabledLanguage => RevisionClaimInput::EnabledLanguage(Language::Rust),
        Kind::GraphCoverage => RevisionClaimInput::GraphCoverage(Language::Rust),
        Kind::Limit => RevisionClaimInput::Limit {
            field: field(0),
            value: 1,
        },
        Kind::AdmittedPath => RevisionClaimInput::AdmittedPath {
            kind: AdmittedPathKind::Source,
            path: "a",
        },
        Kind::SourceLanguage => RevisionClaimInput::SourceLanguage(Language::Rust),
        Kind::Digest => RevisionClaimInput::Digest(&held.digest),
        Kind::ProjectLanguage => RevisionClaimInput::ProjectLanguage(Language::Rust),
        Kind::ProjectAuthority => RevisionClaimInput::ProjectAuthority("a"),
        Kind::ProjectUnit => RevisionClaimInput::ProjectUnit("a"),
        Kind::IndexIdentity => RevisionClaimInput::IndexIdentity(&held.identity),
        Kind::IssueScope => RevisionClaimInput::IssueScope(&held.scope),
        Kind::IssueStage => RevisionClaimInput::IssueStage(IssueStage::Confinement),
        Kind::IssueCode => RevisionClaimInput::IssueCode(IssueCode::SymlinkEscape),
        Kind::IssueMessage => RevisionClaimInput::IssueMessage("a"),
        Kind::IssueStale => RevisionClaimInput::IssueStale(false),
        Kind::StateIdentity => RevisionClaimInput::StateIdentity(&held.published),
        Kind::PagedQueryName => RevisionClaimInput::QueryKind(PagedQuery::Projects),
        Kind::QueryParameter => RevisionClaimInput::QueryParameter {
            field: QueryField::MatchMode,
            value: Some("a"),
        },
        // The same field and a number, because the interesting comparison is
        // against `Limit`, which writes a token and a `u64` under its own tag
        // and would be interchangeable with this one without it.
        Kind::QueryNumber => RevisionClaimInput::QueryNumber {
            field: QueryField::MatchMode,
            value: 1,
        },
    }
}
