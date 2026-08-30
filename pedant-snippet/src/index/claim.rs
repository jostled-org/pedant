//! The one encoder every identity in this crate is claimed through.
//!
//! A revision is a promise: equal inputs give equal identity, and any change to
//! any input changes it. That promise is only as good as the framing. Two
//! fields concatenated without one are one field, so a path `"ab"` followed by
//! `"c"` and a path `"a"` followed by `"bc"` would claim the same identity; and
//! two fields of the same width without a tag are interchangeable, so swapping
//! a source digest for an authority digest would go unnoticed.
//!
//! So every input is written as a tag byte, a length, and its bytes. The tag
//! makes the field kind part of the claim, the length makes the boundary part
//! of it, and the closed [`RevisionClaimInput`] list makes both a property of
//! one registry that production encoding and the identity proof share.
//!
//! Three identities are sealed here: an index, the state published over it, and
//! the page cursor bound to both. A cursor is not a revision, but it is a claim
//! over a list of the same kind, and giving it a second hand-built hash route
//! would put the framing above in two places for one of them to lose. One input
//! is written by the sealer instead of by its caller — see
//! [`seal_cursor`](RevisionClaim::seal_cursor) for which one and why.
//!
//! The encoder is private. Integration tests exercise revision identity through
//! the same public inputs that production callers provide.

use pedant_types::Language;
use sha2::{Digest, Sha256};

use super::count::widened;
use super::issue::{IssueCode, IssueScope, IssueStage};
use super::limit_field::LimitField;
use super::revision::{IndexRevision, StateRevision};

/// Which admitted path a claim record names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdmittedPathKind {
    /// A physical source file the index retained.
    Source,
    /// A project authority file discovery selected.
    Authority,
}

impl AdmittedPathKind {
    /// The stable token this kind is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Authority => "authority",
        }
    }
}

/// Which paged operation one cursor continues.
///
/// Closed over the operations that page, because a cursor is a claim about one
/// of them: a listing cursor that continued a search would present one result
/// set as the rest of another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PagedQuery {
    /// `list_projects`.
    Projects,
    /// `search_symbols`.
    Symbols,
    /// `query_relations`.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Relations,
}

impl PagedQuery {
    /// The stable token this query is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Projects => "list_projects",
            Self::Symbols => "search_symbols",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Relations => "query_relations",
        }
    }
}

/// Which normalized query parameter one cursor claim records.
///
/// The field is written beside its value for the reason [`LimitField`] is: two
/// parameters of the same shape written without their names are
/// interchangeable, and a cursor that survived swapping the owner filter for
/// the path filter would continue a query nobody asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QueryField {
    /// How a search compares its text with a name.
    MatchMode,
    /// The text a search compares.
    QueryText,
    /// The language filter.
    Language,
    /// The structure-kind filter.
    Kind,
    /// The owner-name filter.
    OwnerName,
    /// The path-prefix filter.
    PathPrefix,
    /// How many items one page carries.
    PageSize,
    /// Where the next page starts.
    Offset,
    /// The revision-bound structure a graph walk starts at.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Seed,
    /// The project whose graph a query selects, absent where it selects every
    /// graph the seed appears in.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Project,
    /// Which way a relation walk follows an edge.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Direction,
    /// Which edge kinds a graph query admits.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    EdgeKinds,
    /// Which edge certainties a graph query admits.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    Certainties,
    /// How many selected steps a relation walk may take.
    #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
    MaxDepth,
}

impl QueryField {
    /// The stable token this field is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::MatchMode => "match_mode",
            Self::QueryText => "query_text",
            Self::Language => "language",
            Self::Kind => "kind",
            Self::OwnerName => "owner_name",
            Self::PathPrefix => "path_prefix",
            Self::PageSize => "page_size",
            Self::Offset => "offset",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Seed => "seed",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Project => "project",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Direction => "direction",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::EdgeKinds => "edge_kinds",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::Certainties => "certainties",
            #[cfg(any(feature = "graph-rust", feature = "graph-go"))]
            Self::MaxDepth => "max_depth",
        }
    }
}

/// One sealed page-cursor binding.
///
/// Not published: a caller holding this could mint a cursor for a page nobody
/// offered, and the whole point of binding one is that only the query that
/// produced it can state where it continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CursorBinding {
    digest: [u8; 32],
}

impl CursorBinding {
    /// The claimed digest, as a cursor carries it.
    pub(crate) fn claimed(self) -> [u8; 32] {
        self.digest
    }
}

/// One tagged input to a revision claim.
///
/// Closed, because an untagged escape hatch is how a second hashing route gets
/// added: a variant that carried arbitrary bytes would let a caller claim
/// anything under one tag, and the framing above would stop meaning what it
/// says.
#[derive(Clone, Copy, Debug)]
pub enum RevisionClaimInput<'claim> {
    /// The claim schema this encoder writes.
    SchemaVersion(u32),
    /// One source language this build links an owner for.
    EnabledLanguage(Language),
    /// One language this build can produce project graphs for.
    GraphCoverage(Language),
    /// One host ceiling and the value it holds.
    Limit {
        /// Which ceiling.
        field: LimitField,
        /// Its configured value.
        value: u64,
    },
    /// One normalized path the index admitted.
    AdmittedPath {
        /// Whether it is a source or an authority.
        kind: AdmittedPathKind,
        /// The normalized repository path.
        path: &'claim str,
    },
    /// The language one admitted source was recognized as.
    SourceLanguage(Language),
    /// The exact SHA-256 of one admitted source or authority file.
    Digest(&'claim [u8; 32]),
    /// The language one project slice resolves.
    ProjectLanguage(Language),
    /// The normalized authority path one project slice was selected by.
    ProjectAuthority(&'claim str),
    /// The target or unit label that selects one graph inside that authority.
    ProjectUnit(&'claim str),
    /// The index identity a state or cursor claim is taken over.
    IndexIdentity(&'claim IndexRevision),
    /// The state identity a cursor claim is taken over.
    StateIdentity(&'claim StateRevision),
    /// Which paged operation a cursor claim continues.
    QueryKind(PagedQuery),
    /// One normalized query parameter a cursor claim is bound to, absent where
    /// the request states no value for it.
    QueryParameter {
        /// Which parameter.
        field: QueryField,
        /// Its normalized value, absent where the request omits it.
        value: Option<&'claim str>,
    },
    /// One query parameter whose normalized value is a number.
    ///
    /// The numeric twin of [`QueryParameter`](Self::QueryParameter), and a
    /// separate tag rather than a decimal spelling of the same one. A page size
    /// and an offset are the two parameters every paged query states, so a
    /// claim that spelled them cost two `String`s per sealed binding and up to
    /// three bindings per request — for digits the encoder immediately hashed
    /// as bytes. The width is fixed and the byte order is stated, exactly as
    /// [`Limit`](Self::Limit) writes a ceiling.
    ///
    /// No presence byte, because there is no absent number: a parameter a
    /// request omits is a `QueryParameter` with no value, and a caller holding
    /// a number holds one.
    QueryNumber {
        /// Which parameter.
        field: QueryField,
        /// Its normalized value.
        value: u64,
    },
    /// One issue's scope.
    IssueScope(&'claim IssueScope),
    /// One issue's stage.
    IssueStage(IssueStage),
    /// One issue's stable code.
    IssueCode(IssueCode),
    /// One issue's message.
    IssueMessage(&'claim str),
    /// Whether one issue is serving an older good answer.
    IssueStale(bool),
}

impl RevisionClaimInput<'_> {
    /// The tag byte that makes this input's kind part of the claim.
    ///
    /// Written out rather than derived from declaration order, because a
    /// variant inserted in the middle would otherwise renumber every tag after
    /// it and change the identity of every repository at once.
    fn tag(&self) -> u8 {
        match self {
            Self::SchemaVersion(_) => 1,
            Self::EnabledLanguage(_) => 2,
            Self::GraphCoverage(_) => 3,
            Self::Limit { .. } => 4,
            Self::AdmittedPath { .. } => 5,
            Self::SourceLanguage(_) => 6,
            Self::Digest(_) => 7,
            Self::ProjectLanguage(_) => 8,
            Self::ProjectAuthority(_) => 9,
            Self::ProjectUnit(_) => 10,
            Self::IndexIdentity(_) => 11,
            Self::IssueScope(_) => 12,
            Self::IssueStage(_) => 13,
            Self::IssueCode(_) => 14,
            Self::IssueMessage(_) => 15,
            Self::IssueStale(_) => 16,
            Self::StateIdentity(_) => 17,
            Self::QueryKind(_) => 18,
            Self::QueryParameter { .. } => 19,
            Self::QueryNumber { .. } => 20,
        }
    }
}

/// The claim schema this encoder writes.
///
/// It enters every claim as its own input, so a change to the framing or to the
/// input registry can be stated rather than inferred from identities that
/// silently stopped matching.
pub(crate) const CLAIM_SCHEMA_VERSION: u32 = 1;

/// One revision claim, accumulated in the order its inputs are written.
pub struct RevisionClaim {
    hasher: Sha256,
}

impl Default for RevisionClaim {
    fn default() -> Self {
        Self::new()
    }
}

impl RevisionClaim {
    /// An empty claim that already carries the schema version.
    pub fn new() -> Self {
        let mut claim = Self {
            hasher: Sha256::new(),
        };
        claim.write(RevisionClaimInput::SchemaVersion(CLAIM_SCHEMA_VERSION));
        claim
    }

    /// Write one tagged, length-prefixed input.
    pub fn write(&mut self, input: RevisionClaimInput<'_>) {
        let tag = input.tag();
        match input {
            RevisionClaimInput::SchemaVersion(version) => {
                self.record(tag, &version.to_be_bytes());
            }
            RevisionClaimInput::EnabledLanguage(language)
            | RevisionClaimInput::GraphCoverage(language)
            | RevisionClaimInput::SourceLanguage(language)
            | RevisionClaimInput::ProjectLanguage(language) => {
                // The vocabulary's own token, not a second table beside it. The
                // copy this file used to keep spelled two of the six languages
                // differently from the one every other reader sees.
                self.record(tag, language.token().as_bytes());
            }
            RevisionClaimInput::Limit { field, value } => {
                self.record(tag, field.token().as_bytes());
                self.record(tag, &value.to_be_bytes());
            }
            RevisionClaimInput::AdmittedPath { kind, path } => {
                self.record(tag, kind.token().as_bytes());
                self.record(tag, path.as_bytes());
            }
            RevisionClaimInput::Digest(digest) => self.record(tag, digest),
            RevisionClaimInput::ProjectAuthority(text)
            | RevisionClaimInput::ProjectUnit(text)
            | RevisionClaimInput::IssueMessage(text) => self.record(tag, text.as_bytes()),
            RevisionClaimInput::IndexIdentity(revision) => self.record(tag, revision.claimed()),
            RevisionClaimInput::StateIdentity(revision) => self.record(tag, revision.claimed()),
            RevisionClaimInput::QueryKind(query) => self.record(tag, query.token().as_bytes()),
            RevisionClaimInput::QueryParameter { field, value } => {
                self.record(tag, field.token().as_bytes());
                // A stated value and an omitted one are told apart by the
                // presence byte, so an empty filter and no filter cannot claim
                // the same bytes.
                self.record(tag, &[u8::from(value.is_some())]);
                self.record(tag, value.unwrap_or_default().as_bytes());
            }
            RevisionClaimInput::QueryNumber { field, value } => {
                self.record(tag, field.token().as_bytes());
                self.record(tag, &value.to_be_bytes());
            }
            RevisionClaimInput::IssueScope(scope) => {
                self.record(tag, scope.token().as_bytes());
                self.record(tag, scope.name().as_bytes());
            }
            RevisionClaimInput::IssueStage(stage) => self.record(tag, stage.token().as_bytes()),
            RevisionClaimInput::IssueCode(code) => self.record(tag, code.token().as_bytes()),
            RevisionClaimInput::IssueStale(stale) => self.record(tag, &[u8::from(stale)]),
        }
    }

    /// Seal this claim as one index identity.
    pub fn seal_index(mut self) -> IndexRevision {
        self.domain(b"index");
        IndexRevision::of(self.hasher.finalize().into())
    }

    /// Seal this claim as one state identity.
    ///
    /// A separate closing domain, so an index claim and a state claim over the
    /// same inputs cannot produce the same bytes and be read as each other.
    pub fn seal_state(mut self) -> StateRevision {
        self.domain(b"state");
        StateRevision::of(self.hasher.finalize().into())
    }

    /// Seal this claim as the page-cursor binding of one paged query.
    ///
    /// A third closing domain, so an index claim, a state claim, and a cursor
    /// binding over the same inputs cannot produce the same bytes.
    ///
    /// The query is required here so every cursor binding names the operation
    /// it continues.
    pub(crate) fn seal_cursor(mut self, query: PagedQuery) -> CursorBinding {
        self.write(RevisionClaimInput::QueryKind(query));
        self.domain(b"cursor");
        CursorBinding {
            digest: self.hasher.finalize().into(),
        }
    }

    /// Write one tag, one length, and one payload.
    fn record(&mut self, tag: u8, bytes: &[u8]) {
        self.hasher.update([tag]);
        self.hasher.update(widened(bytes.len()).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Close the claim under the identity it is being sealed as.
    fn domain(&mut self, name: &[u8]) {
        self.hasher.update(widened(name.len()).to_be_bytes());
        self.hasher.update(name);
    }
}
