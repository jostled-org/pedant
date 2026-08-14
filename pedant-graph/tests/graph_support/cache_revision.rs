//! The revision matrix: one repository state, one change, and the reuse the
//! next build owes.
//!
//! Each revision moves one dimension of the fragment key or of the local graph
//! claim, and each states the exact hits and misses the build after it owes. A
//! seam that reused too much or too little fails naming its own row. Every row
//! is also compared with the graph the direct builder returns, so a seam that
//! classified correctly and answered wrongly fails here too.

use pedant_graph::GraphCache;

use super::analysis_perturbation::created_in_reverse;
use super::cache_counting::{
    Classification, assert_build_classifies, assert_build_examines_every_fragment,
};
use super::cache_fixture::{assert_matches_direct, pair, projection_only};
use super::corpus::FixtureFile;
use super::corpus_revision as corpus;
use super::fixture::{self, CORPUS_LIBRARY, Fixture, Resolved};

/// The files one revision writes, beside the paths it removes.
type RevisedFiles = (Box<[FixtureFile]>, Box<[&'static str]>);

/// One revision of [`REVISION_CORPUS`], and the reuse it must produce.
///
/// Each row changes one dimension of the fragment key or of the local graph
/// claim, and every row states the exact hits and misses the next build owes,
/// so a seam that reused too much or too little fails naming its own row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revision {
    /// Nothing is written at all.
    Unchanged,
    /// One source gains a trailing comment: the digest moves, the claim does
    /// not.
    CommentedSource,
    /// One source gains a further definition after every retained span.
    AddedDefinition,
    /// One source widens the declaration another source names.
    ShiftedDefinition,
    /// One further module is declared and written.
    AddedSource,
    /// One module is withdrawn, declaration and source together.
    RemovedSource,
    /// One module is renamed, declaration and source together.
    RenamedSource,
    /// One further dependency package is declared and no source is touched.
    AddedDependency,
    /// The dependency package is renamed, moving its unit's stable key.
    RenamedUnit,
}

/// Every revision, in the order the matrix states them.
pub const REVISIONS: [Revision; 9] = [
    Revision::Unchanged,
    Revision::CommentedSource,
    Revision::AddedDefinition,
    Revision::ShiftedDefinition,
    Revision::AddedSource,
    Revision::RemovedSource,
    Revision::RenamedSource,
    Revision::AddedDependency,
    Revision::RenamedUnit,
];

impl Revision {
    /// The name a case reports this revision by.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "an unchanged rebuild",
            Self::CommentedSource => "a commented source",
            Self::AddedDefinition => "an added definition",
            Self::ShiftedDefinition => "a widened declaration",
            Self::AddedSource => "an added source",
            Self::RemovedSource => "a removed source",
            Self::RenamedSource => "a renamed source",
            Self::AddedDependency => "an added dependency",
            Self::RenamedUnit => "a renamed unit",
        }
    }

    /// How many current fragments this revision reuses.
    pub fn hits(self) -> u64 {
        match self {
            Self::Unchanged => 4,
            Self::CommentedSource | Self::AddedDefinition => 3,
            Self::ShiftedDefinition | Self::RenamedSource | Self::RenamedUnit => 2,
            Self::AddedSource => 3,
            Self::RemovedSource => 2,
            Self::AddedDependency => 4,
        }
    }

    /// How many current fragments this revision must derive again.
    pub fn misses(self) -> u64 {
        match self {
            Self::Unchanged => 0,
            Self::CommentedSource
            | Self::AddedDefinition
            | Self::RemovedSource
            | Self::AddedDependency => 1,
            Self::ShiftedDefinition
            | Self::AddedSource
            | Self::RenamedSource
            | Self::RenamedUnit => 2,
        }
    }

    /// Write this revision into one materialized repository.
    pub fn apply(self, fixture: &mut Fixture) {
        let (written, removed) = self.files();
        fixture.revise(&written, &removed);
    }

    /// The files this revision writes, beside the paths it removes.
    fn files(self) -> RevisedFiles {
        match self {
            Self::Unchanged => (Box::from([]), Box::from([])),
            Self::CommentedSource => (
                Box::from([("repo/src/beta.rs", corpus::REVISION_BETA_COMMENTED)]),
                Box::from([]),
            ),
            Self::AddedDefinition => (
                Box::from([("repo/src/beta.rs", corpus::REVISION_BETA_EXTENDED)]),
                Box::from([]),
            ),
            Self::ShiftedDefinition => (
                Box::from([("repo/src/beta.rs", corpus::REVISION_BETA_SHIFTED)]),
                Box::from([]),
            ),
            Self::AddedSource => (
                Box::from([
                    ("repo/src/lib.rs", corpus::REVISION_ROOT_WITH_GAMMA),
                    ("repo/src/gamma.rs", corpus::REVISION_GAMMA),
                ]),
                Box::from([]),
            ),
            Self::RemovedSource => (
                Box::from([("repo/src/lib.rs", corpus::REVISION_ROOT_WITHOUT_BETA)]),
                Box::from(["repo/src/beta.rs"]),
            ),
            Self::RenamedSource => (
                Box::from([
                    ("repo/src/lib.rs", corpus::REVISION_ROOT_RENAMED_SOURCE),
                    ("repo/src/gamma.rs", corpus::REVISION_ALPHA),
                ]),
                Box::from(["repo/src/alpha.rs"]),
            ),
            Self::AddedDependency => (
                Box::from([
                    ("repo/Cargo.toml", corpus::REVISION_MANIFEST_WITH_SPARE),
                    ("repo/crates/spare/Cargo.toml", corpus::SPARE_MANIFEST),
                    ("repo/crates/spare/src/lib.rs", corpus::SPARE_SOURCE),
                ]),
                Box::from([]),
            ),
            Self::RenamedUnit => (
                Box::from([
                    ("repo/Cargo.toml", corpus::REVISION_MANIFEST_RENAMED_UNIT),
                    ("repo/src/lib.rs", corpus::REVISION_ROOT_RENAMED_UNIT),
                    (
                        "repo/crates/helper/Cargo.toml",
                        corpus::REVISION_HELPER_MANIFEST_RENAMED,
                    ),
                ]),
                Box::from([]),
            ),
        }
    }
}

/// One revision corpus, its base pairing, and the pairing after the revision.
///
/// The fixture travels with both pairings so the repository outlives the case
/// that reads them, and the two pairings are independent values: a case builds
/// the base, revises the repository, and builds again.
pub fn revised(revision: Revision) -> (Fixture, Resolved, Resolved) {
    let mut fixture = Fixture::build(corpus::REVISION_CORPUS);
    let base = fixture.resolve_declared(CORPUS_LIBRARY);
    revision.apply(&mut fixture);
    let after = fixture.resolve_declared(CORPUS_LIBRARY);
    (fixture, base, after)
}

/// Every revision, every prior cache state, and both creation orders produce
/// the graph the direct builder produces, byte for byte.
pub fn assert_revision_matrix_matches_direct() {
    for revision in REVISIONS {
        assert_revision_matches_direct(revision);
    }
    assert_a_polluted_cache_matches_direct();
}

/// One revision built through a cache holding only its own base.
///
/// The classification is required beside the comparison: a build that retained
/// nothing would answer every row with the direct graph and prove nothing about
/// the seam this row is stated for.
fn assert_revision_matches_direct(revision: Revision) {
    let subject = revision.label();
    let (_repository, base, after) = revised(revision);
    let mut cache = GraphCache::new(projection_only(64));
    let warmed = assert_build_classifies(
        &mut cache,
        pair(&base),
        Classification::retained(0, corpus::REVISION_FRAGMENTS),
        &format!("{subject}: the base build"),
    );
    assert_matches_direct(
        warmed.graph(),
        pair(&base),
        &format!("{subject}: the base build"),
    );

    let built = assert_build_classifies(
        &mut cache,
        pair(&after),
        Classification::retained(revision.hits(), revision.misses()),
        subject,
    );
    assert_matches_direct(built.graph(), pair(&after), subject);
}

/// One cache carried across every revision of every other repository still
/// answers each row with the graph the direct builder answers with.
///
/// The rows run in order, so each build examines a store already holding the
/// fragments of other repositories, other paths, and other claims. Which of
/// them a row reuses is what the pollution changes, so these rows require one
/// classification per current fragment rather than a fixed split.
fn assert_a_polluted_cache_matches_direct() {
    let mut cache = GraphCache::new(projection_only(64));
    for revision in REVISIONS {
        let subject = revision.label();
        let (_repository, base, after) = revised(revision);
        let warmed = assert_build_examines_every_fragment(
            &mut cache,
            pair(&base),
            &format!("{subject}: the polluted base build"),
        );
        assert_matches_direct(
            warmed.graph(),
            pair(&base),
            &format!("{subject}: the polluted base build"),
        );
        let built = assert_build_examines_every_fragment(
            &mut cache,
            pair(&after),
            &format!("{subject}: polluted"),
        );
        assert_matches_direct(built.graph(), pair(&after), &format!("{subject}: polluted"));
    }

    let reordered = created_in_reverse(corpus::REVISION_CORPUS);
    let (_repository, resolved) = fixture::resolve_target(&reordered, CORPUS_LIBRARY);
    let subject = "a corpus created in the opposite order";
    let built = assert_build_examines_every_fragment(&mut cache, pair(&resolved), subject);
    assert_matches_direct(built.graph(), pair(&resolved), subject);
}
