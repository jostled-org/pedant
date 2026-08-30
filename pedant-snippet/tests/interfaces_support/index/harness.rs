//! What every index test asks of a built state, stated once.

use std::fmt::Debug;
use std::path::Path;

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeIntelligenceLimits, CodeIntelligenceState,
    ProjectAuthority, RepositoryLimits,
};
use pedant_types::Language;

use super::fixture::Repository;

/// One Cargo manifest named as an authority.
///
/// A constructor rather than the struct literal at every call site: the
/// literal's `Box::from` was written twenty times across this tree, and a row
/// that spelled the variant is a row that has to be revisited when the
/// authority type gains a field.
pub fn rust_manifest(path: &str) -> ProjectAuthority {
    ProjectAuthority::RustManifest {
        path: Box::from(path),
    }
}

/// One Go module manifest named as an authority.
pub fn go_module(path: &str) -> ProjectAuthority {
    ProjectAuthority::GoModule {
        path: Box::from(path),
    }
}

/// One published list is in the order it claims to be published in.
///
/// Strictly ascending rather than merely sorted. Every list this suite asks the
/// question about is keyed — one record per physical file, one row per issue
/// scope, one row per project key — so a repeated row is a duplicated record
/// rather than a tie, and a non-strict comparison would call it ordered. That
/// also makes this one guard cover the sorted-clone idiom and the pairwise
/// window walk that were written separately for the same claim.
///
/// The emptiness guard is the other half, and it is the half a window walk
/// cannot state: `windows(2)` yields nothing for zero rows and nothing for one,
/// so an index that admitted no source, selected no project, or recorded no
/// issue satisfies the order claim by having nothing to order. Every caller
/// asks this about a list its own repository guarantees is populated, so an
/// empty one is a subject that stopped answering rather than a list in order.
pub fn assert_sorted<Row: Ord + Debug>(rows: &[Row], subject: &str) {
    assert!(
        !rows.is_empty(),
        "{subject} state no row at all, so their order is not what this proves"
    );
    assert!(
        rows.windows(2).all(|pair| pair[0] < pair[1]),
        "{subject} are not in ascending order, or state one row twice: {rows:?}"
    );
}

/// Index one repository under the host defaults, or fail with what refused.
///
/// The failure names the root rather than "the mixed repository": every fixture
/// in this tree reaches this one function, and about twenty of them are not that
/// repository.
pub fn indexed(repository: &Repository) -> CodeIntelligenceState {
    required(repository, &[]).unwrap_or_else(|error| {
        panic!(
            "the repository at {} should index: {error}",
            repository.root().display()
        )
    })
}

/// Index one repository under stated authorities and the host defaults.
///
/// The authorities a caller explicitly required are the perturbation these rows
/// are about; the limits beneath them are not. Spelling
/// `CodeIntelligenceLimits::default()` at every such call site put the one thing
/// that never varied into fourteen places that would each have to be revisited
/// to change it.
pub fn required(
    repository: &Repository,
    authorities: &[ProjectAuthority],
) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
    built(repository, authorities, CodeIntelligenceLimits::default())
}

/// Index one repository under stated authorities and limits.
pub fn built(
    repository: &Repository,
    authorities: &[ProjectAuthority],
    limits: CodeIntelligenceLimits,
) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
    CodeIntelligenceIndex::build(repository.root(), authorities, limits)
}

/// Index a path no fixture owns, under no authorities and the host defaults.
///
/// The rows about a root that is not a readable directory cannot go through
/// [`built`]: an absent directory and a plain file are exactly the two roots a
/// [`Repository`] cannot be. Named here anyway so the production entry point is
/// reached from this module and not from a case.
pub fn rooted(root: &Path) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
    CodeIntelligenceIndex::build(root, &[], CodeIntelligenceLimits::default())
}

/// The host defaults with one change applied, whichever owner it belongs to.
pub fn adjusted(change: impl FnOnce(&mut CodeIntelligenceLimits)) -> CodeIntelligenceLimits {
    let mut limits = CodeIntelligenceLimits::default();
    change(&mut limits);
    limits
}

/// The host defaults with one repository ceiling lowered.
pub fn lowered(change: impl FnOnce(&mut RepositoryLimits)) -> CodeIntelligenceLimits {
    adjusted(|limits| change(&mut limits.repository))
}

/// Every admitted source path, in the order the index states them.
///
/// Boxed rather than a `Vec`: the list is the index's own answer, copied out
/// once and then compared, and no caller appends to it. A caller comparing it
/// to a literal reslices it with `&*`, because a boxed slice states no equality
/// against an array of string literals.
pub fn paths(state: &CodeIntelligenceState) -> Box<[String]> {
    state
        .index()
        .files()
        .iter()
        .map(|file| file.path().to_owned())
        .collect()
}

/// Every project key, as the three components it is ordered by.
///
/// The language is handed back as the shared enum rather than as a token, so a
/// caller asserting the published order sorts by the same `Ord` production
/// does instead of restating the enum's declaration order in a table of its
/// own.
pub fn project_key_rows(state: &CodeIntelligenceState) -> Box<[(Language, String, String)]> {
    state
        .index()
        .projects()
        .iter()
        .map(|project| {
            (
                project.key().language(),
                project.key().authority().to_owned(),
                project.key().unit().to_owned(),
            )
        })
        .collect()
}

/// Every project key, rendered as `language|authority|unit`.
pub fn project_keys(state: &CodeIntelligenceState) -> Box<[String]> {
    project_key_rows(state)
        .into_iter()
        .map(|(language, authority, unit)| format!("{language:?}|{authority}|{unit}"))
        .collect()
}

/// Every issue, rendered as `scope:name|stage|code|stale`.
///
/// The message is left out on purpose: it carries an operating system's own
/// wording, and a claim about the classification must not become a claim about
/// the phrasing of `ENOENT` on one host.
pub fn issue_rows(state: &CodeIntelligenceState) -> Box<[String]> {
    state
        .issues()
        .iter()
        .map(|issue| {
            format!(
                "{}:{}|{}|{}|{}",
                issue.scope().token(),
                issue.scope().name(),
                issue.stage().token(),
                issue.code().token(),
                issue.stale()
            )
        })
        .collect()
}
