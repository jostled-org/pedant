//! What one reported path is to this repository, before a batch folds it.
//!
//! Three answers rather than two. A path is keyed, discarded, or beneath the
//! root with no repository spelling at all — and that third answer used to be
//! folded into the second. The corpus walk records exactly that refusal as an
//! issue against the file it names, so a live update that discarded it left the
//! two readers of one tree disagreeing about the same name: a newly created
//! unkeyable name was an issue in a rebuild and invisible to a live update, and
//! because it selected nothing it triggered no rebuild that would have recorded
//! it.
//!
//! The order of the tests is what makes them cheap. Confinement, the hard
//! exclusions, and the corpus role are string comparisons over a path this
//! index has already spelled, so a write inside a build directory costs no file
//! read and no `stat`. Only a path that survives all three is measured against
//! the ignore files.

use std::path::{Component, Path};

use ignore::IncrementalIgnore;

use crate::index::{
    CanonicalRoot, EXCLUDED_DIRECTORIES, IGNORE_FILES, authority_language, recognized,
};

use super::change::ChangeRole;

/// What normalization made of one reported path.
pub(super) enum Keyed {
    /// Not this repository's, or not one this index admits: outside the root,
    /// inside a hard exclusion, of no interest to the corpus, or kept out of it
    /// by the repository's own ignore files.
    Discarded,
    /// A repository key and the role that path plays in the corpus.
    Admitted {
        /// The normalized repository spelling.
        relative: Box<str>,
        /// What the path is to the corpus.
        role: ChangeRole,
    },
    /// A name beneath the root, in a directory the walk enters, that this index
    /// has no repository spelling for at all.
    Unkeyable,
}

/// The repository key and corpus role one reported path has, if it has one.
///
/// Discarded for a path outside the root, one inside a hard exclusion, one this
/// index would never admit, and one the repository's own ignore files keep out
/// of the corpus. Each of those is a path a rebuild would reach exactly the
/// same conclusion about, and reaching it here costs no rebuild.
///
/// A stated refusal is none of those. The `Result` is read rather than
/// discarded, because a path escape and a name with no UTF-8 spelling are
/// refusals this repository owns rather than facts about somebody else's tree.
pub(super) fn keyed(
    root: &CanonicalRoot,
    ignored: &mut Option<IncrementalIgnore>,
    path: &Path,
) -> Keyed {
    match root.relative(path) {
        Ok(None) => Keyed::Discarded,
        Ok(Some(relative)) => keyable(ignored, relative),
        Err(_) => unkeyable(root, path),
    }
}

/// What one path with a repository spelling is to this batch.
///
/// The key comes back owned but unshared. A batch of a checkout's size names
/// most paths more than once, and the shared key is taken only where the batch
/// does not already hold the path — so a second report about one file costs a
/// lookup rather than a second copy of its name.
fn keyable(ignored: &mut Option<IncrementalIgnore>, relative: Box<str>) -> Keyed {
    if excluded(relative.split('/')) {
        return Keyed::Discarded;
    }
    match admitted(ignored, &relative) {
        Some(role) => Keyed::Admitted { relative, role },
        None => Keyed::Discarded,
    }
}

/// What one name beneath the root with no repository spelling is worth.
///
/// A rebuild, and nothing else. The refusal itself is dropped because the
/// corpus walk re-derives it from the same path and records it as an issue
/// under its own classification — so a live update states the refusal by making
/// that walk happen, rather than by keeping a second copy of the walk's
/// vocabulary here.
///
/// Discarded beneath a hard exclusion, because the walk refuses to enter those
/// directories before it keys anything inside them: a rebuild forced there
/// would record nothing and publish the index it already had.
///
/// The exclusion is asked of the host's own segments, since this is the one
/// path with no repository spelling to ask it of. Absent only where the path is
/// not beneath the root, which the refusal being handled has already ruled out.
fn unkeyable(root: &CanonicalRoot, path: &Path) -> Keyed {
    let Ok(suffix) = path.strip_prefix(root.as_path()) else {
        return Keyed::Discarded;
    };
    if suffix
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Keyed::Discarded;
    }
    match excluded(suffix.components().filter_map(segment)) {
        true => Keyed::Discarded,
        false => Keyed::Unkeyable,
    }
}

/// Whether one path's segments name a directory the walk never enters.
///
/// Asked of a repository spelling where the path has one and of the host's own
/// segments where it does not. The walk refuses those directories before it
/// keys anything inside them, so both readings owe the same answer.
fn excluded<'segment>(mut segments: impl Iterator<Item = &'segment str>) -> bool {
    segments.any(|segment| EXCLUDED_DIRECTORIES.contains(&segment))
}

/// The host's own spelling of one ordinary path segment.
///
/// Absent for a component that is not a plain segment and for one with no UTF-8
/// spelling. Neither can equal an excluded directory's name, which is a UTF-8
/// literal, so neither excludes anything.
fn segment<'path>(component: Component<'path>) -> Option<&'path str> {
    match component {
        Component::Normal(segment) => segment.to_str(),
        _ => None,
    }
}

/// The corpus role one repository path has, unless the walk ignores it.
///
/// The ignore rules are asked of a source and of nothing else. A source is what
/// the rules exist to select, and it is the role a generated tree produces by
/// the thousand: without this test a build script writing into `dist/` admitted
/// every file it wrote and rebuilt the whole repository for an index that came
/// back byte-identical.
///
/// An authority and an ignore file are admitted whatever the rules say, and the
/// asymmetry is deliberate. Those two roles are what *redefine* the corpus, and
/// the matcher is a snapshot of the rules as they stood: a rule change has to
/// reach the index through the very change that reloads the matcher, so a
/// matcher that had gone stale over its own reload trigger would leave this
/// index following rules the repository has stopped using. Admitting them costs
/// at most one rebuild that publishes the index it already had, and the two
/// conventional authority names are far too few for that to be a storm.
fn admitted(ignored: &mut Option<IncrementalIgnore>, relative: &str) -> Option<ChangeRole> {
    let role = role_of(relative)?;
    // The role test is first and the conjunction short-circuits, so an
    // authority and an ignore file reach no ignore file of their own.
    let refused = matches!(role, ChangeRole::Source) && ignores(ignored, relative);
    match refused {
        true => None,
        false => Some(role),
    }
}

/// Whether the walk's own ignore rules leave one source out of the corpus.
///
/// A build that states no matcher ignores nothing, which is what a repository
/// with no ignore file already answers and the only reading that admits rather
/// than discards.
fn ignores(ignored: &mut Option<IncrementalIgnore>, relative: &str) -> bool {
    ignored
        .as_mut()
        .is_some_and(|rules| rules.matched(relative, false).is_ignore())
}

/// What one repository path is to the corpus this index admits.
///
/// The three questions are the corpus walk's own, asked in the walk's own
/// order: a manifest is an authority whatever its extension says, an ignore
/// file is read before the sources beside it, and everything else is a source
/// only if this build links an inventory for its language. A build without the
/// Python feature therefore rebuilds nothing when a Python file is written,
/// which is the same answer its corpus already gives.
fn role_of(relative: &str) -> Option<ChangeRole> {
    let name = relative.rsplit('/').next()?;
    if authority_language(name).is_some() {
        return Some(ChangeRole::Authority);
    }
    if IGNORE_FILES.contains(&name) {
        return Some(ChangeRole::Ignore);
    }
    recognized(Path::new(relative)).map(|_| ChangeRole::Source)
}
