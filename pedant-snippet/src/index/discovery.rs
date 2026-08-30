//! The one corpus walk: what this repository holds that the index may admit.
//!
//! The walk never enters `.git`, `target`, or `node_modules`, follows no
//! symlink, and applies the repository's own ignore files in directory order. A
//! project loader may still admit an ignored source when that source is part of
//! its compilation closure — the ignore rules decide what the *loose* corpus
//! is, not what a compiler sees.
//!
//! Candidates come back sorted rather than in enumeration order, because the
//! order the filesystem hands entries back is the one thing an identity must
//! not depend on.

use std::path::Path;
use std::sync::Arc;

use ignore::{IncrementalIgnore, WalkBuilder};
use pedant_syntax::{FileClassification, Language, classify_path};

use super::authority::ProjectAuthority;
use super::error::{CapacityCollection, CapacityOwner, CodeIntelligenceError, capacity};
use super::issue::{IndexIssue, IssueCode, IssueScope, IssueStage};
use super::limits::RepositoryLimits;
use super::path::CanonicalRoot;
use super::profile;

/// Directory names the walk never enters, whatever the ignore files say.
///
/// Hard rather than configurable: each of these holds machine-generated or
/// vendored trees that dwarf the repository, and a caller that could switch one
/// off would be asking for a walk whose cost has nothing to do with the code.
pub(crate) const EXCLUDED_DIRECTORIES: [&str; 3] = [".git", "target", "node_modules"];

/// The ignore files this walk reads, in the configuration [`builder`] states.
///
/// Named here because the walk is what reads them: `parents(false)` and
/// `git_global(false)` leave exactly the repository's own two names, and a live
/// update that recognized a third would rediscover the corpus for a file the
/// walk never consults.
pub(crate) const IGNORE_FILES: [&str; 2] = [".gitignore", ".ignore"];

/// Everything one walk found, already ordered.
pub(crate) struct Discovery {
    /// Automatic project authorities, sorted by language, path, then kind.
    pub(crate) authorities: Box<[ProjectAuthority]>,
    /// Recognized source candidates, sorted by normalized path.
    pub(crate) sources: Box<[(Arc<str>, Language)]>,
    /// What the walk itself could not do.
    pub(crate) issues: Vec<IndexIssue>,
}

/// Walk one canonical root and state what it holds.
pub(crate) fn walk(
    root: &CanonicalRoot,
    limits: RepositoryLimits,
) -> Result<Discovery, CodeIntelligenceError> {
    let mut authorities = Vec::new();
    let mut sources = Vec::new();
    let mut issues = Vec::new();
    let mut visited = 0_u64;
    let ceiling = u64::from(limits.max_directory_entries);

    for entry in builder(root.as_path()).build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                walk_issues(root, &error, &mut issues);
                continue;
            }
        };
        visited = visited.saturating_add(1);
        if visited > ceiling {
            return Err(capacity(
                CapacityOwner::Repository,
                CapacityCollection::DirectoryEntry,
                visited,
                ceiling,
            ));
        }
        // A symlink is a candidate rather than a skip. The walk does not
        // follow it, and admission resolves it: a link out of the repository is
        // then refused and recorded, where skipping it here would leave the
        // index silently smaller than the tree it walked.
        let candidate = entry
            .file_type()
            .is_some_and(|kind| kind.is_file() || kind.is_symlink());
        if !candidate {
            continue;
        }
        // A name with no UTF-8 spelling is one file this index cannot key, not
        // a repository it cannot answer for. It is recorded against the lossy
        // rendering and skipped, on the same terms as an entry the walk could
        // not read: refusing the whole build would drop every other file over
        // one name.
        let relative = match root.relative(entry.path()) {
            Ok(Some(relative)) => relative,
            Ok(None) => continue,
            Err(error) => {
                issues.push(unkeyable(&error));
                continue;
            }
        };
        classify(&relative, entry.path(), &mut authorities, &mut sources);
    }

    authorities.sort();
    authorities.dedup();
    sources.sort();
    let selected = super::count::widened(authorities.len());
    let authority_ceiling = u64::from(limits.max_authorities);
    if selected > authority_ceiling {
        return Err(capacity(
            CapacityOwner::Repository,
            CapacityCollection::Authority,
            selected,
            authority_ceiling,
        ));
    }
    issues.sort();
    Ok(Discovery {
        authorities: authorities.into_boxed_slice(),
        sources: sources.into_boxed_slice(),
        issues,
    })
}

/// Which authority or source one admitted path states, if any.
fn classify(
    relative: &str,
    path: &Path,
    authorities: &mut Vec<ProjectAuthority>,
    sources: &mut Vec<(Arc<str>, Language)>,
) {
    if let Some(authority) = authority_at(relative, path) {
        authorities.push(authority);
        return;
    }
    if let Some(language) = recognized(path) {
        sources.push((Arc::from(relative), language));
    }
}

/// The manifests automatic discovery recognizes, and nothing else.
///
/// One name, the language a project selected by it resolves, and the authority
/// it states over the path it was found at. Read by both questions a name is
/// asked, so a live update and a corpus walk cannot disagree about which names
/// are authorities.
///
/// Only the two conventional names, because automatic discovery recognizes only
/// them. A repository that spells a manifest differently states it explicitly,
/// which is what [`ProjectAuthority`] is for.
const AUTHORITY_MANIFESTS: [(&str, Language); 2] =
    [("Cargo.toml", Language::Rust), ("go.mod", Language::Go)];

/// The language one conventionally named manifest selects a project for.
///
/// Nothing is allocated to answer. A watcher batch asks this once per reported
/// path, and building a whole authority to read one field off it minted a
/// `Box<str>` name for every one of them and dropped it again.
pub(crate) fn authority_language(name: &str) -> Option<Language> {
    let name = Path::new(name).file_name()?.to_str()?;
    AUTHORITY_MANIFESTS
        .iter()
        .find_map(|(manifest, language)| (*manifest == name).then_some(*language))
}

/// The authority one conventionally named manifest states.
///
/// The one reader of the table that allocates, because the authority it returns
/// retains the path it was found at. It allocates only where it returns one:
/// the table is consulted first, so the ordinary answer — every source file in
/// the repository, which names no manifest — mints nothing.
fn authority_at(relative: &str, path: &Path) -> Option<ProjectAuthority> {
    let name = path.file_name()?.to_str()?;
    match authority_language(name)? {
        Language::Rust => Some(ProjectAuthority::RustManifest {
            path: Box::from(relative),
        }),
        Language::Go => Some(ProjectAuthority::GoModule {
            path: Box::from(relative),
        }),
        Language::Python | Language::JavaScript | Language::TypeScript | Language::Bash => None,
    }
}

/// The language one path states, when this build links an inventory for it.
///
/// Classification is by path alone. A shebang decides the language of a file
/// whose extension states none, and reading every unrecognized file in a
/// repository to ask would make the corpus cost proportional to what the
/// repository is not.
pub(crate) fn recognized(path: &Path) -> Option<Language> {
    let language = match classify_path(path) {
        FileClassification::Rust => Language::Rust,
        FileClassification::Source(language) | FileClassification::SourceAndManifest(language) => {
            language
        }
        FileClassification::Manifest | FileClassification::Unsupported => return None,
    };
    profile::reads(language).then_some(language)
}

/// The walk, configured once.
fn builder(root: &Path) -> WalkBuilder {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(false)
        .hidden(false)
        .parents(false)
        .require_git(false)
        .git_global(false)
        .filter_entry(|entry| {
            !entry
                .file_name()
                .to_str()
                .is_some_and(|name| EXCLUDED_DIRECTORIES.contains(&name))
        });
    builder
}

/// The walk's own ignore rules, asked one path at a time.
///
/// Built from [`builder`], so a caller that admits a single path and the walk
/// that admits the whole corpus read the same `.gitignore` and `.ignore` files
/// under the same configuration. Reimplementing the rules beside the walk was
/// the alternative, and a second copy of git's precedence order is a second
/// answer to "is this file part of this repository".
///
/// The entry predicate is not part of it — `build_matchers` applies no rule that
/// needs traversal state — so a caller still owes [`EXCLUDED_DIRECTORIES`]
/// itself. That costs nothing: the exclusion is a string comparison and this is
/// a file read.
///
/// A matcher is a snapshot of the ignore files as they were when each directory
/// was first reached, so a caller that outlives an edit to one owes itself a
/// fresh matcher.
///
/// Absent only where the builder states no root, which no caller here does.
pub(crate) fn ignore_matcher(root: &Path) -> Option<IncrementalIgnore> {
    builder(root).build_matchers().into_iter().next()
}

/// One entry beneath the root whose name this index cannot key.
///
/// The scope, the stage, and the code all come from the one classification
/// table `IndexIssue` owns, so a confinement refusal the walk states and one an
/// admission states are recorded identically. The scope is asked of
/// [`IssueScope::of`] rather than matched again here: that match is closed over
/// the refusal set, so a refusal added later fails to compile there instead of
/// falling into a catch-all this walk would file against the repository.
fn unkeyable(error: &CodeIntelligenceError) -> IndexIssue {
    IndexIssue::classified(IssueScope::of(error), error)
}

/// Every entry one walk refusal names.
///
/// A `Partial` is several refusals at once, each about its own entry, so each
/// one is recorded on its own terms. Reporting the first named one path and
/// dropped every other path the same walk could not read — leaving an index
/// that answers for a corpus as though the entries it never saw were not there.
fn walk_issues(root: &CanonicalRoot, error: &ignore::Error, issues: &mut Vec<IndexIssue>) {
    let (path, stated) = located(error);
    match stated {
        ignore::Error::Partial(held) => held
            .iter()
            .for_each(|refusal| walk_issues(root, refusal, issues)),
        _ => issues.push(walk_issue(root, path, stated)),
    }
}

/// One entry the walk could not read.
///
/// The path is the one nested inside the refusal, rendered relative to the
/// root, and the message is the refusal found beside it rather than the outer
/// `Display`. Both matter: `ignore` prints the absolute path, an issue message
/// reaches the state claim, and a claim carrying an absolute path gives one
/// repository two identities on two machines.
fn walk_issue(root: &CanonicalRoot, path: Option<&Path>, stated: &ignore::Error) -> IndexIssue {
    let scope = path
        .and_then(|path| root.relative(path).ok().flatten())
        .map_or(IssueScope::Repository, |path| IssueScope::File {
            path: Arc::from(path),
        });
    IndexIssue::recorded(
        scope,
        IssueStage::Discovery,
        IssueCode::SourceUnreadable,
        Arc::from(stated.to_string()),
    )
}

/// The path one `ignore` refusal names, and the refusal stated beneath it.
///
/// Every traversal failure the walker produces is a `WithDepth` wrapping a
/// `WithPath`, so a match on the outer value alone reaches only the ignore-file
/// parse errors — every real I/O failure would be scoped to the walk instead of
/// to the file that failed. The crate publishes no accessor for either half, so
/// the unwrapping is here.
///
/// Only the wrappers above the path are descended through. The one directly
/// beneath it is returned whole, because that is where a `.gitignore`'s line
/// number lives and a message that dropped it names no line to look at.
///
/// A `Partial` is returned whole too, and for the opposite reason: it holds one
/// refusal per entry the walker gave up on, and choosing one of them here is
/// what dropped the rest. [`walk_issues`] records each on its own terms.
///
/// A `Loop` names two absolute paths in its own sentence and none of this
/// reaches it: the walk follows no link, so no loop can be found.
fn located(error: &ignore::Error) -> (Option<&Path>, &ignore::Error) {
    match error {
        ignore::Error::WithPath { path, err } => (Some(path), err),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            located(err)
        }
        _ => (None, error),
    }
}
