//! The one build: root, authorities, projects, loose corpus, seal.
//!
//! The order is the contract. Projects load first, because a project loader
//! admits the sources its compilation closure reaches — including ones the
//! repository's ignore files exclude — and the loose corpus is defined as what
//! is left. Running the walk first would admit a project source as a loose file
//! and then have to reconcile two records of it.
//!
//! Fatal and degraded are decided here too. A root that is not a root and an
//! explicit authority that does not load are fatal, because both are the
//! caller's own statement about what to index. Everything else is recorded and
//! the build continues: a repository with one unreadable file still has an
//! answer for every other file.

#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use pedant_types::Language;

use super::authority::ProjectAuthority;
use super::discovery;
use super::error::CodeIntelligenceError;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use super::issue::IssueCode;
use super::issue::{IndexIssue, IssueScope, IssueStage};
use super::limits::CodeIntelligenceLimits;
#[cfg(feature = "test-support")]
use super::observe::WorkPhase;
use super::path::{CanonicalRoot, normalize};
use super::profile;
use super::project::ProjectSlice;
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
use super::read;
use super::reuse::GraphReuse;
use super::seal::{self, AdmittedAuthority};
use super::state::CodeIntelligenceState;
use super::store::RepositorySourceStore;

/// Index one repository beneath `root`.
pub(crate) fn build(
    root: &Path,
    authorities: &[ProjectAuthority],
    limits: CodeIntelligenceLimits,
    reuse: &mut GraphReuse,
) -> Result<CodeIntelligenceState, CodeIntelligenceError> {
    let root = CanonicalRoot::open(root)?;
    let explicit = validated(&root, authorities)?;
    let discovered = discovery::walk(&root, limits.repository)?;
    let selected = merged(&explicit, &discovered.authorities);

    let mut store = RepositorySourceStore::new(root.clone(), limits);
    #[cfg(feature = "test-support")]
    let work = Arc::clone(store.work());
    let mut issues = discovered.issues;
    let mut admitted = Vec::new();
    #[cfg(feature = "test-support")]
    work.entered(WorkPhase::Resolution);
    let slices = selected_projects(
        &mut store,
        &root,
        reuse,
        &selected,
        &explicit,
        &mut issues,
        &mut admitted,
    )?;
    #[cfg(feature = "test-support")]
    work.entered(WorkPhase::LooseCorpus);
    loose(&mut store, &discovered.sources, &mut issues);

    admitted.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(seal::seal(limits, &store, &admitted, slices, issues))
}

/// Every explicit authority, or the first reason one of them is not usable.
///
/// Fatal by design: a caller that named a project meant that project.
fn validated(
    root: &CanonicalRoot,
    authorities: &[ProjectAuthority],
) -> Result<Box<[ProjectAuthority]>, CodeIntelligenceError> {
    authorities
        .iter()
        .try_for_each(|authority| usable(root, authority))?;
    let mut validated = authorities.to_vec();
    validated.sort();
    validated.dedup();
    Ok(validated.into_boxed_slice())
}

/// Whether one explicit authority names a project this build can load.
fn usable(root: &CanonicalRoot, authority: &ProjectAuthority) -> Result<(), CodeIntelligenceError> {
    let path = normalize(authority.path())?;
    let canonical = root.resolve(path)?;
    let refusal = match (canonical.is_file(), profile::resolves(authority.language())) {
        (false, _) => "the explicit authority is not a file",
        (_, false) => "this build links no project loader for that language",
        (true, true) => return Ok(()),
    };
    Err(CodeIntelligenceError::Project {
        authority: Box::from(path),
        stage: IssueStage::Authority,
        reason: Box::from(refusal),
    })
}

/// Every authority to select, with automatic duplicates of an explicit one
/// removed, in one order that does not depend on how the caller listed them.
///
/// The whole selection is sorted together rather than kept in two halves. That
/// is what makes an outer authority load before an inner one it contains, so a
/// workspace claims its own members and each project is selected exactly once —
/// whichever half the member's manifest came from. The containment order is
/// [`ProjectAuthority`]'s own, stated there rather than here.
fn merged(
    explicit: &[ProjectAuthority],
    automatic: &[ProjectAuthority],
) -> Box<[ProjectAuthority]> {
    let mut selected: Vec<ProjectAuthority> = explicit.to_vec();
    selected.extend(
        automatic
            .iter()
            .filter(|candidate| profile::resolves(candidate.language()))
            .filter(|candidate| !stated(explicit, candidate))
            .cloned(),
    );
    selected.sort();
    selected.into_boxed_slice()
}

/// Whether an explicit authority already names the same project file.
fn stated(explicit: &[ProjectAuthority], candidate: &ProjectAuthority) -> bool {
    explicit
        .iter()
        .any(|held| held.path() == candidate.path() && held.language() == candidate.language())
}

/// What one build is writing down as it selects projects.
///
/// One value rather than a pair, so the two collections travel to
/// [`record_authorities`] under their own names. Held inside this profile
/// rather than in the signature above: the profile that links no graph producer
/// writes nothing down, and a context it is handed and never reads is a context
/// its compiler stops checking.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
struct BuildRecords<'records> {
    /// What the build could not do.
    issues: &'records mut Vec<IndexIssue>,
    /// Every authority file this build read and hashed.
    admitted: &'records mut Vec<AdmittedAuthority>,
}

/// Load every selected authority that an earlier one has not already claimed.
///
/// Every parameter is named. The two authority slices are the same type and the
/// pair that used to carry them made a transposition — selecting the caller's
/// explicit list and treating the whole discovery as fatal — a swap that
/// type-checks and compiles.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn selected_projects(
    store: &mut RepositorySourceStore,
    root: &CanonicalRoot,
    reuse: &mut GraphReuse,
    selected: &[ProjectAuthority],
    explicit: &[ProjectAuthority],
    issues: &mut Vec<IndexIssue>,
    admitted: &mut Vec<AdmittedAuthority>,
) -> Result<Box<[ProjectSlice]>, CodeIntelligenceError> {
    let mut records = BuildRecords { issues, admitted };
    let limits = *store.limits();
    let mut budget = super::graph_budget::GraphBudget::new(limits.repository);
    let mut claimed: BTreeSet<Arc<str>> = BTreeSet::new();
    let mut slices = Vec::new();

    for authority in selected {
        // Asked of the borrowed path, not of an `Arc` built to ask it: the set
        // borrows as `str`, and a claimed authority is the ordinary case in a
        // workspace whose members each name the manifest that already claimed
        // them.
        if claimed.contains(authority.path()) {
            continue;
        }
        let path: Arc<str> = Arc::from(authority.path());
        let mut selection = select_one(store, root, authority, &path, (reuse, &mut budget));
        if let Some(error) = fatal_capacity(&mut selection, authority, explicit) {
            return Err(error);
        }
        named_refusal(&selection, authority, explicit, &path)?;
        for failure in &selection.failures {
            records.issues.push(IndexIssue::recorded(
                IssueScope::Project {
                    authority: Arc::clone(&path),
                },
                failure.stage,
                failure.code,
                Arc::from(&*failure.reason),
            ));
        }
        record_authorities(
            root,
            &selection.claimed,
            &path,
            limits,
            &mut claimed,
            &mut records,
        );
        slices.extend(selection.slices);
    }
    super::slice::sealed(slices, limits)
}

/// A capacity that must end the build rather than degrade one automatic project.
///
/// Repository capacity is global. Authority capacity means project selection
/// itself was incomplete. A language or graph owner remains local for an
/// automatic project, but is fatal when the caller explicitly required the
/// authority or the exact nested member that produced the failed unit.
///
/// The search is for the first failure that is fatal *and* carries a typed
/// ceiling. Stopping at the first fatal one and then asking it for a capacity
/// answered nothing whenever that failure held none — and a later failure
/// holding a genuine repository refusal was never reached, so the build
/// reported an unrelated first failure in place of the ceiling that ended it.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn fatal_capacity(
    selection: &mut super::slice::Selection,
    authority: &ProjectAuthority,
    explicit: &[ProjectAuthority],
) -> Option<CodeIntelligenceError> {
    // Asked once above the search: whether the caller named this authority is a
    // fact about the authority, and asked inside the closure it was one full
    // scan of the explicit list, with a string comparison per entry, for every
    // failure the selection carried.
    let named = explicit.contains(authority);
    selection.failures.iter_mut().find_map(|failure| {
        let fatal = named
            || failure.capacity_owner() == Some(super::error::CapacityOwner::Repository)
            || failure.stage == IssueStage::Authority
            || required_authority(failure, authority.language(), explicit).is_some();
        fatal.then(|| failure.take_capacity()).flatten()
    })
}

/// No graph producer is linked, so this build states no project at all.
///
/// The authorities are still walked and still not selected: a repository whose
/// `Cargo.toml` this build cannot load holds Rust sources it can still outline,
/// and `graph_coverage` is where that absence is stated rather than in an issue
/// on every manifest.
#[cfg(not(any(feature = "graph-rust", feature = "graph-go")))]
fn selected_projects(
    _: &mut RepositorySourceStore,
    _: &CanonicalRoot,
    _: &mut GraphReuse,
    _: &[ProjectAuthority],
    _: &[ProjectAuthority],
    _: &mut Vec<IndexIssue>,
    _: &mut Vec<AdmittedAuthority>,
) -> Result<Box<[ProjectSlice]>, CodeIntelligenceError> {
    Ok(Box::new([]))
}

/// The fatal error an authority the caller named states when it refuses.
///
/// A discovered authority that fails is a degraded project, because nobody
/// asked for it by name. One the caller named is the caller's own statement
/// about what to index, so indexing the repository without it would answer a
/// question nobody asked.
///
/// The path travels as `&str` rather than as a shared handle: the one thing done
/// with it is the `Box<str>` the refusal carries, so retaining the authority's
/// own `Arc` and minting a second one from the required authority's path were
/// both a retention this function never uses — the second of them a whole copy
/// of the string, allocated to be copied again one line later.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn named_refusal(
    selection: &super::slice::Selection,
    authority: &ProjectAuthority,
    explicit: &[ProjectAuthority],
    path: &str,
) -> Result<(), CodeIntelligenceError> {
    let refusal = match explicit.contains(authority) {
        true => selection.failures.first().map(|failure| (failure, path)),
        false => selection.failures.iter().find_map(|failure| {
            required_authority(failure, authority.language(), explicit)
                .map(|required| (failure, required.path()))
        }),
    };
    match refusal {
        Some((failure, required)) => Err(CodeIntelligenceError::Project {
            authority: Box::from(required),
            stage: failure.stage,
            reason: Box::from(&*failure.reason),
        }),
        None => Ok(()),
    }
}

/// The explicit authority whose claimed package produced one refusal.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn required_authority<'authority>(
    failure: &super::slice::SliceFailure,
    language: Language,
    explicit: &'authority [ProjectAuthority],
) -> Option<&'authority ProjectAuthority> {
    let manifest = failure.required_manifest()?;
    explicit
        .iter()
        .find(|required| required.language() == language && required.path() == manifest)
}

/// Route one authority to its language's own loader.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn select_one(
    store: &mut RepositorySourceStore,
    root: &CanonicalRoot,
    authority: &ProjectAuthority,
    path: &Arc<str>,
    reuse: (&mut GraphReuse, &mut super::graph_budget::GraphBudget),
) -> super::slice::Selection {
    // Read out of the pair inside the arm that wants it rather than into two
    // names above the match. Go takes the budget alone, so a build that links
    // the Go producer and not the Rust one would bind a graph store its one
    // loader never asks for.
    match authority.language() {
        #[cfg(feature = "graph-rust")]
        Language::Rust => super::rust_slices::select(store, root, path, reuse),
        #[cfg(feature = "graph-go")]
        Language::Go => super::go_slices::select(store, root, path, reuse.1),
        _ => super::slice::Selection {
            slices: Vec::new(),
            claimed: Box::new([]),
            failures: Vec::new(),
        },
    }
}

/// Read and hash every authority one selection accounts for, each one once.
///
/// A claimed package manifest and the authority that selected the project are
/// the same path whenever the authority sits at its own package's root, which
/// is the ordinary case for a root `Cargo.toml` or `go.mod`. The claim set
/// answers whether this build already read a path, so one selected authority
/// costs one file read and one digest rather than two of each — and states one
/// issue rather than two when it cannot be read at all.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn record_authorities(
    root: &CanonicalRoot,
    manifests: &[Arc<str>],
    authority: &Arc<str>,
    limits: CodeIntelligenceLimits,
    claimed: &mut BTreeSet<Arc<str>>,
    records: &mut BuildRecords<'_>,
) {
    for path in manifests.iter().chain([authority]) {
        if claimed.insert(Arc::clone(path)) {
            record_authority(root, path, limits, records);
        }
    }
}

/// Read one selected authority file and retain the digest of its exact bytes.
///
/// The manifests are part of the index's identity: a workspace member added to
/// a `[workspace]` list changes which sources the project reaches without
/// changing one byte of any source that was already admitted.
///
/// The stage is pinned and the code is the refusal's own. `resolve` and
/// `bounded` state four different things — an escaping link, a malformed path,
/// a manifest past the byte ceiling, and a read that failed — and the one
/// classification table already separates them. Recording all four as
/// `authority_unreadable` left an operator filtering on `capacity_refused`
/// unable to see a manifest that blew a ceiling.
#[cfg(any(feature = "graph-rust", feature = "graph-go"))]
fn record_authority(
    root: &CanonicalRoot,
    path: &Arc<str>,
    limits: CodeIntelligenceLimits,
    records: &mut BuildRecords<'_>,
) {
    let read = root.resolve(path).and_then(|canonical| {
        read::bounded(&canonical, path, limits.repository.max_source_file_bytes)
    });
    match read {
        Ok(bytes) => records.admitted.push(AdmittedAuthority {
            path: Arc::clone(path),
            digest: read::digest(&bytes),
        }),
        Err(error) => records.issues.push(IndexIssue::recorded(
            IssueScope::Project {
                authority: Arc::clone(path),
            },
            IssueStage::Authority,
            IssueCode::of(&error),
            Arc::from(error.to_string()),
        )),
    }
}

/// Admit every recognized source no project slice already reached.
fn loose(
    store: &mut RepositorySourceStore,
    candidates: &[(Arc<str>, Language)],
    issues: &mut Vec<IndexIssue>,
) {
    for (path, language) in candidates {
        if store.retained(path).is_some() {
            continue;
        }
        if let Err(error) = store.admit(path, *language) {
            issues.push(IndexIssue::classified(
                IssueScope::File {
                    path: Arc::clone(path),
                },
                &error,
            ));
        }
    }
}
