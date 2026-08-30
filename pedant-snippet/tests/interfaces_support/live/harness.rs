//! One live index over one temporary repository, and everything a live case
//! asks of it.
//!
//! Every resource has one owner and the field order is the teardown order: the
//! watcher is dropped first, which stops observing and joins the applying
//! thread, and only then is the tree removed. A case that held them the other
//! way round would let a callback wake on a directory that is already gone.
//! That holds on success, on failure, on panic, and on an early return alike,
//! because it is drop order rather than a step a case has to remember.
//!
//! The corpus is this tree's own rather than the mixed six-language repository.
//! A live claim is about authorities, ignore files, and sources changing, and it
//! is made several times per case: four languages that add nothing to it would
//! add their parse to every transaction.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pedant_snippet::{
    ChangeKind, CodeIntelligenceLimits, CodeIntelligenceState, EventBatch, FileRecord,
    LiveCodeIntelligenceIndex, LiveIndexError, LiveLedger, LiveTransaction, ObservedChange,
    ProjectAuthority, RootWatcher, StructureDescriptor,
};

use super::probe::{Presence, WatchProbe};
use super::tree::Tree;

/// Every reading of a built state a live case shares with the index cases.
///
/// Re-exported rather than written again. These are the same three renderings
/// over the same types in the same test binary, and a second copy of
/// `scope:name|stage|code|stale` is a second place for one of them to drift
/// from the contract the index rows are asserted against. The source listing
/// keeps this tree's own name for it, because a live case is always saying
/// which sources survived a change.
pub use crate::index::harness::{issue_rows, paths as source_paths, project_keys};

/// Bound on every wait a live case performs.
///
/// Reached by [`probe`](super::probe) too: the probe that establishes a watch
/// waits on the same host this contract does, so a second bound there would be
/// a second answer to how long this run is allowed to take.
pub(super) const DEADLINE: Duration = Duration::from_secs(20);

/// How often a bounded wait looks again.
const INTERVAL: Duration = Duration::from_millis(25);

/// The repository every live case opens over.
///
/// One Cargo workspace with one member, one Go module, and one syntax-only
/// source: an authority per graph producer, and a file that belongs to no
/// project.
pub const LIVE_REPOSITORY: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[workspace]\nmembers = [\"crate-a\"]\nresolver = \"3\"\n",
    ),
    (
        "crate-a/Cargo.toml",
        "[package]\nname = \"crate-a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("crate-a/src/lib.rs", "pub fn make() -> u32 {\n    0\n}\n"),
    ("go.mod", "module example.com/live\n\ngo 1.22\n"),
    (
        "main.go",
        "package main\n\nfunc New() int {\n\treturn 1\n}\n",
    ),
    ("scripts/tool.py", "def build():\n    return 1\n"),
];

/// Every source path [`LIVE_REPOSITORY`] admits, sorted.
pub const LIVE_SOURCES: &[&str] = &["crate-a/src/lib.rs", "main.go", "scripts/tool.py"];

/// The manifest a case names as an authority, so its failure is the case's own.
///
/// Here rather than in the two cases that break it, because a manifest that
/// refuses is one fixture: a change to what it means has one place to land.
pub const NAMED: &str = "crate-a/Cargo.toml";

/// Bytes no Cargo manifest parses, written where [`NAMED`] was.
pub const UNPARSABLE: &str = "[package\nname =\n";

/// The state one live index publishes now.
pub(super) fn published(index: &LiveCodeIntelligenceIndex) -> Arc<CodeIntelligenceState> {
    index
        .state()
        .unwrap_or_else(|error| panic!("the live index answers: {error}"))
}

/// What one live index has applied.
pub(super) fn counted(index: &LiveCodeIntelligenceIndex) -> LiveLedger {
    index
        .ledger()
        .unwrap_or_else(|error| panic!("the live index states its ledger: {error}"))
}

/// One live index, the tree it is over, and the watcher observing it.
///
/// The field order is the teardown order, for the three fields that own
/// anything. The two readings below them own nothing and release nothing.
pub struct Live {
    watcher: Option<RootWatcher>,
    index: LiveCodeIntelligenceIndex,
    tree: Tree,
    presence: Presence,
    watched: u64,
}

impl Live {
    /// Open a live index over [`LIVE_REPOSITORY`], with no watcher.
    pub fn opened() -> Self {
        Self::over(Tree::of(LIVE_REPOSITORY), &[])
    }

    /// Open one over a tree this case wrote itself.
    pub fn over(tree: Tree, authorities: &[ProjectAuthority]) -> Self {
        let index = LiveCodeIntelligenceIndex::open(
            tree.root(),
            authorities,
            CodeIntelligenceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("the fixture repository opens live: {error}"));
        Self {
            watcher: None,
            index,
            tree,
            presence: Presence::new(),
            watched: 0,
        }
    }

    /// Open over [`LIVE_REPOSITORY`] and observe it.
    pub fn watching() -> Self {
        let mut live = Self::opened();
        live.watch();
        live
    }

    /// Start observing, and return once the host is reporting.
    pub fn watch(&mut self) {
        let watcher = self
            .index
            .watch()
            .unwrap_or_else(|error| panic!("the fixture root is watchable: {error}"));
        self.watcher = Some(watcher);
        self.watched = WatchProbe {
            index: &self.index,
            tree: &self.tree,
            presence: &self.presence,
        }
        .establish();
    }

    /// Stop observing and join the applying thread, saying whether it ended
    /// cleanly.
    pub fn stop(&mut self) -> Result<(), LiveIndexError> {
        match self.watcher.take() {
            Some(watcher) => watcher.shutdown(),
            None => Ok(()),
        }
    }

    /// Stop observing by dropping the watcher rather than shutting it down.
    pub fn abandon(&mut self) {
        drop(self.watcher.take());
    }

    /// The repository this index is over.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// The state published now.
    pub fn state(&self) -> Arc<CodeIntelligenceState> {
        published(&self.index)
    }

    /// What this index has applied.
    pub fn ledger(&self) -> LiveLedger {
        counted(&self.index)
    }

    /// How many batches it has applied since its watch was established.
    ///
    /// The probe that established the watch is a transaction of its own, so a
    /// case counting the transactions its own changes produced starts here
    /// rather than at zero.
    pub fn applied_since_watch(&self) -> u64 {
        self.ledger().applied().saturating_sub(self.watched)
    }

    /// The batch one list of repository-relative changes normalizes to.
    pub fn batch(&self, rows: &[(&str, ChangeKind)]) -> EventBatch {
        self.reported(&observed(&self.tree, rows))
    }

    /// The batch one list of host paths normalizes to.
    pub fn reported(&self, observed: &[ObservedChange]) -> EventBatch {
        self.index.normalized(observed)
    }

    /// Apply one list of repository-relative changes as a single transaction.
    pub fn apply(&self, rows: &[(&str, ChangeKind)]) -> LiveTransaction {
        self.applied(self.batch(rows))
    }

    /// Apply one already-normalized batch.
    pub fn applied(&self, batch: EventBatch) -> LiveTransaction {
        self.index
            .apply(batch)
            .unwrap_or_else(|error| panic!("the live index applies a batch: {error}"))
    }

    /// Wait until the published state answers `settled`, sampling every state a
    /// caller could have observed on the way.
    ///
    /// Every sample is required to be whole. A rebuild that published anything
    /// part-way through would be caught here rather than at the end, because
    /// the end is the one state a partial publish is guaranteed not to be.
    pub fn wait_for<T>(
        &self,
        what: &str,
        settled: impl Fn(&CodeIntelligenceState) -> Option<T>,
    ) -> T {
        let started = Instant::now();
        let deadline = started + DEADLINE;
        let mut seen = 0_u32;
        loop {
            let state = self.state();
            assert_whole(&state, what);
            seen = seen.saturating_add(1);
            if let Some(answer) = settled(&state) {
                self.presence.record(started);
                return answer;
            }
            assert!(
                Instant::now() < deadline,
                "{what} did not happen within {DEADLINE:?}; {seen} states observed, \
                 the last holding {:?} and {:?}",
                source_paths(&state),
                issue_rows(&state)
            );
            thread::sleep(INTERVAL);
        }
    }

    /// Wait out the quiet window and hand back the state that survived it.
    ///
    /// Held to the same wholeness every sample of a bounded wait is. This is
    /// the state every absence claim is read from, and an absence is satisfied
    /// by an empty corpus and by a part-built publish exactly as well as by the
    /// state the last transaction really left.
    pub fn quiet(&self) -> Arc<CodeIntelligenceState> {
        self.presence.quiet();
        let state = self.state();
        assert_whole(&state, "the state that survived the quiet window");
        state
    }
}

/// One list of repository-relative changes, as the host would have reported it.
fn observed(tree: &Tree, rows: &[(&str, ChangeKind)]) -> Box<[ObservedChange]> {
    rows.iter()
        .map(|(path, kind)| ObservedChange::new(tree.at(path), *kind))
        .collect()
}

/// Whether one published state admits the named source.
///
/// Every presence and absence claim a live case makes about one path asks this,
/// and asking it as `source_paths(state).contains(&path.to_owned())` allocated a
/// `String` per question in order to compare it against one the list already
/// holds. A caller that also wants to print the list it searched keeps
/// [`source_paths`] for the message.
pub fn admits(state: &CodeIntelligenceState, path: &str) -> bool {
    source_paths(state).iter().any(|held| held.as_str() == path)
}

/// Every named structure one admitted source declares, in the order the outline
/// states them.
///
/// Stated here because three cases ask it of three different sources: a
/// rediscovered ECMAScript file, a repaired Python one, and a Go file about to
/// be renamed. Over a state rather than over a [`Live`], so the caller that
/// already holds the state it means can pass that one instead of taking a
/// fresh publish it never asked for.
///
/// Boxed for the reason [`source_paths`] is: the list is the index's own
/// answer, copied out once and then compared, and no caller appends to it.
pub fn declared_names(state: &CodeIntelligenceState, path: &str) -> Box<[String]> {
    state
        .outline_file(path)
        .unwrap_or_else(|error| panic!("{path} outlines: {error}"))
        .result()
        .structures()
        .iter()
        .filter_map(StructureDescriptor::name)
        .map(str::to_owned)
        .collect()
}

/// Every normalized row of one batch, rendered as `role|path|kind`.
///
/// Boxed on the same terms as [`declared_names`].
pub fn batch_rows(batch: &EventBatch) -> Box<[String]> {
    batch
        .changes()
        .iter()
        .map(|change| {
            format!(
                "{}|{}|{}",
                change.role().token(),
                change.path(),
                change.kind().token()
            )
        })
        .collect()
}

/// Require one published state to be a whole index rather than a part-built
/// one.
///
/// Every admitted file must outline to exactly the structures its record
/// claims, and every structure must slice the retained text of the file it
/// names. A state published from a partly rebuilt corpus fails one of the two.
///
/// The corpus is required to hold something, and so is the outline taken over
/// it. Both rules are stated per file and the second is stated per structure, so
/// a state that admitted every file and outlined nothing in any of them
/// satisfies them by having nothing to check — which is the part-built publish
/// this guard exists to catch, on every sample of every bounded wait. The count
/// is taken across the whole corpus rather than per file, because a repository
/// may legitimately admit a source that declares nothing. Every live fixture
/// admits at least three sources and declares in more than one of them.
pub fn assert_whole(state: &CodeIntelligenceState, what: &str) {
    assert!(
        !state.index().files().is_empty(),
        "{what}: an empty corpus is not a whole index of this repository"
    );
    let outlined: usize = state
        .index()
        .files()
        .iter()
        .map(|file| assert_file_is_whole(state, file, what))
        .sum();
    assert!(
        outlined > 0,
        "{what}: a corpus that outlines no structure anywhere is not one either, and leaves \
         the one rule that cross-checks two tables with nothing to run over"
    );
}

/// Every structure one admitted file states, held to its record and its text.
///
/// Hands back how many it checked, which is what makes the guard above able to
/// require that something was checked at all. The slice is the rule that
/// matters: it reads a span out of one table and indexes the retained source in
/// another, so a state whose two halves came from different builds fails here.
fn assert_file_is_whole(state: &CodeIntelligenceState, file: &FileRecord, what: &str) -> usize {
    let outline = state
        .outline_file(file.path())
        .unwrap_or_else(|error| panic!("{what}: {} outlines: {error}", file.path()));
    let structures = outline.result().structures();
    assert_eq!(
        structures.len(),
        file.structure_count() as usize,
        "{what}: {} states every structure its record counts",
        file.path()
    );
    for structure in structures {
        assert!(
            file.text().get(structure.span().byte_range()).is_some(),
            "{what}: {} slices the source this state retained",
            file.path()
        );
    }
    structures.len()
}
