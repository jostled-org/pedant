//! What one change to a repository says, before and after this index keys it.
//!
//! Two vocabularies, one step apart. An [`ObservedChange`] is what the host
//! reported: an absolute path and what happened to it. A [`SourceChange`] is
//! what this index made of it — a normalized repository path, the role that
//! path plays in the corpus, and the net effect of every observation of it in
//! one batch.
//!
//! A report is held unsettled until normalization admits the path it names.
//! Some host reports state their own effect and some can only be told apart by
//! asking the filesystem, and asking is a syscall per path — so the question is
//! carried as [`ReportedChange`] and answered on the applying thread, after the
//! string-only tests have already discarded every path this index would never
//! admit.
//!
//! A host also reports that it stopped being able to report. That notice names
//! no path, so [`HostReport`] carries it beside the changes rather than as one
//! of them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What one change says happened to a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    /// The path was not there before and is there now.
    Created,
    /// The path was there before and holds different bytes now.
    Modified,
    /// The path is not there now.
    Removed,
}

impl ChangeKind {
    /// The stable token this kind is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::Removed => "removed",
        }
    }
}

/// What a changed path is to the corpus this index admits.
///
/// Ordered by precedence, and that order is the reason the variants sit in it.
/// An authority decides which sources a compilation closure reaches and an
/// ignore file decides which of the rest are loose, so both redefine what the
/// corpus *is*; a source only changes what one admitted member of it holds. A
/// batch sorted by this order therefore states the changes that redefine the
/// corpus before the changes inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeRole {
    /// A conventionally named project manifest.
    Authority,
    /// An ignore file the corpus walk reads.
    Ignore,
    /// A source this build links a structure inventory for.
    Source,
}

impl ChangeRole {
    /// The stable token this role is named by.
    pub fn token(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Ignore => "ignore",
            Self::Source => "source",
        }
    }
}

/// What one host report says, before the filesystem has been asked.
///
/// A create and a remove state themselves. A rename does not: it arrives as one
/// event naming both paths on hosts that pair them and as two events on hosts
/// that do not, and the paired form gives no way to tell which name is which
/// from the kind alone. So a rename asks the filesystem, which answers the same
/// way on every host — the old name is gone and the new one is there.
///
/// Everything that is neither asks too, because a modify that names a path no
/// longer there is a removal that reached this process under another name.
///
/// The two unsettled variants exist so the asking can be deferred. The
/// notification layer's callback must do nothing but translate and send, and a
/// `cargo build` reports thousands of paths inside `target/` that this index
/// discards on a string comparison — one `stat` each, on the thread holding the
/// host's event queue, for an answer nothing reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReportedChange {
    /// The host named the effect, and nothing needs asking.
    Stated(ChangeKind),
    /// A rename: created where the path is there now, removed where it is not.
    Renamed,
    /// Any other report: modified where the path is there now, removed where it
    /// is not.
    Touched,
}

impl ReportedChange {
    /// What this report says once the filesystem has answered.
    fn settled(self, path: &Path) -> ChangeKind {
        match self {
            Self::Stated(kind) => kind,
            Self::Renamed => present(path, ChangeKind::Created),
            Self::Touched => present(path, ChangeKind::Modified),
        }
    }
}

/// `whole` where the path is there now, and removed where it is not.
///
/// A stat that refuses is not an absence. A directory this process may not
/// search, an I/O error, and a link with no target all answer "I could not
/// ask", and a check that read them as `false` published `Removed` for a file
/// the next rebuild still indexes. [`SourceChange::kind`] is published, and the
/// ledger's last transaction is what an operator reads to tell "nothing
/// changed" from "every rebuild failed" — so a removal it never observed is the
/// one answer this must not invent.
fn present(path: &Path, whole: ChangeKind) -> ChangeKind {
    match path.try_exists() {
        Ok(false) => ChangeKind::Removed,
        Ok(true) | Err(_) => whole,
    }
}

/// One change as the host reported it, before this index has keyed it.
///
/// The path is whatever the host handed over, so it is absolute and may name
/// something outside the root, inside an excluded directory, or with no UTF-8
/// spelling. Deciding which of those it is belongs to normalization, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedChange {
    path: Box<Path>,
    reported: ReportedChange,
}

impl ObservedChange {
    /// One change to one host path whose effect the caller already knows.
    ///
    /// Published for a host that learns about changes some way other than this
    /// crate's watcher, which is the caller that can state the effect outright:
    /// it knows what it did.
    ///
    /// The path is taken owned and retained boxed: nothing here ever grows it,
    /// and a batch of a thousand reports would otherwise carry a thousand
    /// allocations' worth of spare capacity nothing writes into.
    pub fn new(path: PathBuf, kind: ChangeKind) -> Self {
        Self::reported(path, ReportedChange::Stated(kind))
    }

    /// One change to one host path, settled or not.
    pub(super) fn reported(path: PathBuf, reported: ReportedChange) -> Self {
        Self {
            path: path.into_boxed_path(),
            reported,
        }
    }

    /// The host path that changed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What happened to it, asking the filesystem where the report cannot say.
    ///
    /// Not published, and not an accessor a caller could reach by accident: it
    /// is the one place a live update touches the filesystem before a rebuild,
    /// and normalization calls it only for a path it has already admitted.
    pub(super) fn settled(&self) -> ChangeKind {
        self.reported.settled(&self.path)
    }
}

/// What one host notification asks a live index for.
///
/// Two answers rather than one list, because a host has two things to say. It
/// names what changed, or it states that it dropped changes it will never name
/// — an inotify queue that overflowed, an FSEvents stream that asked for the
/// subtree to be rescanned.
///
/// The second cannot be spelled as the first. The notice carries no path, so as
/// a list of changes it is an empty one, which is exactly what an event this
/// index discarded every path of comes to — and that one is dropped for naming
/// nothing. Read as that, the host's "I lost your changes" became silence, and
/// the index went on answering as though it were current.
pub(super) enum HostReport {
    /// Changes the host named, translated and ready to key.
    Changes(Vec<ObservedChange>),
    /// The host dropped events, and only a rebuild against the tree as it
    /// stands reaches them.
    Rescan,
}

impl HostReport {
    /// What this report and the one drained after it ask for together.
    ///
    /// A rescan is never taken back. It states that the host dropped changes it
    /// will never name, so no report drained beside it can name them either —
    /// and the rebuild it asks for reads every file, which is where the changes
    /// the other reports do name already are.
    pub(super) fn followed_by(self, next: Self) -> Self {
        match (self, next) {
            (Self::Rescan, _) | (_, Self::Rescan) => Self::Rescan,
            (Self::Changes(mut held), Self::Changes(added)) => {
                held.extend(added);
                Self::Changes(held)
            }
        }
    }
}

/// One normalized change: a repository path, its role, and the net effect.
///
/// The ordering is role, then path, then kind, which is the order a batch
/// states its rows in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceChange {
    role: ChangeRole,
    path: Arc<str>,
    kind: ChangeKind,
}

impl SourceChange {
    /// One normalized row of a batch.
    pub(super) fn stated(role: ChangeRole, path: Arc<str>, kind: ChangeKind) -> Self {
        Self { role, path, kind }
    }

    /// What the changed path is to this index's corpus.
    pub fn role(&self) -> ChangeRole {
        self.role
    }

    /// The normalized repository path that changed.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The net effect of every observation of that path in this batch.
    pub fn kind(&self) -> ChangeKind {
        self.kind
    }
}
