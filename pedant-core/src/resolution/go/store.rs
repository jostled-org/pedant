//! The shared Go source store: which sources a snapshot holds, keyed by their
//! normalized repository-relative paths.
//!
//! The store no longer opens a file. It asks a provider for one normalized
//! path, and the provider answers with the exact bytes, the digest, and the one
//! inventory that path states — reading, parsing, and walking it only if this
//! is the first request in that provider's life. Several package contexts
//! inside one snapshot, and several snapshots that share one provider, all
//! instantiate the same walk.
//!
//! The interning table, the key buffer, the file-count ceiling, the byte
//! charge, and the sorted finish belong to the shared
//! [`SnapshotStoreOf`](crate::resolution::snapshot_store::SnapshotStoreOf).
//! What this module states is only the Go half: the two extra ceilings a
//! retained record owes — the facts its walk kept and the depth it reached —
//! and the snapshot vocabulary each refusal is published in.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pedant_types::SourceRecord;

use crate::resolution::path_normalization::RelativePathError;
use crate::resolution::read::{ByteCeilings, ReadFault};
use crate::resolution::snapshot_rules::SnapshotRules;
use crate::resolution::snapshot_store::{Interned, SnapshotStoreOf};
use crate::resolution::supply::SourceSupply;

use super::fault::GoSourceFault;
use super::inventory::GoFileInventory;
use super::limits::GoResolutionLimits;
use super::paths;
use super::snapshot_error::GoSnapshotError;
use super::source::GoSource;

/// Every distinct source one snapshot reached, keyed by normalized path.
pub(super) struct GoSourceStore {
    store: SnapshotStoreOf<GoSnapshotRules>,
}

impl GoSourceStore {
    /// An empty store rooted at one canonical repository root.
    pub(super) fn new(root: &Path, limits: GoResolutionLimits) -> Self {
        Self {
            store: SnapshotStoreOf::new(GoSnapshotRules {
                root: root.to_path_buf(),
                limits,
            }),
        }
    }

    /// Retain `canonical` in this snapshot unless it is already held, and
    /// return its normalized repository-relative path beside the position it
    /// occupies.
    ///
    /// The position travels with the path because the caller has a second
    /// question about the same source — which package its clause declares — and
    /// answering it from the key meant searching the interning table a second
    /// time for a source that was just looked up.
    pub(super) fn intern<P: SourceSupply<GoFileInventory, GoSourceFault>>(
        &mut self,
        provider: &mut P,
        canonical: &Path,
    ) -> Result<(Arc<str>, usize), GoSnapshotError> {
        let limits = self.store.rules().limits;
        let interned = self
            .store
            .intern(provider, canonical, &(), |path, record| {
                check_retention(record, path, limits)?;
                Ok(GoSource::of_record(path, record))
            })?;
        match interned {
            Interned::Held(placement) | Interned::Admitted(placement) => {
                Ok((placement.path, placement.index))
            }
        }
    }

    /// The declared package name of the source at one stored position.
    ///
    /// Absence here is a store inconsistency rather than a source that declares
    /// nothing: no source without a package clause is ever retained, so the
    /// caller reports the disagreement instead of reading it as a fact about
    /// the repository.
    pub(super) fn package_name_at(&self, index: usize) -> Option<&str> {
        self.store
            .stored(index)
            .and_then(|source| source.facts().package_name())
    }

    /// Every stored source, sorted by normalized path.
    pub(super) fn finish(self) -> Box<[GoSource]> {
        self.store.finish()
    }
}

/// The Go half of one snapshot retention: the root it names paths against, the
/// ceilings it holds them to, and the vocabulary it refuses in.
struct GoSnapshotRules {
    root: PathBuf,
    limits: GoResolutionLimits,
}

/// The byte ceilings, taken from the limits this snapshot was taken under.
impl ByteCeilings for GoSnapshotRules {
    fn source_bytes(&self) -> u64 {
        self.limits.source_bytes()
    }

    fn total_bytes(&self) -> u64 {
        self.limits.total_bytes()
    }
}

impl SnapshotRules for GoSnapshotRules {
    type Inventory = GoFileInventory;
    type Fault = GoSourceFault;
    type Refusal = GoSnapshotError;
    /// A Go refusal names the path and nothing else: a package walk has no
    /// declaration site to name, because a directory's sources are what put it
    /// in the snapshot.
    type Site = ();
    type Stored = GoSource;

    fn root(&self) -> &Path {
        &self.root
    }

    fn max_source_files(&self) -> u32 {
        self.limits.max_source_files
    }

    fn stored_path(stored: &GoSource) -> &str {
        stored.path()
    }

    fn unrelative(
        &self,
        error: RelativePathError,
        (_, canonical): (&(), &Path),
    ) -> GoSnapshotError {
        paths::unrelative(error, &self.root, canonical).into()
    }

    /// The ceiling alone. A Go snapshot's file-count refusal names no path,
    /// because the source that crossed the ceiling is not the source that is
    /// wrong.
    fn source_files(&self, (_, _): (&(), &str)) -> GoSnapshotError {
        GoSnapshotError::SourceFileLimitExceeded {
            limit: self.limits.max_source_files,
        }
    }

    fn unnormalized(&self, (_, relative): (&(), &str)) -> GoSnapshotError {
        GoSnapshotError::UnnormalizedPath {
            path: Box::from(relative),
        }
    }

    fn refused(&self, fault: GoSourceFault, (_, relative): (&(), &str)) -> GoSnapshotError {
        refusal(fault, (&self.root, relative))
    }

    fn oversized(&self, fault: ReadFault, at: (&(), &str)) -> GoSnapshotError {
        self.refused(GoSourceFault::of_read(fault, self.limits), at)
    }
}

/// Hold one supplied record to this snapshot's own fact and depth ceilings.
///
/// The byte charge belongs to the shared store; these two are Go's own, and
/// they are checked before the record is retained so a refusal leaves the
/// snapshot with nothing it would have to unwind. A provider may walk beneath
/// looser ceilings than the snapshot that asked — that is the point of sharing
/// one — so a record another snapshot already walked is checked exactly as a
/// first walk is.
fn check_retention(
    record: &SourceRecord<GoFileInventory>,
    relative: &str,
    limits: GoResolutionLimits,
) -> Result<(), GoSnapshotError> {
    let facts = record.facts();
    match (
        facts.fact_count() > limits.max_facts_per_source,
        facts.syntax_depth() > limits.max_syntax_depth,
    ) {
        (true, _) => Err(GoSnapshotError::RetainedFactsExceeded {
            path: Box::from(relative),
            limit: limits.max_facts_per_source,
        }),
        (false, true) => Err(GoSnapshotError::RetainedDepthExceeded {
            path: Box::from(relative),
            limit: limits.max_syntax_depth,
        }),
        (false, false) => Ok(()),
    }
}

/// The store's own error for one refused provider request.
///
/// A free function taking exactly what it reads: the root the refusal is
/// measured against, and the path it is reported for. A provider states which
/// path escaped its own confinement; naming the root is this seam's job, because
/// this seam is the one that has one.
fn refusal(fault: GoSourceFault, at: (&Path, &str)) -> GoSnapshotError {
    let (root, relative) = at;
    match fault {
        GoSourceFault::Unreadable(source) => GoSnapshotError::SourceRead {
            path: Box::from(relative),
            source,
        },
        // The provider states where the request landed; this seam holds the
        // root it is measured against and the repository-relative path that was
        // asked for, and a refusal naming only the landing leaves a caller with
        // no path it can act on.
        GoSourceFault::OutOfRoot { path } => GoSnapshotError::OutOfRoot {
            path,
            root: paths::path_text(root),
            request: Box::from(relative),
        },
        GoSourceFault::NonUtf8Path { path } => GoSnapshotError::NonUtf8Path { path },
        GoSourceFault::PathRead { path, source } => GoSnapshotError::PathRead { path, source },
        GoSourceFault::SourceFiles { ceiling } => {
            GoSnapshotError::SourceFileLimitExceeded { limit: ceiling }
        }
        GoSourceFault::SourceBytes { ceiling } => GoSnapshotError::SourceBytesLimitExceeded {
            path: Box::from(relative),
            limit: ceiling,
        },
        GoSourceFault::TotalBytes { ceiling } => {
            GoSnapshotError::TotalSourceBytesLimitExceeded { limit: ceiling }
        }
        GoSourceFault::NonUtf8 { reason } => GoSnapshotError::NonUtf8Source {
            path: Box::from(relative),
            reason,
        },
        GoSourceFault::Unparsed { reason } => GoSnapshotError::UnparsedSource {
            path: Box::from(relative),
            reason,
        },
        GoSourceFault::Incomplete(defect) => GoSnapshotError::IncompleteSource {
            path: Box::from(relative),
            defect,
        },
        GoSourceFault::FactExtraction(source) => GoSnapshotError::FactExtraction {
            path: Box::from(relative),
            source,
        },
        GoSourceFault::MissingPackageClause => GoSnapshotError::MissingPackageClause {
            path: Box::from(relative),
        },
        GoSourceFault::Refused { path } => GoSnapshotError::AlreadyRefused { path },
        GoSourceFault::StructureProjection { reason } => GoSnapshotError::StructureProjection {
            path: Box::from(relative),
            reason,
        },
    }
}
