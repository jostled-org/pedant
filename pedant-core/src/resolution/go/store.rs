//! The shared Go source store: which sources a snapshot holds, keyed by their
//! normalized repository-relative paths.
//!
//! One normalized path is read, hashed, parsed, and walked for facts exactly
//! once even when several package contexts instantiate it. Every ceiling this
//! store owns is checked before the state it would pay for is retained, and the
//! byte ceilings bound the read itself: at most one byte past the per-file
//! ceiling ever enters memory, and the length both ceilings are compared
//! against — and the length the running total is charged — is the length that
//! actually arrived. A separate stat could not state that, because a file may
//! grow between the stat and the read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pedant_syntax::SyntaxLanguage;
use pedant_syntax::go::{GoFactLimits, GoFileFacts};
use pedant_syntax::tree_sitter::parse_bound;

use crate::hash::digest_bytes;
use crate::observe::{self, Observation};
use crate::resolution::capacity::admits_one_more;
use crate::resolution::read::{self, ReadBounds, ReadFault};

use super::condition::conditions_of;
use super::facts::GoSourceFacts;
use super::limits::GoResolutionLimits;
use super::paths;
use super::snapshot_error::{GoSnapshotError, GoSourceDefect};
use super::source::GoSource;

/// Every distinct source one snapshot reached, keyed by normalized path.
pub(super) struct GoSourceStore {
    root: PathBuf,
    limits: GoResolutionLimits,
    indexes: BTreeMap<Arc<str>, usize>,
    stored: Vec<GoSource>,
    consumed: u64,
}

/// One source read under the byte ceilings, and the length it was charged.
struct ReadSource {
    source: GoSource,
    bytes: u64,
}

impl GoSourceStore {
    /// An empty store rooted at one canonical repository root.
    pub(super) fn new(root: &Path, limits: GoResolutionLimits) -> Self {
        Self {
            root: root.to_path_buf(),
            limits,
            indexes: BTreeMap::new(),
            stored: Vec::new(),
            consumed: 0,
        }
    }

    /// Read, hash, parse, and walk `canonical` unless it is already stored, and
    /// return its normalized repository-relative path.
    ///
    /// Every ceiling is stated before the store grows, so a refusal leaves the
    /// snapshot with nothing it would have to unwind.
    pub(super) fn intern(&mut self, canonical: &Path) -> Result<Arc<str>, GoSnapshotError> {
        let relative = paths::relative_shared(&self.root, canonical)?;
        if let Some(stored) = self.indexes.get_key_value(&relative) {
            return Ok(Arc::clone(stored.0));
        }
        check_source_capacity(self.stored.len(), self.limits)?;
        let read = self.read_and_walk(canonical, &relative)?;
        self.consumed = self.consumed.saturating_add(read.bytes);
        self.indexes
            .insert(Arc::clone(&relative), self.stored.len());
        self.stored.push(read.source);
        Ok(relative)
    }

    /// The declared package name of one already-stored source.
    ///
    /// Absence here is a store inconsistency rather than a source that declares
    /// nothing: no source without a package clause is ever retained, so the
    /// caller reports the disagreement instead of reading it as a fact about
    /// the repository.
    pub(super) fn package_name(&self, path: &str) -> Option<&str> {
        self.indexes
            .get(path)
            .and_then(|index| self.stored.get(*index))
            .and_then(|source| source.facts().package_name())
    }

    /// Every stored source, sorted by normalized path.
    pub(super) fn finish(self) -> Box<[GoSource]> {
        let mut sources = self.stored;
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        sources.into_boxed_slice()
    }

    /// Read one confined source under both byte ceilings, parse it once, and
    /// walk it for facts once.
    ///
    /// The read is announced before it is attempted, so a source this store
    /// opened and failed part-way through still counts as opened. Under-
    /// reporting is the unsafe direction: a claim that a path was never opened
    /// is proved from this stream.
    fn read_and_walk(
        &self,
        canonical: &Path,
        relative: &Arc<str>,
    ) -> Result<ReadSource, GoSnapshotError> {
        observe::record(Observation::SourceRead(relative));
        let bytes = read::bounded(canonical, self.bounds())
            .map_err(|fault| byte_refusal(fault, relative, self.limits))?;
        let charged = read::byte_count(&bytes);
        let text = String::from_utf8(bytes).map_err(|_| GoSnapshotError::NonUtf8Source {
            path: Box::from(&**relative),
        })?;
        let facts = extract(&text, relative, fact_limits(self.limits))?;
        Ok(ReadSource {
            source: GoSource {
                digest: digest_bytes(text.as_bytes()),
                conditions: facts.0,
                facts: facts.1,
                path: Arc::clone(relative),
                text: Arc::from(text),
            },
            bytes: charged,
        })
    }

    /// The two byte ceilings this store reads under, and the total it has spent.
    fn bounds(&self) -> ReadBounds {
        ReadBounds {
            source_bytes: self.limits.max_source_file_bytes,
            total_bytes: self.limits.max_total_source_bytes,
            consumed: self.consumed,
        }
    }
}

/// Parse one complete source and retain the inventory it states.
///
/// The tree must be complete: a snapshot that admitted a recovered tree would
/// publish a report whose missing definitions look exactly like definitions the
/// repository never had.
fn extract(
    text: &str,
    relative: &str,
    limits: GoFactLimits,
) -> Result<(Box<[super::condition::GoBuildCondition]>, GoSourceFacts), GoSnapshotError> {
    let Some(parsed) = parse_bound(text, SyntaxLanguage::Go) else {
        return Err(incomplete(relative, GoSourceDefect::Unparsed));
    };
    observe::record(Observation::SourceParse(relative));
    if parsed.has_errors() {
        return Err(incomplete(relative, GoSourceDefect::Recovered));
    }
    let facts = parsed
        .go_file_facts(limits)
        .map_err(|source| GoSnapshotError::FactExtraction {
            path: Box::from(relative),
            source,
        })?;
    observe::record(Observation::SiteVisit(relative));
    require_package_clause(&facts, relative)?;
    Ok((
        conditions_of(paths::file_name(relative), &facts),
        GoSourceFacts::of(&facts),
    ))
}

/// A source with no package clause belongs to no package, so it cannot join
/// one.
fn require_package_clause(facts: &GoFileFacts<'_>, relative: &str) -> Result<(), GoSnapshotError> {
    match facts.package_name() {
        Some(_) => Ok(()),
        None => Err(GoSnapshotError::MissingPackageClause {
            path: Box::from(relative),
        }),
    }
}

fn incomplete(relative: &str, defect: GoSourceDefect) -> GoSnapshotError {
    GoSnapshotError::IncompleteSource {
        path: Box::from(relative),
        defect,
    }
}

/// The two fact ceilings a snapshot converts its own limits into.
fn fact_limits(limits: GoResolutionLimits) -> GoFactLimits {
    GoFactLimits::new(limits.max_syntax_depth, limits.max_facts_per_source)
}

/// One more source must still fit under the configured ceiling.
fn check_source_capacity(held: usize, limits: GoResolutionLimits) -> Result<(), GoSnapshotError> {
    match admits_one_more(held, limits.max_source_files) {
        true => Ok(()),
        false => Err(GoSnapshotError::SourceFileLimitExceeded {
            limit: limits.max_source_files,
        }),
    }
}

/// The store's own error for one refused read.
fn byte_refusal(fault: ReadFault, relative: &str, limits: GoResolutionLimits) -> GoSnapshotError {
    match fault {
        ReadFault::Unreadable(source) => GoSnapshotError::SourceRead {
            path: Box::from(relative),
            source,
        },
        ReadFault::SourceBytes => GoSnapshotError::SourceBytesLimitExceeded {
            path: Box::from(relative),
            limit: limits.max_source_file_bytes,
        },
        ReadFault::TotalBytes => GoSnapshotError::TotalSourceBytesLimitExceeded {
            limit: limits.max_total_source_bytes,
        },
    }
}
