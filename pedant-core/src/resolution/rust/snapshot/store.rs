//! The shared source store: which sources a snapshot holds, keyed by their
//! normalized repository-relative paths.
//!
//! The store no longer opens a file. It asks a provider for one normalized
//! path, and the provider answers with the exact bytes, the digest, and the one
//! inventory that path states — reading and parsing it only if this is the
//! first request in that provider's life. Several units inside one snapshot,
//! and several snapshots that share one provider, therefore all instantiate the
//! same parse.
//!
//! The interning table, the key buffer, the file-count ceiling, the byte
//! charge, and the sorted finish belong to the shared
//! [`SnapshotStoreOf`](crate::resolution::snapshot_store::SnapshotStoreOf).
//! What this module states is the Rust half: the nesting ceiling and the
//! edition compatibility a retained record owes, the `mod` items each stored
//! source declares, and the closure vocabulary every refusal is published in.
//!
//! The provider is a parameter rather than a field. Everything else this store
//! answers — which paths it holds, what they declare, what they cost — is
//! answered from what it already holds, and only [`SourceStore::intern`] can
//! need a reader.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pedant_types::SourceRecord;

use crate::resolution::confinement::{ConfinementFault, canonical_present};
use crate::resolution::path_normalization::RelativePathError;
use crate::resolution::read::{ByteCeilings, ReadFault};
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::fault::RustSourceFault;
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::rust::limits::{ResolutionLimits, admits_depth};
use crate::resolution::rust::paths;
use crate::resolution::snapshot_rules::SnapshotRules;
use crate::resolution::snapshot_store::{Interned, SnapshotStoreOf};
use crate::resolution::supply::SourceSupply;

use super::declaration::{ModuleDeclaration, declarations_by_scope};
use super::error::{
    ClosureSite, ResolutionLimit, RustSnapshotError, SourceClosureError, SourceClosureFailure,
    SourceClosureFailureKind,
};
use super::failure::{at_path, failure, limit_failure, read_failure};
use super::source::RustSource;

/// One instantiated source beside the `mod` items it declares, projected once.
struct StoredSource {
    source: RustSource,
    declarations: BTreeMap<u32, Arc<[ModuleDeclaration]>>,
}

/// Every distinct source one snapshot reached, keyed by normalized path.
pub(super) struct SourceStore {
    store: SnapshotStoreOf<RustSnapshotRules>,
    /// The answer for a scope that declares no module, shared rather than
    /// allocated once per childless scope.
    empty: Arc<[ModuleDeclaration]>,
}

impl SourceStore {
    /// An empty store rooted at one canonical repository root.
    pub(super) fn new(root: &Path, limits: ResolutionLimits) -> Self {
        Self {
            store: SnapshotStoreOf::new(RustSnapshotRules {
                root: root.to_path_buf(),
                limits,
            }),
            empty: Arc::from(Vec::new()),
        }
    }

    /// The canonical repository root every read must stay inside.
    pub(super) fn root(&self) -> &Path {
        self.store.rules().root()
    }

    /// The ceilings this store enforces.
    pub(super) fn limits(&self) -> ResolutionLimits {
        self.store.rules().limits
    }

    /// Resolve `path` to its canonical form and refuse anything outside the
    /// repository root, following symlinks before the decision.
    pub(super) fn canonical_inside(
        &self,
        path: &Path,
        site: &ClosureSite,
    ) -> Result<PathBuf, SourceClosureFailure> {
        canonical_present(self.root(), path).map_err(|fault| match fault {
            ConfinementFault::Unreadable(source) => failure(
                site.read_kind(),
                (site, self.relative_of(path)),
                format!("{site}: the source could not be resolved: {source}"),
            ),
            // The failure's path stays the request, because that is what a
            // caller can act on and the canonical target has no
            // repository-relative spelling by definition. Where it landed is
            // named in the sentence instead: a request that escaped through a
            // link is spelled inside the root, so the request alone reads as a
            // contradiction.
            ConfinementFault::OutOfRoot { canonical } => {
                outside_root(site, self.relative_of(path), &paths::path_text(&canonical))
            }
        })
    }

    /// Instantiate `canonical` in this snapshot unless it is already held, and
    /// return its normalized repository-relative path.
    ///
    /// A source already held answers with the key retained by the store.
    ///
    /// Whether a source this snapshot already holds may also be compiled on
    /// `edition` is asked on the branch that has to ask it. A source admitted by
    /// this request was checked before it was retained, so only the held branch
    /// asks again, from the position the one lookup already produced.
    pub(super) fn intern<P: SourceSupply<RustFileInventory, RustSourceFault>>(
        &mut self,
        provider: &mut P,
        canonical: &Path,
        site: &ClosureSite,
        edition: CargoEdition,
    ) -> Result<Arc<str>, SourceClosureFailure> {
        let ceiling = self.limits().max_syntax_depth;
        let interned = self
            .store
            .intern(provider, canonical, site, |path, record| {
                retained(record, (site, path), (edition, ceiling))
            })?;
        match interned {
            Interned::Admitted(placement) => Ok(placement.path),
            Interned::Held(placement) => {
                self.check_held_edition(placement.index, edition, (site, &placement.path))?;
                Ok(placement.path)
            }
        }
    }

    /// Whether a source this snapshot already holds may also be compiled by a
    /// unit on `edition`.
    ///
    /// Takes the position [`Self::intern`]'s one lookup already produced rather
    /// than searching for the path again. The remaining absence is a slice
    /// index rather than a map miss: it names an index the store issued and no
    /// longer holds, which is the store disagreeing with itself.
    fn check_held_edition(
        &self,
        index: usize,
        edition: CargoEdition,
        at: (&ClosureSite, &str),
    ) -> Result<(), SourceClosureFailure> {
        let (site, relative) = at;
        let stored = self
            .store
            .stored(index)
            .ok_or_else(|| missing_stored_source(site, relative))?;
        compatible(stored.source.legacy_callable_trait_error(), edition, at)
    }

    /// The `mod` items one stored source declares inside one of its scopes.
    ///
    /// A path this store never interned is a store inconsistency rather than a
    /// source that declares nothing, so it is reported instead of answered.
    pub(super) fn declarations(
        &self,
        request: (&str, u32),
        site: &ClosureSite,
    ) -> Result<Arc<[ModuleDeclaration]>, SourceClosureFailure> {
        let (path, scope) = request;
        let stored = self
            .store
            .stored_at(path)
            .ok_or_else(|| missing_stored_source(site, path))?;
        Ok(stored
            .declarations
            .get(&scope)
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(&self.empty)))
    }

    /// The sorted normalized paths this store reached, as failure evidence.
    ///
    /// The evidence shares the keys retained by this store.
    pub(super) fn reached(&self) -> Box<[Arc<str>]> {
        self.store.keys()
    }

    /// Every stored source, sorted by normalized path.
    pub(super) fn finish(self) -> Box<[RustSource]> {
        self.store
            .finish()
            .into_vec()
            .into_iter()
            .map(|stored| stored.source)
            .collect()
    }

    /// One path as failure evidence, when it has a repository-relative
    /// spelling.
    ///
    /// Owned rather than shared: every reader of this is a failure payload that
    /// states the path once and is dropped with the refusal.
    pub(super) fn relative_of(&self, path: &Path) -> Option<Box<str>> {
        paths::relative_text(self.root(), path).ok()
    }
}

/// The Rust half of one snapshot retention: the root it names paths against,
/// the ceilings it holds sources to, and the vocabulary it refuses in.
struct RustSnapshotRules {
    root: PathBuf,
    limits: ResolutionLimits,
}

/// The byte ceilings, taken from the limits this snapshot was taken under.
impl ByteCeilings for RustSnapshotRules {
    fn source_bytes(&self) -> u64 {
        self.limits.source_bytes()
    }

    fn total_bytes(&self) -> u64 {
        self.limits.total_bytes()
    }
}

impl SnapshotRules for RustSnapshotRules {
    type Inventory = RustFileInventory;
    type Fault = RustSourceFault;
    type Refusal = SourceClosureFailure;
    /// A Rust refusal names the target entry, `mod` item, or Cargo edge that
    /// asked for the source, which is what tells a caller which declaration
    /// leads to it.
    type Site = ClosureSite;
    type Stored = StoredSource;

    fn root(&self) -> &Path {
        &self.root
    }

    fn max_source_files(&self) -> u32 {
        self.limits.max_source_files
    }

    fn stored_path(stored: &StoredSource) -> &str {
        stored.source.path()
    }

    fn unrelative(
        &self,
        error: RelativePathError,
        (site, canonical): (&ClosureSite, &Path),
    ) -> SourceClosureFailure {
        let source = paths::unrelative(error, &self.root, canonical);
        failure(
            SourceClosureFailureKind::OutOfRoot,
            (site, None),
            format!("{site}: the source path is not repository-relative: {source}"),
        )
    }

    fn source_files(&self, at: (&ClosureSite, &str)) -> SourceClosureFailure {
        crossed(
            ResolutionLimit::SourceFiles,
            self.max_source_files().into(),
            at,
        )
    }

    fn unnormalized(&self, at: (&ClosureSite, &str)) -> SourceClosureFailure {
        let (site, relative) = at;
        at_path(
            SourceClosureFailureKind::OutOfRoot,
            at,
            format!("{site}: {relative} is not a normalized repository-relative path"),
        )
    }

    fn refused(&self, fault: RustSourceFault, at: (&ClosureSite, &str)) -> SourceClosureFailure {
        refusal(fault, at)
    }

    fn oversized(&self, fault: ReadFault, at: (&ClosureSite, &str)) -> SourceClosureFailure {
        refusal(RustSourceFault::of_read(fault, self.limits), at)
    }
}

/// Hold one supplied record to this snapshot's own nesting ceiling and edition,
/// then project the `mod` items it declares.
///
/// The byte charge belongs to the shared store; these two are Rust's own, and
/// they are checked before the record is retained so a snapshot that refuses
/// holds nothing it would have to unwind and names no path in
/// [`SourceStore::reached`] that it did not complete.
fn retained(
    record: &SourceRecord<RustFileInventory>,
    at: (&ClosureSite, &Arc<str>),
    admits: (CargoEdition, u32),
) -> Result<StoredSource, SourceClosureFailure> {
    let (site, relative) = at;
    let (edition, max_syntax_depth) = admits;
    within_depth(record.facts().syntax_depth(), max_syntax_depth, at)?;
    compatible(
        record.facts().legacy_callable_trait_error(),
        edition,
        (site, &**relative),
    )?;
    let source = RustSource::of_record(relative, record);
    Ok(StoredSource {
        declarations: declarations_by_scope(source.ir()),
        source,
    })
}

/// The nesting one retained source may reach under this snapshot's ceiling.
///
/// A provider may parse beneath a looser ceiling than the snapshot that asked,
/// so a record another snapshot already parsed is measured exactly as a first
/// parse is.
fn within_depth(
    depth: u32,
    ceiling: u32,
    at: (&ClosureSite, &Arc<str>),
) -> Result<(), SourceClosureFailure> {
    let (site, relative) = at;
    match admits_depth(depth, ceiling) {
        true => Ok(()),
        false => Err(limit_failure(
            ResolutionLimit::SyntaxDepth,
            (site, Some(Box::from(&**relative))),
            ceiling.into(),
        )),
    }
}

/// This seam's own failure for one refused provider request.
fn refusal(fault: RustSourceFault, at: (&ClosureSite, &str)) -> SourceClosureFailure {
    let (site, relative) = at;
    match fault {
        RustSourceFault::Unreadable(source) => read_failure(site, relative, source),
        RustSourceFault::OutOfRoot { path, landing } => outside_root(site, Some(path), &landing),
        RustSourceFault::SourceFiles { ceiling } => {
            crossed(ResolutionLimit::SourceFiles, ceiling, at)
        }
        RustSourceFault::SourceBytes { ceiling } => {
            crossed(ResolutionLimit::SourceFileBytes, ceiling, at)
        }
        RustSourceFault::TotalBytes { ceiling } => {
            crossed(ResolutionLimit::TotalSourceBytes, ceiling, at)
        }
        RustSourceFault::SyntaxDepth { ceiling } => {
            crossed(ResolutionLimit::SyntaxDepth, ceiling, at)
        }
        RustSourceFault::InvalidUtf8 { reason } => at_path(
            SourceClosureFailureKind::InvalidUtf8,
            at,
            format!("{relative} is not valid UTF-8: {reason}"),
        ),
        RustSourceFault::Unparsed { reason } => at_path(
            SourceClosureFailureKind::SourceParse,
            at,
            format!("{relative} is not valid Rust: {reason}"),
        ),
        // The provider states the path it remembers refusing; this closure
        // states the site that asked for it again, which is what tells a
        // caller which `mod` item leads to the source that cannot be read.
        RustSourceFault::Refused { path } => at_path(
            site.read_kind(),
            at,
            format!("{path} was already refused by the provider reading for this snapshot"),
        ),
    }
}

/// One source that resolved outside the repository root, and where it landed.
///
/// The path is optional because the seam that measured the escape may hold no
/// repository-relative spelling for it. Naming it when it is known is what tells
/// a caller which source to act on, rather than only that some source escaped.
fn outside_root(site: &ClosureSite, path: Option<Box<str>>, landing: &str) -> SourceClosureFailure {
    let message = match &path {
        Some(relative) => {
            format!("{site}: {relative} resolves outside the repository root, at {landing}")
        }
        None => format!("{site}: the source resolves outside the repository root, at {landing}"),
    };
    failure(SourceClosureFailureKind::OutOfRoot, (site, path), message)
}

/// A ceiling the provider crossed, named against the path that crossed it.
fn crossed(limit: ResolutionLimit, ceiling: u64, at: (&ClosureSite, &str)) -> SourceClosureFailure {
    let (site, relative) = at;
    limit_failure(limit, (site, Some(Box::from(relative))), ceiling)
}

/// Whether a tree that needed pre-2021 repair may be compiled on `edition`.
///
/// One owner for both the first instantiation and every later one: the provider
/// parses permissively so a source reached from two editions is read once, and
/// this is the single place that decides which units may then use it.
fn compatible(
    legacy_error: Option<&str>,
    edition: CargoEdition,
    at: (&ClosureSite, &str),
) -> Result<(), SourceClosureFailure> {
    let (site, relative) = at;
    match (legacy_error, edition.permits_bare_callable_traits()) {
        (None, _) | (Some(_), true) => Ok(()),
        (Some(strict_error), false) => Err(failure(
            SourceClosureFailureKind::SourceParse,
            (site, Some(Box::from(relative))),
            format!("{relative} is not valid Rust: {strict_error}"),
        )),
    }
}

fn missing_stored_source(site: &ClosureSite, path: &str) -> SourceClosureFailure {
    failure(
        SourceClosureFailureKind::MissingStoredSource,
        (site, Some(Box::from(path))),
        format!("{site}: {path} is instantiated but holds no stored source"),
    )
}

/// Refuse a snapshot, binding the paths that were reached to the failures that
/// stopped the closure.
pub(super) fn refuse(
    store: &SourceStore,
    failures: Vec<SourceClosureFailure>,
) -> RustSnapshotError {
    RustSnapshotError::SourceClosure(SourceClosureError::new(
        store.reached(),
        failures.into_boxed_slice(),
    ))
}
