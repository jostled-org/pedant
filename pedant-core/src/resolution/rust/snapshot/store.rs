//! The shared source store: which sources a snapshot holds, keyed by their
//! normalized repository-relative paths.
//!
//! One normalized path is read, hashed, and parsed exactly once even when
//! several resolution units instantiate it, so per-unit identities never cost a
//! second parse.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ir::extract::ParseCompatibility;
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::identity::position;
use crate::resolution::rust::limits::ResolutionLimits;
use crate::resolution::rust::paths;

use super::declaration::{ModuleDeclaration, declarations_by_scope};
use super::error::{
    ClosureSite, ResolutionLimit, RustSnapshotError, SourceClosureError, SourceClosureFailure,
    SourceClosureFailureKind,
};
use super::failure::{failure, limit_failure};
use super::reader::{ReadBudget, ReadRequest, byte_length, read_source};
use super::source::RustSource;

/// One read source beside the `mod` items it declares, projected once.
struct StoredSource {
    source: RustSource,
    declarations: BTreeMap<u32, Arc<[ModuleDeclaration]>>,
    compatibility: ParseCompatibility,
}

/// Every distinct source one snapshot reached, keyed by normalized path.
pub(super) struct SourceStore {
    root: PathBuf,
    limits: ResolutionLimits,
    indexes: BTreeMap<Arc<str>, usize>,
    stored: Vec<StoredSource>,
    /// The answer for a scope that declares no module, shared rather than
    /// allocated once per childless scope.
    empty: Arc<[ModuleDeclaration]>,
    consumed: u64,
}

impl SourceStore {
    /// An empty store rooted at one canonical repository root.
    pub(super) fn new(root: &Path, limits: ResolutionLimits) -> Self {
        Self {
            root: root.to_path_buf(),
            limits,
            indexes: BTreeMap::new(),
            stored: Vec::new(),
            empty: Arc::from(Vec::new()),
            consumed: 0,
        }
    }

    /// The canonical repository root every read must stay inside.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// The ceilings this store enforces.
    pub(super) fn limits(&self) -> ResolutionLimits {
        self.limits
    }

    /// Resolve `path` to its canonical form and refuse anything outside the
    /// repository root, following symlinks before the decision.
    pub(super) fn canonical_inside(
        &self,
        path: &Path,
        site: &ClosureSite,
    ) -> Result<PathBuf, SourceClosureFailure> {
        let canonical = std::fs::canonicalize(path).map_err(|source| {
            failure(
                site.read_kind(),
                (site, self.relative_of(path)),
                format!("{site}: the source could not be resolved: {source}"),
            )
        })?;
        match paths::contains(&self.root, &canonical) {
            true => Ok(canonical),
            false => Err(failure(
                SourceClosureFailureKind::OutOfRoot,
                (site, None),
                format!("{site}: the source resolves outside the repository root"),
            )),
        }
    }

    /// Read, hash, and parse `canonical` unless it is already stored, and
    /// return its normalized repository-relative path.
    pub(super) fn intern(
        &mut self,
        canonical: &Path,
        site: &ClosureSite,
        edition: CargoEdition,
    ) -> Result<Arc<str>, SourceClosureFailure> {
        let relative = self.relative(canonical, site)?;
        if let Some(stored) = self.stored_source(&relative) {
            return compatible_path(stored, edition, site, relative);
        }
        self.check_capacity(site, &relative)?;
        let stored = read_source(
            &ReadRequest {
                canonical,
                relative: &relative,
                site,
                edition,
            },
            ReadBudget {
                limits: self.limits,
                consumed: self.consumed,
            },
        )?;
        self.consumed = self.consumed.saturating_add(byte_length(&stored.source));
        self.indexes
            .insert(Arc::clone(&relative), self.stored.len());
        self.stored.push(StoredSource {
            declarations: declarations_by_scope(&stored.source.ir),
            source: stored.source,
            compatibility: stored.compatibility,
        });
        Ok(relative)
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
        let stored = self.stored_source(path).ok_or_else(|| {
            failure(
                SourceClosureFailureKind::MissingStoredSource,
                (site, Some(Box::from(path))),
                format!("{site}: {path} is instantiated but holds no stored source"),
            )
        })?;
        Ok(stored
            .declarations
            .get(&scope)
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(&self.empty)))
    }

    fn stored_source(&self, path: &str) -> Option<&StoredSource> {
        self.indexes
            .get(path)
            .and_then(|index| self.stored.get(*index))
    }

    /// The sorted normalized paths this store reached, as failure evidence.
    pub(super) fn reached(&self) -> Box<[Box<str>]> {
        self.indexes.keys().map(|path| Box::from(&**path)).collect()
    }

    /// Every stored source, sorted by normalized path.
    pub(super) fn finish(self) -> Box<[RustSource]> {
        let mut sources: Vec<RustSource> = self
            .stored
            .into_iter()
            .map(|stored| stored.source)
            .collect();
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        sources.into_boxed_slice()
    }

    fn relative(
        &self,
        canonical: &Path,
        site: &ClosureSite,
    ) -> Result<Arc<str>, SourceClosureFailure> {
        paths::relative_text(&self.root, canonical).map_err(|source| {
            failure(
                SourceClosureFailureKind::OutOfRoot,
                (site, None),
                format!("{site}: the source path is not repository-relative: {source}"),
            )
        })
    }

    fn check_capacity(
        &self,
        site: &ClosureSite,
        relative: &str,
    ) -> Result<(), SourceClosureFailure> {
        let next = u64::from(position(self.stored.len())).saturating_add(1);
        match next > u64::from(self.limits.max_source_files) {
            true => Err(limit_failure(
                ResolutionLimit::SourceFiles,
                (site, Some(Box::from(relative))),
                self.limits.max_source_files.into(),
            )),
            false => Ok(()),
        }
    }

    pub(super) fn relative_of(&self, path: &Path) -> Option<Box<str>> {
        paths::relative_text(&self.root, path)
            .ok()
            .map(|text| Box::from(&*text))
    }
}

fn compatible_path(
    stored: &StoredSource,
    edition: CargoEdition,
    site: &ClosureSite,
    relative: Arc<str>,
) -> Result<Arc<str>, SourceClosureFailure> {
    match (
        &stored.compatibility,
        edition.permits_bare_callable_traits(),
    ) {
        (ParseCompatibility::AllEditions, _)
        | (ParseCompatibility::LegacyCallableTraits { .. }, true) => Ok(relative),
        (ParseCompatibility::LegacyCallableTraits { strict_error }, false) => Err(failure(
            SourceClosureFailureKind::SourceParse,
            (site, Some(Box::from(&*relative))),
            format!("{relative} is not valid Rust: {strict_error}"),
        )),
    }
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
