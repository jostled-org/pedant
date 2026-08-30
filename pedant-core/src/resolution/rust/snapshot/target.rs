//! The root-only target snapshot: exactly the sources one Cargo target's
//! module closure reaches.
//!
//! This is the source-discovery contract supply-chain hashing consumes, so it
//! never admits a dependency package's sources and never returns a partial
//! closure.

use std::sync::Arc;

use crate::resolution::line_index;
use crate::resolution::rust::fault::RustSourceFault;
use crate::resolution::rust::identity::TargetId;
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::rust::project::RustProject;
use crate::resolution::supply::SourceSupply;

use super::authority;
use super::closure::{self, ClosureEntry};
use super::error::RustSnapshotError;
use super::source::RustSource;
use super::store::{SourceStore, refuse};

/// Every source one Cargo target reaches, with its exact bytes and IR.
#[derive(Debug)]
pub struct RustTargetSnapshot {
    target: TargetId,
    crate_root: Arc<str>,
    sources: Box<[RustSource]>,
}

impl RustTargetSnapshot {
    /// The target this snapshot was taken for.
    pub fn target(&self) -> TargetId {
        self.target
    }

    /// The repository-relative entry point the closure started at.
    pub fn crate_root(&self) -> &str {
        &self.crate_root
    }

    /// Every reached source, sorted by repository-relative path.
    pub fn sources(&self) -> &[RustSource] {
        &self.sources
    }

    /// The reached source at one repository-relative path.
    pub fn source(&self, path: &str) -> Option<&RustSource> {
        line_index::find(&self.sources, path)
    }
}

/// Validate the target's authority, then walk only its module closure.
pub(in crate::resolution::rust) fn build<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    project: &RustProject,
    provider: &mut P,
    id: TargetId,
) -> Result<RustTargetSnapshot, RustSnapshotError> {
    let target = authority::validated_target(project, id)?;
    let mut store = SourceStore::new(project.root(), project.limits());
    let mut failures = Vec::new();
    let entry = ClosureEntry::of_target(target);
    let closure = closure::walk_unit(&mut store, provider, &entry, &mut failures).completed();
    match (closure, failures.is_empty()) {
        (Some(_), true) => Ok(RustTargetSnapshot {
            target: id,
            crate_root: Arc::clone(target.shared_entry_path()),
            sources: store.finish(),
        }),
        (None, _) | (Some(_), false) => Err(refuse(&store, failures)),
    }
}
