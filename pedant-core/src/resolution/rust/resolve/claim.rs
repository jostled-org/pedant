//! What one resolution snapshot claims about the repository a semantic
//! database must hold.
//!
//! The claim is the whole identity Tier 2 is verified against: the canonical
//! root, the requested target, every unit and Cargo edge with its activation,
//! every unit's source closure, and the exact digest of every snapshotted
//! source. Its fingerprint is the value the snapshot was completed with, so
//! edges taken against one claim can never be joined to a report built from
//! another, and no second hashing implementation can drift from the first.

use std::sync::Arc;

use crate::ir::semantic::{
    SemanticEdgeClaim, SemanticSnapshotClaim, SemanticSourceClaim, SemanticUnitClaim,
};
use crate::resolution::rust::dependency::DependencyActivation;
use crate::resolution::rust::identity::index_of;
use crate::resolution::rust::snapshot::{RustResolutionSnapshot, RustSource};

use super::target::crate_name;

/// State everything `snapshot` claims, fingerprint included.
pub(super) fn state(snapshot: &RustResolutionSnapshot) -> SemanticSnapshotClaim {
    let units: Box<[SemanticUnitClaim]> = snapshot
        .units()
        .iter()
        .map(|unit| SemanticUnitClaim {
            name: crate_name(unit),
            crate_root: Arc::from(unit.crate_root()),
            sources: unit.sources().iter().map(Arc::clone).collect(),
            conditional: is_conditional(unit.activation()),
        })
        .collect();
    let edges: Box<[SemanticEdgeClaim]> = snapshot
        .edges()
        .iter()
        .map(|edge| SemanticEdgeClaim {
            source: index_of(edge.source().index()),
            target: index_of(edge.target().index()),
            alias: Arc::from(edge.name()),
            conditional: is_conditional(edge.activation()),
        })
        .collect();
    let sources: Box<[SemanticSourceClaim]> = snapshot.sources().iter().map(source).collect();
    SemanticSnapshotClaim {
        fingerprint: *snapshot.fingerprint().bytes(),
        root: Box::from(snapshot.root()),
        requested: index_of(snapshot.root_unit().index()),
        units,
        edges,
        sources,
    }
}

fn source(source: &RustSource) -> SemanticSourceClaim {
    SemanticSourceClaim {
        path: Arc::from(source.path()),
        digest: *source.digest(),
    }
}

fn is_conditional(activation: &DependencyActivation) -> bool {
    matches!(activation, DependencyActivation::Conditional(_))
}
