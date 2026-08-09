//! What one resolution snapshot claims about the repository a semantic
//! database must hold.
//!
//! The claim is the whole identity Tier 2 is verified against: the canonical
//! root, the requested target, every unit and Cargo edge with its activation,
//! every unit's source closure, and the exact digest of every snapshotted
//! source. Its fingerprint covers all of them, so edges taken against one claim
//! can never be joined to a report built from another.

use std::sync::Arc;

use sha2::{Digest, Sha256};

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
    let requested = index_of(snapshot.root_unit().index());
    SemanticSnapshotClaim {
        fingerprint: fingerprint(snapshot, (&units, &edges, &sources), requested),
        root: Box::from(snapshot.root()),
        requested,
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

/// The identity every answer taken against this claim is bound to.
///
/// Each field is hashed with its own length, so no two different claims can
/// produce the same byte stream by running two fields together.
fn fingerprint(
    snapshot: &RustResolutionSnapshot,
    stated: (
        &[SemanticUnitClaim],
        &[SemanticEdgeClaim],
        &[SemanticSourceClaim],
    ),
    requested: usize,
) -> [u8; 32] {
    let (units, edges, sources) = stated;
    let mut hasher = Sha256::new();
    field(&mut hasher, snapshot.root().to_string_lossy().as_bytes());
    field(&mut hasher, &requested.to_le_bytes());
    units.iter().for_each(|unit| hash_unit(&mut hasher, unit));
    edges.iter().for_each(|edge| hash_edge(&mut hasher, edge));
    sources
        .iter()
        .for_each(|source| hash_source(&mut hasher, source));
    hasher.finalize().into()
}

fn hash_unit(hasher: &mut Sha256, unit: &SemanticUnitClaim) {
    field(hasher, unit.name.as_bytes());
    field(hasher, unit.crate_root.as_bytes());
    field(hasher, &[u8::from(unit.conditional)]);
    unit.sources
        .iter()
        .for_each(|path| field(hasher, path.as_bytes()));
}

fn hash_edge(hasher: &mut Sha256, edge: &SemanticEdgeClaim) {
    field(hasher, &edge.source.to_le_bytes());
    field(hasher, &edge.target.to_le_bytes());
    field(hasher, edge.alias.as_bytes());
    field(hasher, &[u8::from(edge.conditional)]);
}

fn hash_source(hasher: &mut Sha256, source: &SemanticSourceClaim) {
    field(hasher, source.path.as_bytes());
    field(hasher, &source.digest);
}

/// Hash one field, length first.
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_le_bytes());
    hasher.update(bytes);
}
