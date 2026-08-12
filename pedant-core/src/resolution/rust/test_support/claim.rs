//! A controlled snapshot claim whose every field family a proof can change.
//!
//! The builder exists so a coverage proof can hold canonical root and requested
//! authority byte-identical while it perturbs one field family at a time. It
//! delegates to the production constructor and returns only the opaque value,
//! so it can neither state a second hashing rule nor expose digest bytes.

use std::path::PathBuf;

use crate::resolution::rust::dependency::CargoDependencyKind;
use crate::resolution::rust::fingerprint::{
    EdgeClaim, RustSnapshotFingerprint, SnapshotClaims, SourceClaim, UnitClaim,
};

/// One unit's identity and source membership, as a proof states them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitFingerprintClaim {
    /// The Cargo target name the unit compiles under.
    pub name: String,
    /// The repository-relative manifest declaring the unit's target.
    pub manifest: String,
    /// The stable token of the Cargo target kind.
    pub kind: String,
    /// The repository-relative entry point of the unit's module tree.
    pub crate_root: String,
    /// The unevaluated activation predicate, when the unit is conditional.
    pub predicate: Option<String>,
    /// The sorted repository-relative sources the unit instantiates.
    pub sources: Vec<String>,
}

/// One Cargo edge's attributes, as a proof states them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeFingerprintClaim {
    /// The snapshot-local index of the declaring unit.
    pub source: u32,
    /// The snapshot-local index of the selected unit.
    pub target: u32,
    /// The namespace-local dependency or library crate name.
    pub alias: String,
    /// The dependency table that declared the edge.
    pub kind: CargoDependencyKind,
    /// The unevaluated activation predicate, when the edge is conditional.
    pub predicate: Option<String>,
}

/// One snapshotted source's normalized path and exact digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFingerprintClaim {
    /// The normalized repository-relative path.
    pub path: String,
    /// SHA-256 of the exact bytes the snapshot read.
    pub digest: [u8; 32],
}

/// Everything one stated snapshot claims, ready to be perturbed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFingerprintClaim {
    /// The canonical repository root.
    pub root: PathBuf,
    /// The snapshot-local index of the requested unit.
    pub requested: u32,
    /// Every selected unit, in snapshot order.
    pub units: Vec<UnitFingerprintClaim>,
    /// Every selected Cargo edge, in snapshot order.
    pub edges: Vec<EdgeFingerprintClaim>,
    /// Every distinct source, in snapshot order.
    pub sources: Vec<SourceFingerprintClaim>,
}

impl SnapshotFingerprintClaim {
    /// The opaque identity these stated claims produce.
    pub fn fingerprint(&self) -> RustSnapshotFingerprint {
        let memberships: Box<[Box<[&str]>]> = self
            .units
            .iter()
            .map(|unit| unit.sources.iter().map(String::as_str).collect())
            .collect();
        let units: Box<[UnitClaim<'_>]> = self
            .units
            .iter()
            .zip(&memberships)
            .map(|(unit, sources)| stated_unit(unit, sources))
            .collect();
        let edges: Box<[EdgeClaim<'_>]> = self.edges.iter().map(stated_edge).collect();
        let sources: Box<[SourceClaim<'_>]> = self.sources.iter().map(stated_source).collect();
        RustSnapshotFingerprint::from_claims(&SnapshotClaims {
            root: &self.root,
            requested: self.requested,
            units: &units,
            edges: &edges,
            sources: &sources,
        })
    }
}

fn stated_unit<'a>(unit: &'a UnitFingerprintClaim, sources: &'a [&'a str]) -> UnitClaim<'a> {
    UnitClaim {
        name: &unit.name,
        manifest: &unit.manifest,
        kind: &unit.kind,
        crate_root: &unit.crate_root,
        predicate: unit.predicate.as_deref(),
        sources,
    }
}

fn stated_edge(edge: &EdgeFingerprintClaim) -> EdgeClaim<'_> {
    EdgeClaim {
        source: edge.source,
        target: edge.target,
        alias: &edge.alias,
        kind: edge.kind,
        predicate: edge.predicate.as_deref(),
    }
}

fn stated_source(source: &SourceFingerprintClaim) -> SourceClaim<'_> {
    SourceClaim {
        path: &source.path,
        digest: &source.digest,
    }
}
