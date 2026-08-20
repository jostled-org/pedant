//! A controlled Go snapshot claim whose every field family a proof can change.
//!
//! The builder exists so a coverage proof can hold one family byte-identical
//! while it perturbs another. It delegates to the production constructor and
//! returns only the opaque value, so it can neither state a second hashing rule
//! nor expose digest bytes.

use std::path::PathBuf;

use super::fingerprint::{
    GoEdgeClaim, GoModuleClaim, GoSnapshotClaims, GoSnapshotFingerprint, GoSourceClaim, GoUnitClaim,
};

/// One admitted module, as a proof states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoModuleFingerprintClaim {
    /// The module path its own manifest declares.
    pub path: String,
    /// The module's repository-relative directory.
    pub directory: String,
    /// The module's repository-relative manifest.
    pub manifest: String,
    /// How many replacement hops separate it from the main module.
    pub depth: u32,
}

/// One package unit's identity and source membership, as a proof states them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoUnitFingerprintClaim {
    /// The snapshot-local index of the module holding the unit.
    pub module: u32,
    /// The stable token of the unit's compilation context.
    pub context: String,
    /// The import path the unit's directory has inside its module.
    pub import_path: String,
    /// The package clause the unit's sources declare.
    pub package_name: String,
    /// The unit's repository-relative directory.
    pub directory: String,
    /// The sorted repository-relative sources the unit instantiates.
    pub sources: Vec<String>,
}

/// One local dependency edge, as a proof states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoEdgeFingerprintClaim {
    /// The snapshot-local index of the requiring module.
    pub source: u32,
    /// The snapshot-local index of the required module.
    pub target: u32,
    /// The module path the requirement names.
    pub module_path: String,
    /// The version the requirement names.
    pub version: String,
}

/// One snapshotted source's path, digest, and predicates, as a proof states
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoSourceFingerprintClaim {
    /// The normalized repository-relative path.
    pub path: String,
    /// SHA-256 of the exact bytes the snapshot read.
    pub digest: [u8; 32],
    /// The stable tokens of every retained build predicate.
    pub predicates: Vec<String>,
}

/// Everything one stated Go snapshot claims, ready to be perturbed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoSnapshotFingerprintClaim {
    /// The canonical repository root.
    pub root: PathBuf,
    /// Every admitted module, in snapshot order.
    pub modules: Vec<GoModuleFingerprintClaim>,
    /// Every package unit, in snapshot order.
    pub units: Vec<GoUnitFingerprintClaim>,
    /// Every local dependency edge, in snapshot order.
    pub edges: Vec<GoEdgeFingerprintClaim>,
    /// Every distinct source, in snapshot order.
    pub sources: Vec<GoSourceFingerprintClaim>,
}

impl GoSnapshotFingerprintClaim {
    /// The opaque identity these stated claims produce.
    pub fn fingerprint(&self) -> GoSnapshotFingerprint {
        let modules: Box<[GoModuleClaim<'_>]> = self.modules.iter().map(stated_module).collect();
        let memberships: Box<[Box<[&str]>]> = self
            .units
            .iter()
            .map(|unit| unit.sources.iter().map(String::as_str).collect())
            .collect();
        let units: Box<[GoUnitClaim<'_>]> = self
            .units
            .iter()
            .zip(&memberships)
            .map(|(unit, sources)| stated_unit(unit, sources))
            .collect();
        let edges: Box<[GoEdgeClaim<'_>]> = self.edges.iter().map(stated_edge).collect();
        let predicates: Box<[Box<[&str]>]> = self
            .sources
            .iter()
            .map(|source| source.predicates.iter().map(String::as_str).collect())
            .collect();
        let sources: Box<[GoSourceClaim<'_>]> = self
            .sources
            .iter()
            .zip(&predicates)
            .map(|(source, predicates)| stated_source(source, predicates))
            .collect();
        GoSnapshotFingerprint::from_claims(&GoSnapshotClaims {
            root: &self.root,
            modules: &modules,
            units: &units,
            edges: &edges,
            sources: &sources,
        })
    }
}

fn stated_module(module: &GoModuleFingerprintClaim) -> GoModuleClaim<'_> {
    GoModuleClaim {
        path: &module.path,
        directory: &module.directory,
        manifest: &module.manifest,
        depth: module.depth,
    }
}

fn stated_unit<'a>(unit: &'a GoUnitFingerprintClaim, sources: &'a [&'a str]) -> GoUnitClaim<'a> {
    GoUnitClaim {
        module: unit.module,
        context: &unit.context,
        import_path: &unit.import_path,
        package_name: &unit.package_name,
        directory: &unit.directory,
        sources,
    }
}

fn stated_edge(edge: &GoEdgeFingerprintClaim) -> GoEdgeClaim<'_> {
    GoEdgeClaim {
        source: edge.source,
        target: edge.target,
        module_path: &edge.module_path,
        version: &edge.version,
    }
}

fn stated_source<'a>(
    source: &'a GoSourceFingerprintClaim,
    predicates: &'a [&'a str],
) -> GoSourceClaim<'a> {
    GoSourceClaim {
        path: &source.path,
        digest: &source.digest,
        predicates,
    }
}
