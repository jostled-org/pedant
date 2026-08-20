//! The one provenance value a completed Go snapshot carries.
//!
//! A resolution and a graph are joined to the snapshot they describe by this
//! identity, so it covers every claim either of them can restate: the canonical
//! root, each admitted module, each package unit and its source membership,
//! each local dependency edge, and each source's normalized path, exact digest,
//! and retained predicates. Framing belongs to
//! [`ClaimDigest`](crate::resolution::digest::ClaimDigest), so a Go claim and a
//! Rust claim cannot disagree about where one field ends.

use std::fmt;
use std::path::Path;

use crate::resolution::digest::ClaimDigest;

use super::snapshot_module::{GoSnapshotEdge, GoSnapshotModule};
use super::source::GoSource;
use super::unit::GoResolutionUnit;

/// One admitted module, as the fingerprint reads it.
pub(super) struct GoModuleClaim<'a> {
    /// The module path its own manifest declares.
    pub(super) path: &'a str,
    /// The module's repository-relative directory.
    pub(super) directory: &'a str,
    /// The module's repository-relative manifest.
    pub(super) manifest: &'a str,
    /// How many replacement hops separate it from the main module.
    pub(super) depth: u32,
}

/// One package unit's identity and source membership, as the fingerprint reads
/// them.
pub(super) struct GoUnitClaim<'a> {
    /// The snapshot-local index of the module holding the unit.
    pub(super) module: u32,
    /// The stable token of the unit's compilation context.
    pub(super) context: &'a str,
    /// The import path the unit's directory has inside its module.
    pub(super) import_path: &'a str,
    /// The package clause the unit's sources declare.
    pub(super) package_name: &'a str,
    /// The unit's repository-relative directory.
    pub(super) directory: &'a str,
    /// The sorted repository-relative sources the unit instantiates.
    pub(super) sources: &'a [&'a str],
}

/// One local dependency edge's attributes, as the fingerprint reads them.
pub(super) struct GoEdgeClaim<'a> {
    /// The snapshot-local index of the requiring module.
    pub(super) source: u32,
    /// The snapshot-local index of the required module.
    pub(super) target: u32,
    /// The module path the requirement names.
    pub(super) module_path: &'a str,
    /// The version the requirement names.
    pub(super) version: &'a str,
}

/// One snapshotted source's normalized path, exact digest, and predicates.
pub(super) struct GoSourceClaim<'a> {
    /// The normalized repository-relative path.
    pub(super) path: &'a str,
    /// SHA-256 of the exact bytes the snapshot read.
    pub(super) digest: &'a [u8; 32],
    /// The stable tokens of every retained build predicate, in source order.
    pub(super) predicates: &'a [&'a str],
}

/// Everything one completed snapshot claims, in the order it is hashed.
pub(super) struct GoSnapshotClaims<'a> {
    /// The canonical repository root the snapshot was taken beneath.
    pub(super) root: &'a Path,
    /// Every admitted module, in snapshot order.
    pub(super) modules: &'a [GoModuleClaim<'a>],
    /// Every package unit, in snapshot order.
    pub(super) units: &'a [GoUnitClaim<'a>],
    /// Every local dependency edge, in snapshot order.
    pub(super) edges: &'a [GoEdgeClaim<'a>],
    /// Every distinct source, in snapshot order.
    pub(super) sources: &'a [GoSourceClaim<'a>],
}

/// The opaque identity of one completed Go resolution snapshot.
///
/// The value has no public constructor, no public byte accessor, and a redacted
/// `Debug`, so it can be compared and retained but never re-derived, embedded
/// in a graph identity, or leaked through a diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoSnapshotFingerprint {
    digest: [u8; 32],
}

impl GoSnapshotFingerprint {
    /// The sole Go fingerprint computation in this repository.
    ///
    /// The canonical root enters as its operating-system bytes. A root is never
    /// held to UTF-8, and a lossy rendering would give two roots that differ
    /// only in unencodable bytes one identity.
    pub(super) fn from_claims(claims: &GoSnapshotClaims<'_>) -> Self {
        let mut digest = ClaimDigest::new();
        digest.field(claims.root.as_os_str().as_encoded_bytes());
        digest.count(claims.modules.len());
        claims
            .modules
            .iter()
            .for_each(|module| hash_module(&mut digest, module));
        digest.count(claims.units.len());
        claims
            .units
            .iter()
            .for_each(|unit| hash_unit(&mut digest, unit));
        digest.count(claims.edges.len());
        claims
            .edges
            .iter()
            .for_each(|edge| hash_edge(&mut digest, edge));
        digest.count(claims.sources.len());
        claims
            .sources
            .iter()
            .for_each(|source| hash_source(&mut digest, source));
        Self {
            digest: digest.finish(),
        }
    }
}

impl fmt::Debug for GoSnapshotFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GoSnapshotFingerprint(redacted)")
    }
}

/// Every stored field a completed snapshot holds, stated as claims and hashed.
///
/// This is the one adapter between snapshot fields and the constructor, so a
/// field that reaches a snapshot without reaching the digest is a change to
/// this function rather than a silent omission somewhere else.
pub(super) fn of_completed(
    root: &Path,
    modules: &[GoSnapshotModule],
    held: (&[GoResolutionUnit], &[GoSnapshotEdge]),
    sources: &[GoSource],
) -> GoSnapshotFingerprint {
    let (units, edges) = held;
    let stated: Box<[GoModuleClaim<'_>]> = modules.iter().map(module_claim).collect();
    let memberships: Box<[Box<[&str]>]> = units.iter().map(unit_sources).collect();
    let compiled: Box<[GoUnitClaim<'_>]> = units
        .iter()
        .zip(&memberships)
        .map(|(unit, sources)| unit_claim(unit, sources))
        .collect();
    let required: Box<[GoEdgeClaim<'_>]> = edges.iter().map(edge_claim).collect();
    let tokens: Box<[Box<[Box<str>]>]> = sources.iter().map(source_predicates).collect();
    let borrowed: Box<[Box<[&str]>]> = tokens
        .iter()
        .map(|held| held.iter().map(|token| &**token).collect())
        .collect();
    let read: Box<[GoSourceClaim<'_>]> = sources
        .iter()
        .zip(&borrowed)
        .map(|(source, predicates)| source_claim(source, predicates))
        .collect();
    GoSnapshotFingerprint::from_claims(&GoSnapshotClaims {
        root,
        modules: &stated,
        units: &compiled,
        edges: &required,
        sources: &read,
    })
}

fn module_claim(module: &GoSnapshotModule) -> GoModuleClaim<'_> {
    GoModuleClaim {
        path: module.path(),
        directory: module.directory(),
        manifest: module.manifest(),
        depth: module.depth(),
    }
}

fn unit_sources(unit: &GoResolutionUnit) -> Box<[&str]> {
    unit.sources().iter().map(|path| &**path).collect()
}

fn unit_claim<'a>(unit: &'a GoResolutionUnit, sources: &'a [&'a str]) -> GoUnitClaim<'a> {
    GoUnitClaim {
        module: unit.module().index(),
        context: unit.context().token(),
        import_path: unit.import_path(),
        package_name: unit.package_name(),
        directory: unit.directory(),
        sources,
    }
}

fn edge_claim(edge: &GoSnapshotEdge) -> GoEdgeClaim<'_> {
    GoEdgeClaim {
        source: edge.source().index(),
        target: edge.target().index(),
        module_path: edge.module_path(),
        version: edge.version(),
    }
}

fn source_predicates(source: &GoSource) -> Box<[Box<str>]> {
    source
        .conditions()
        .iter()
        .map(|condition| condition.token())
        .collect()
}

fn source_claim<'a>(source: &'a GoSource, predicates: &'a [&'a str]) -> GoSourceClaim<'a> {
    GoSourceClaim {
        path: source.path(),
        digest: source.digest(),
        predicates,
    }
}

fn hash_module(digest: &mut ClaimDigest, module: &GoModuleClaim<'_>) {
    digest.text(module.path);
    digest.text(module.directory);
    digest.text(module.manifest);
    digest.field(&module.depth.to_le_bytes());
}

fn hash_unit(digest: &mut ClaimDigest, unit: &GoUnitClaim<'_>) {
    digest.field(&unit.module.to_le_bytes());
    digest.text(unit.context);
    digest.text(unit.import_path);
    digest.text(unit.package_name);
    digest.text(unit.directory);
    digest.count(unit.sources.len());
    unit.sources.iter().for_each(|path| digest.text(path));
}

fn hash_edge(digest: &mut ClaimDigest, edge: &GoEdgeClaim<'_>) {
    digest.field(&edge.source.to_le_bytes());
    digest.field(&edge.target.to_le_bytes());
    digest.text(edge.module_path);
    digest.text(edge.version);
}

fn hash_source(digest: &mut ClaimDigest, source: &GoSourceClaim<'_>) {
    digest.text(source.path);
    digest.field(source.digest);
    digest.count(source.predicates.len());
    source
        .predicates
        .iter()
        .for_each(|token| digest.text(token));
}
