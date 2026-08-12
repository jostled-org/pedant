//! The one provenance value a completed resolution snapshot carries.
//!
//! A report is bound to the snapshot it describes, but a snapshot value can be
//! taken twice over sources that changed between them. The fingerprint is what
//! distinguishes those two snapshots: it covers the canonical root, the
//! requested unit, every unit identity and source membership, every Cargo edge
//! attribute, every normalized path, and every exact source digest. A consumer
//! that holds a snapshot and a resolution can therefore prove they describe the
//! same repository state before it joins them.
//!
//! Every field is hashed with its own length, and every list with its own
//! element count, so no two different claims can produce one byte stream by
//! running two fields or two lists together. Both are fixed-width, so one
//! repository state states one digest on every host.

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::dependency::{CargoDependencyKind, DependencyActivation};
use super::snapshot::{RustResolutionUnit, RustSnapshotEdge, RustSource};

/// One unit's identity and source membership, as the fingerprint reads them.
pub(in crate::resolution::rust) struct UnitClaim<'a> {
    /// The Cargo target name this unit compiles under.
    pub(in crate::resolution::rust) name: &'a str,
    /// The repository-relative manifest that declares the unit's target.
    pub(in crate::resolution::rust) manifest: &'a str,
    /// The stable token of the Cargo target kind.
    pub(in crate::resolution::rust) kind: &'a str,
    /// The repository-relative entry point the unit's module tree starts at.
    pub(in crate::resolution::rust) crate_root: &'a str,
    /// The unevaluated activation predicate, when the unit is conditional.
    pub(in crate::resolution::rust) predicate: Option<&'a str>,
    /// The sorted repository-relative sources this unit instantiates.
    pub(in crate::resolution::rust) sources: &'a [&'a str],
}

/// One Cargo edge's attributes, as the fingerprint reads them.
pub(in crate::resolution::rust) struct EdgeClaim<'a> {
    /// The snapshot-local index of the unit that declares the edge.
    pub(in crate::resolution::rust) source: u32,
    /// The snapshot-local index of the unit the edge selects.
    pub(in crate::resolution::rust) target: u32,
    /// The namespace-local dependency or library crate name.
    pub(in crate::resolution::rust) alias: &'a str,
    /// The dependency table that declared the edge.
    pub(in crate::resolution::rust) kind: CargoDependencyKind,
    /// The unevaluated activation predicate, when the edge is conditional.
    pub(in crate::resolution::rust) predicate: Option<&'a str>,
}

/// One snapshotted source's normalized path and exact digest.
pub(in crate::resolution::rust) struct SourceClaim<'a> {
    /// The normalized repository-relative path.
    pub(in crate::resolution::rust) path: &'a str,
    /// SHA-256 of the exact bytes the snapshot read.
    pub(in crate::resolution::rust) digest: &'a [u8; 32],
}

/// Everything one completed snapshot claims, in the order it is hashed.
pub(in crate::resolution::rust) struct SnapshotClaims<'a> {
    /// The canonical repository root the snapshot was taken beneath.
    pub(in crate::resolution::rust) root: &'a Path,
    /// The snapshot-local index of the unit compiling the requested target.
    pub(in crate::resolution::rust) requested: u32,
    /// Every selected unit, in snapshot order.
    pub(in crate::resolution::rust) units: &'a [UnitClaim<'a>],
    /// Every selected Cargo edge, in snapshot order.
    pub(in crate::resolution::rust) edges: &'a [EdgeClaim<'a>],
    /// Every distinct source, in snapshot order.
    pub(in crate::resolution::rust) sources: &'a [SourceClaim<'a>],
}

/// The opaque identity of one completed resolution snapshot.
///
/// The value has no public constructor, no public byte accessor, and a redacted
/// `Debug`, so it can be compared and retained but never re-derived, embedded in
/// a graph identity, or leaked through a diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RustSnapshotFingerprint {
    digest: [u8; 32],
}

impl RustSnapshotFingerprint {
    /// The sole fingerprint computation in this repository.
    ///
    /// The canonical root enters as its operating-system bytes. A root is never
    /// held to UTF-8, and a lossy rendering gives two roots that differ only in
    /// unencodable bytes one identity.
    pub(in crate::resolution::rust) fn from_claims(claims: &SnapshotClaims<'_>) -> Self {
        let mut hasher = Sha256::new();
        field(&mut hasher, claims.root.as_os_str().as_encoded_bytes());
        field(&mut hasher, &claims.requested.to_le_bytes());
        count(&mut hasher, claims.units.len());
        claims
            .units
            .iter()
            .for_each(|unit| hash_unit(&mut hasher, unit));
        count(&mut hasher, claims.edges.len());
        claims
            .edges
            .iter()
            .for_each(|edge| hash_edge(&mut hasher, edge));
        count(&mut hasher, claims.sources.len());
        claims
            .sources
            .iter()
            .for_each(|source| hash_source(&mut hasher, source));
        Self {
            digest: hasher.finalize().into(),
        }
    }

    /// The digest bytes, for the semantic claim alone.
    ///
    /// Crate-private on purpose: the semantic handshake needs a wire-shaped
    /// value, and nothing else in this repository may reconstruct or transport
    /// the identity.
    #[cfg(feature = "semantic")]
    pub(in crate::resolution::rust) fn bytes(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for RustSnapshotFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RustSnapshotFingerprint(redacted)")
    }
}

/// State everything a completed snapshot claims, then fingerprint it.
///
/// This is the one adapter between stored snapshot fields and the constructor,
/// so a field that reaches a snapshot without reaching the digest is a change
/// to this function rather than a silent omission somewhere else.
pub(in crate::resolution::rust) fn of_completed(
    root: &Path,
    requested: u32,
    units: &[RustResolutionUnit],
    edges: &[RustSnapshotEdge],
    sources: &[RustSource],
) -> RustSnapshotFingerprint {
    let memberships: Box<[Box<[&str]>]> = units.iter().map(unit_sources).collect();
    let stated: Box<[UnitClaim<'_>]> = units
        .iter()
        .zip(&memberships)
        .map(|(unit, sources)| unit_claim(unit, sources))
        .collect();
    let selected: Box<[EdgeClaim<'_>]> = edges.iter().map(edge_claim).collect();
    let read: Box<[SourceClaim<'_>]> = sources.iter().map(source_claim).collect();
    RustSnapshotFingerprint::from_claims(&SnapshotClaims {
        root,
        requested,
        units: &stated,
        edges: &selected,
        sources: &read,
    })
}

fn unit_sources(unit: &RustResolutionUnit) -> Box<[&str]> {
    unit.sources().iter().map(|path| &**path).collect()
}

fn unit_claim<'a>(unit: &'a RustResolutionUnit, sources: &'a [&'a str]) -> UnitClaim<'a> {
    UnitClaim {
        name: unit.name(),
        manifest: unit.manifest_path(),
        kind: unit.kind().token(),
        crate_root: unit.crate_root(),
        predicate: predicate(unit.activation()),
        sources,
    }
}

fn edge_claim(edge: &RustSnapshotEdge) -> EdgeClaim<'_> {
    EdgeClaim {
        source: edge.source().index(),
        target: edge.target().index(),
        alias: edge.name(),
        kind: edge.kind(),
        predicate: predicate(edge.activation()),
    }
}

fn source_claim(source: &RustSource) -> SourceClaim<'_> {
    SourceClaim {
        path: source.path(),
        digest: source.digest(),
    }
}

/// The unevaluated predicate a conditional activation records.
fn predicate(activation: &DependencyActivation) -> Option<&str> {
    match activation {
        DependencyActivation::Always => None,
        DependencyActivation::Conditional(predicate) => Some(predicate),
    }
}

fn hash_unit(hasher: &mut Sha256, unit: &UnitClaim<'_>) {
    field(hasher, unit.name.as_bytes());
    field(hasher, unit.manifest.as_bytes());
    field(hasher, unit.kind.as_bytes());
    field(hasher, unit.crate_root.as_bytes());
    hash_predicate(hasher, unit.predicate);
    count(hasher, unit.sources.len());
    unit.sources
        .iter()
        .for_each(|path| field(hasher, path.as_bytes()));
}

fn hash_edge(hasher: &mut Sha256, edge: &EdgeClaim<'_>) {
    field(hasher, &edge.source.to_le_bytes());
    field(hasher, &edge.target.to_le_bytes());
    field(hasher, edge.alias.as_bytes());
    field(hasher, &[kind_tag(edge.kind)]);
    hash_predicate(hasher, edge.predicate);
}

fn hash_source(hasher: &mut Sha256, source: &SourceClaim<'_>) {
    field(hasher, source.path.as_bytes());
    field(hasher, source.digest);
}

/// An always-active claim and a conditional one with an empty predicate are
/// distinct facts, so the presence tag is hashed beside the predicate text.
fn hash_predicate(hasher: &mut Sha256, predicate: Option<&str>) {
    match predicate {
        None => field(hasher, &[0]),
        Some(text) => {
            field(hasher, &[1]);
            field(hasher, text.as_bytes());
        }
    }
}

/// The stable byte one dependency table takes in the digest.
fn kind_tag(kind: CargoDependencyKind) -> u8 {
    match kind {
        CargoDependencyKind::Normal => 0,
        CargoDependencyKind::Development => 1,
        CargoDependencyKind::Build => 2,
    }
}

/// Hash one field, length first.
///
/// The length is a fixed-width `u64` rather than a pointer-width one, so a
/// 32-bit host and a 64-bit host state one digest for one repository state.
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Hash one list's element count, in the same framed form as a field.
///
/// A field length delimits one field; it does not say where a list ends. Without
/// the count, a claim of two units and one edge runs field-for-field against one
/// of one unit and two edges.
fn count(hasher: &mut Sha256, elements: usize) {
    field(hasher, &(elements as u64).to_le_bytes());
}
