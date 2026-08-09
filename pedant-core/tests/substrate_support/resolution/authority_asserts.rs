//! Refused target identities and the fixtures that invalidate one.
//!
//! Only the proof feature can construct an identity no target occupies, so this
//! module compiles with the probe that observes the refusal.

use pedant_core::resolution::rust::{ResolutionProbe, RustProject, RustSnapshotError, TargetId};

use crate::resolution::views::observed_paths;

/// The one manifest a [`MINIMAL_PACKAGE`] fixture declares, repository-relative.
const FIXTURE_MANIFEST: &str = "Cargo.toml";

/// One manifest read per project load: the local root, the foreign root, both
/// invalidated roots, and the reload of the stale one.
const INDEXED_MANIFEST_READS: [&str; 5] = [FIXTURE_MANIFEST; 5];

/// The revision re-check reads once per snapshot operation, and only one
/// refusal ever reaches it.
const REVISION_RECHECK_READS: [&str; 2] = [FIXTURE_MANIFEST; 2];

/// One refused identity: its label, the project that must refuse it, the
/// identity itself, and the error it owes.
pub type Refusal<'a> = (
    &'a str,
    &'a RustProject,
    TargetId,
    fn(&RustSnapshotError) -> bool,
);

/// Two projects issue the same local index, so only the authority behind the
/// index can separate the identities that carry it.
pub fn assert_indices_collide(local: TargetId, foreign: TargetId) {
    assert_eq!(
        (format!("{local:?}"), format!("{foreign:?}")),
        ("TargetId(0)".to_string(), "TargetId(0)".to_string()),
        "both libraries occupy local index zero, so only the issuing \
         authority can separate them"
    );
}

/// Every manifest read the fixture loads left behind, taken before any
/// identity is offered to a snapshot.
pub fn indexed_manifest_reads(probe: &ResolutionProbe) -> Box<[Box<str>]> {
    let reads = probe.manifest_reads();
    assert_eq!(
        observed_paths(&reads),
        INDEXED_MANIFEST_READS,
        "indexing a fixture reads its one manifest, and nothing has offered an \
         identity to a snapshot yet"
    );
    reads
}

/// The revision check re-reads the manifest instead of trusting the digest
/// taken at load, and only an identity that survives root, revision, and index
/// ever reaches it.
///
/// `indexed` is what [`indexed_manifest_reads`] observed before the refusals
/// ran, so the reads compared here are the refusals' own.
pub fn assert_manifest_revision_is_reread(probe: &ResolutionProbe, indexed: &[Box<str>]) {
    let reads = probe.manifest_reads();
    let (before, during) = reads.split_at(indexed.len());
    assert_eq!(
        observed_paths(before),
        observed_paths(indexed),
        "a refusal cannot rewrite what the fixture loads already observed"
    );
    assert_eq!(
        observed_paths(during),
        REVISION_RECHECK_READS,
        "the foreign, stale, and unknown identities are refused before the \
         revision check opens anything; the changed-manifest identity reaches \
         it, and both of its snapshot operations re-read the manifest"
    );
}

/// No refusal opened a Rust source, every fixture loaded its project exactly
/// once, and an accepted identity still reads its closure.
pub fn assert_reads_only_follow_acceptance(
    probe: &ResolutionProbe,
    accepted: (&RustProject, TargetId),
    expected_loads: u32,
) {
    assert!(
        probe.source_reads().is_empty(),
        "no refusal may read a Rust source: {:?}",
        probe.source_reads()
    );
    assert_eq!(
        probe.project_loads(),
        expected_loads,
        "the probe observes the production project loader once per fixture: \
         local, foreign, both invalidated roots, and the reload"
    );

    let (project, target) = accepted;
    project.snapshot_target(target).unwrap();
    assert_eq!(
        probe.source_reads().len(),
        1,
        "an accepted authority does read its closure, so the refusals are not vacuous"
    );
}

/// Both snapshot operations refuse the identity with the same typed error.
pub fn assert_both_snapshots_refuse(refusal: &Refusal<'_>) {
    let (label, project, target, expected) = refusal;
    let by_target = project.snapshot_target(*target).expect_err(label);
    assert!(
        expected(&by_target),
        "{label}: snapshot_target returned {by_target:?}"
    );
    let by_resolution = project.snapshot_resolution(*target).expect_err(label);
    assert!(
        expected(&by_resolution),
        "{label}: snapshot_resolution returned {by_resolution:?}"
    );
}
