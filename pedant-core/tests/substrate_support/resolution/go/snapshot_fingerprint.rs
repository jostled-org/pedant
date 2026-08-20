//! The one provenance value a completed Go snapshot carries.
//!
//! A resolution and a graph are joined to a snapshot by this identity, so a
//! claim the digest does not cover is a claim two different repository states
//! can agree on. Each row holds every other family byte-identical and perturbs
//! one, which is what tells "covered" from "happens to differ".

#![cfg(feature = "resolution-test-support")]

use pedant_core::resolution::go::{GoProject, GoResolutionLimits, GoSnapshotFingerprint};

use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::fixture::snapshot_default;
use crate::resolution::go::snapshot_claims::{CLAIM_CASES, baseline_claim};
use crate::resolution::go::snapshot_fixtures::{MINIMAL, REPLACED_MODULE};

/// The families the digest is required to separate. A row deleted from
/// [`CLAIM_CASES`] lowers the pass bar, so the count is asserted first.
const EXPECTED_FAMILIES: usize = 23;

/// 4.T9 (Invariants 7, 8, 21): the snapshot fingerprint covers every
/// resolution- and graph-relevant claim, and exposes no digest bytes.
#[test]
fn go_snapshot_fingerprint_covers_every_resolution_and_graph_claim() {
    assert_eq!(
        CLAIM_CASES.len(),
        EXPECTED_FAMILIES,
        "the claim table is the pass bar, so its size is asserted before it is read"
    );

    let baseline = baseline_claim();
    let identity = baseline.fingerprint();
    assert_eq!(
        identity,
        baseline_claim().fingerprint(),
        "equal claims state one identity"
    );

    for case in CLAIM_CASES {
        let mut perturbed = baseline_claim();
        (case.perturb)(&mut perturbed);
        assert_ne!(
            perturbed.fingerprint(),
            identity,
            "the digest must separate a changed {}",
            case.label
        );
    }

    assert_eq!(
        format!("{identity:?}"),
        "GoSnapshotFingerprint(redacted)",
        "the identity renders redacted, so no diagnostic transports its bytes"
    );

    assert_snapshots_state_their_own_identities();
}

/// One repository state states one identity twice, and a different repository
/// state states another.
fn assert_snapshots_state_their_own_identities() {
    let tree = build_repository(REPLACED_MODULE, false);
    let root = repository_root(&tree);
    let first = taken(&root);
    let again = taken(&root);
    assert_eq!(
        first, again,
        "one repository state states one identity on every take"
    );
    drop(tree);

    let (other_tree, other) = snapshot_default(MINIMAL);
    assert_ne!(
        first,
        other.fingerprint(),
        "two repository states state two identities"
    );
    drop(other_tree);
}

/// The identity of one snapshot taken beneath `root`.
fn taken(root: &std::path::Path) -> GoSnapshotFingerprint {
    GoProject::load(root, GoResolutionLimits::default())
        .expect("the fixture should load")
        .snapshot_resolution()
        .expect("the fixture should snapshot")
        .fingerprint()
}
