//! The one provenance value a completed Go snapshot carries.
//!
//! A resolution and a graph are joined to a snapshot by this identity, so a
//! claim the digest does not cover is a claim two different repository states
//! can agree on. Each row holds every other family byte-identical and perturbs
//! one, which is what tells "covered" from "happens to differ".

#![cfg(feature = "resolution-test-support")]

use pedant_core::resolution::go::{GoProject, GoResolutionLimits, GoSnapshotFingerprint};

use crate::resolution::authority_scan::read_text;
use crate::resolution::fingerprint::function_text;
use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::fixture::snapshot_default;
use crate::resolution::go::snapshot_claims::{CLAIM_CASES, baseline_claim};
use crate::resolution::go::snapshot_fixtures::{MINIMAL, REPLACED_MODULE};

/// The families the digest is required to separate. A row deleted from
/// [`CLAIM_CASES`] lowers the pass bar, so the count is asserted first.
const EXPECTED_FAMILIES: usize = 23;

/// The one production owner of the Go snapshot identity.
const FINGERPRINT_OWNER: &str = "pedant-core/src/resolution/go/fingerprint.rs";

/// The one owner that completes a snapshot and computes its identity there.
const COMPLETION_ADAPTER: &str = "pedant-core/src/resolution/go/snapshot.rs";

/// Each claim adapter and the stored fields its own body must read.
///
/// Grouped by owning function rather than searched over the whole file: three
/// adapters state a `path` and two state a `directory`, so a mapping that moved
/// into a neighbouring helper would still be found anywhere in the file.
const CLAIM_ADAPTERS: &[(&str, &[&str])] = &[
    (
        "fn module_claim(",
        &[
            "path: module.path()",
            "directory: module.directory()",
            "manifest: module.manifest()",
            "depth: module.depth()",
        ],
    ),
    ("fn unit_sources(", &["unit.sources()"]),
    (
        "fn unit_claim<",
        &[
            "module: unit.module().index()",
            "context: unit.context().token()",
            "import_path: unit.import_path()",
            "package_name: unit.package_name()",
            "directory: unit.directory()",
            "sources,",
        ],
    ),
    (
        "fn edge_claim(",
        &[
            "source: edge.source().index()",
            "target: edge.target().index()",
            "module_path: edge.module_path()",
            "version: edge.version()",
        ],
    ),
    (
        "fn source_predicates(",
        &[".conditions()", "condition.token()"],
    ),
    (
        "fn source_claim<",
        &[
            "path: source.path()",
            "digest: source.digest()",
            "predicates,",
        ],
    ),
];

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

    assert_production_claims_reach_the_digest();
    assert_snapshots_state_their_own_identities();
}

/// Every stored snapshot field reaches the digest through the one adapter, and
/// the identity is computed from those fields before the snapshot is published.
///
/// The rows above perturb a stated claim, so they prove the hashing rule
/// separates a family it is handed. They cannot prove the production snapshot
/// hands it one: an adapter that stopped reading `predicates` would leave all
/// 23 rows green while two repository states differing only in a build tag
/// shared one identity — which is exactly the identity Step 8's stale-snapshot
/// defence rests on. So the adapter bodies are read here too.
fn assert_production_claims_reach_the_digest() {
    let owner = read_text(FINGERPRINT_OWNER);
    let mapping = function_text(&owner, FINGERPRINT_OWNER, "fn of_completed(");
    let mut at = 0;
    for marker in [
        "root,",
        "modules: &stated,",
        "units: &compiled,",
        "edges: &required,",
        "sources: &read,",
    ] {
        let found = mapping[at..].find(marker).unwrap_or_else(|| {
            panic!("{FINGERPRINT_OWNER} states {marker} in of_completed after position {at}")
        });
        at += found + marker.len();
    }

    for (signature, fields) in CLAIM_ADAPTERS {
        let adapter = function_text(&owner, FINGERPRINT_OWNER, signature);
        for field in *fields {
            assert!(
                adapter.contains(field),
                "{FINGERPRINT_OWNER} must map {field} inside {signature}"
            );
        }
    }

    let completion = read_text(COMPLETION_ADAPTER);
    let adapter = function_text(&completion, COMPLETION_ADAPTER, "fn complete(");
    let computed = adapter
        .find("fingerprint::of_completed(")
        .expect("the completion adapter states the identity");
    let published = adapter
        .find("\n    GoResolutionSnapshot {")
        .expect("the completion adapter publishes the value");
    assert!(
        computed < published,
        "the identity is computed before the snapshot is published"
    );
    for stored in ["&root", "&modules", "(&units, &edges)", "&sources"] {
        assert!(
            adapter.contains(stored),
            "the completion adapter must supply {stored} to the constructor"
        );
    }
}

/// One repository state states one identity twice, a different repository state
/// states another, and the same bytes beneath another root state a third.
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

    let elsewhere = build_repository(REPLACED_MODULE, false);
    let copied = taken(&repository_root(&elsewhere));
    assert_ne!(
        copied, first,
        "byte-identical sources beneath another canonical root state another identity"
    );
    drop(elsewhere);
}

/// The identity of one snapshot taken beneath `root`.
fn taken(root: &std::path::Path) -> GoSnapshotFingerprint {
    GoProject::load(root, GoResolutionLimits::default())
        .expect("the fixture should load")
        .snapshot_resolution()
        .expect("the fixture should snapshot")
        .fingerprint()
}
