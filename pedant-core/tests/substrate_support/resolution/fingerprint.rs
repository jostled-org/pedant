//! Retained snapshot provenance: one computation, one owner, two consumers.
//!
//! A report is bound to the snapshot it describes, but two snapshots of the
//! same repository at different moments are different facts. These cases prove
//! the value that tells them apart covers every claim a downstream projection
//! reads, is computed once, is retained by both public owners, and never leaks
//! its bytes.

use std::collections::BTreeSet;

use pedant_core::resolution::rust::RustResolver;
#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::rust::RustSnapshotFingerprint;

#[cfg(feature = "resolution-test-support")]
use crate::resolution::fingerprint_claims::{CLAIM_CASES, baseline_claim};

use crate::resolution::authority_model::FIRST_PARTY_SOURCES;
use crate::resolution::authority_scan::{Source, first_party_sources, read_text};
use crate::resolution::fixture;
use crate::resolution::root_inventory::workspace_root;
use crate::resolution::views::sole_library;

/// The corpus the freshness cases edit. One package, one source, no dependency,
/// so a rewritten body changes the sources and nothing else.
const FRESHNESS_PROJECT: &[fixture::FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn run() { work(); }
pub fn work() {}
"#,
    ),
];

/// The same library after a source-only edit: same manifest, same path, same
/// target identity, different bytes.
const FRESHNESS_EDIT: &str = "pub fn run() { work(); }\npub fn work() { let _ = 1; }\n";

/// The one source allowed to compute a snapshot fingerprint.
const FINGERPRINT_OWNER: &str = "pedant-core/src/resolution/rust/fingerprint.rs";

/// The one owner of the framing every language's snapshot identity is built
/// from. Rust and Go each state their own claims and each hash them here, so
/// two languages cannot disagree about where one field ends.
const FRAMING_OWNER: &str = "pedant-core/src/resolution/digest.rs";

/// The one proof boundary allowed to delegate straight into that computation.
const PROOF_BUILDER: &str = "pedant-core/src/resolution/rust/test_support/claim.rs";

/// The one consumer allowed to read the digest bytes.
const BYTE_CONSUMER: &str = "pedant-core/src/resolution/rust/resolve/claim.rs";

/// The one owner that completes a snapshot and computes its identity there.
const COMPLETION_ADAPTER: &str = "pedant-core/src/resolution/rust/snapshot/resolution.rs";

/// The Go half of the same three roles.
///
/// Go states its own claims and hashes them through the same framing owner, so
/// the sole-site rule has to hold over both trees: a second hashing rule kept
/// out of the Rust tree could otherwise simply be written in the Go one, and
/// every Go coverage row would then perturb and hash entirely inside the proof
/// boundary.
const GO_FINGERPRINT_OWNER: &str = "pedant-core/src/resolution/go/fingerprint.rs";

/// The one Go proof boundary allowed to delegate straight into that computation.
const GO_PROOF_BUILDER: &str = "pedant-core/src/resolution/go/test_support.rs";

/// The one Go owner that completes a snapshot and retains its identity.
const GO_COMPLETION_ADAPTER: &str = "pedant-core/src/resolution/go/snapshot.rs";

/// The two public owners that must retain the value.
const RETAINED_OWNERS: &[&str] = &[
    COMPLETION_ADAPTER,
    "pedant-core/src/resolution/rust/resolve/target.rs",
];

/// Each claim adapter and the stored fields its own body must read.
///
/// Grouped by owning function rather than checked over the whole file: two
/// adapters state a `kind` and two state a `predicate`, and a fragment that
/// moved to a neighbouring helper would still be found anywhere in the file.
const CLAIM_ADAPTERS: &[(&str, &[&str])] = &[
    ("fn unit_sources(", &["unit.sources()"]),
    (
        "fn unit_claim<",
        &[
            "name: unit.name()",
            "manifest: unit.manifest_path()",
            "kind: unit.kind().token()",
            "crate_root: unit.crate_root()",
            "predicate: predicate(unit.activation())",
        ],
    ),
    (
        "fn edge_claim(",
        &[
            "source: edge.source().index()",
            "target: edge.target().index()",
            "alias: edge.name()",
            "kind: edge.kind()",
            "predicate: predicate(edge.activation())",
        ],
    ),
    (
        "fn source_claim(",
        &["path: source.path()", "digest: source.digest()"],
    ),
];

/// The trees a second snapshot-fingerprint hashing implementation could hide in.
const HASHING_SCOPE: &[&str] = &[
    "pedant-core/src/resolution/go/",
    "pedant-core/src/resolution/rust/resolve/",
    "pedant-core/src/resolution/rust/snapshot/",
    "pedant-core/src/resolution/rust/test_support/",
];

/// Every projection-relevant field family changes the identity, one at a time,
/// while the canonical root and the requested authority stay fixed.
///
/// The requested authority is then changed by itself, after the table, so the
/// row invariant keeps holding it fixed and the field it names is still covered.
#[cfg(feature = "resolution-test-support")]
#[test]
fn snapshot_fingerprint_covers_every_projection_claim() {
    let baseline = baseline_claim();
    let stated = baseline.fingerprint();
    assert_eq!(
        stated,
        baseline_claim().fingerprint(),
        "two identical claims state one identity"
    );

    let mut seen: BTreeSet<RustSnapshotFingerprint> = BTreeSet::new();
    for case in CLAIM_CASES {
        let mut perturbed = baseline_claim();
        (case.perturb)(&mut perturbed);
        assert_eq!(
            (&perturbed.root, perturbed.requested),
            (&baseline.root, baseline.requested),
            "{}: the row must hold canonical root and requested authority fixed",
            case.label
        );
        let changed = perturbed.fingerprint();
        assert_ne!(
            changed, stated,
            "{}: the digest does not cover this field family",
            case.label
        );
        assert!(
            seen.insert(changed),
            "{}: rows must state distinct identities",
            case.label
        );
    }
    assert_eq!(
        CLAIM_CASES.len(),
        19,
        "every covered field family needs its own row"
    );

    let mut requested = baseline_claim();
    requested.requested = 1;
    let mut restored = requested.clone();
    restored.requested = baseline.requested;
    assert_eq!(
        restored, baseline,
        "the requested case must change the requested authority alone"
    );
    let reauthorized = requested.fingerprint();
    assert_ne!(
        reauthorized, stated,
        "the digest does not cover the requested unit"
    );
    assert!(
        !seen.contains(&reauthorized),
        "the requested authority must state an identity no other row states"
    );
}

/// The completion adapter maps every stored snapshot field into the sole
/// constructor, in the specified order, before the snapshot is published.
#[test]
fn snapshot_fingerprint_production_claim_mapping_is_complete() {
    let owner = read_text(FINGERPRINT_OWNER);
    let mapping = function_text(&owner, FINGERPRINT_OWNER, "fn of_completed(");
    let mut at = 0;
    for marker in [
        "root,",
        "requested,",
        "units: &stated,",
        "edges: &selected,",
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
        .find("\n    RustResolutionSnapshot {")
        .expect("the completion adapter publishes the value");
    assert!(
        computed < published,
        "the identity is computed before the snapshot is published"
    );
    for stored in ["&root", "root_unit.index()", "&units", "&edges", "&sources"] {
        assert!(
            adapter.contains(stored),
            "the completion adapter must supply {stored} to the constructor"
        );
    }
}

/// One top-level function's text, from its signature to its closing brace.
///
/// A search over the whole file passes for a fragment that moved into a
/// neighbouring helper, which is the refactor these mappings must not survive.
///
/// Shared with the Go claim-mapping proof: both languages state their own
/// adapter tables, and one reader serves both rather than two that could
/// disagree about where a function body ends.
pub(crate) fn function_text<'a>(source: &'a str, subject: &str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("{subject} states {signature}"));
    let region = &source[start..];
    let end = region
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{subject}: {signature} has no closing brace at column zero"));
    &region[..end]
}

/// Both public owners expose one retained value, and no rendering reveals it.
#[test]
fn snapshot_fingerprint_is_retained_and_redacted() {
    let tmp = fixture::build_repository(FRESHNESS_PROJECT, false);
    let project = fixture::load_default(&tmp);
    let target = sole_library(&project);

    let first = project
        .snapshot_resolution(target)
        .expect("the fixture snapshots");
    let second = project
        .snapshot_resolution(target)
        .expect("the fixture snapshots again");
    assert_eq!(
        first.fingerprint(),
        second.fingerprint(),
        "two snapshots of one unchanged repository state share one identity"
    );

    let resolution = RustResolver::resolve_syntactic(&first).expect("the snapshot resolves");
    assert_eq!(
        first.fingerprint(),
        resolution.snapshot_fingerprint(),
        "the resolution retains the identity it was validated against"
    );

    fixture::write_file(tmp.path(), "repo/src/lib.rs", FRESHNESS_EDIT.as_bytes());
    let edited = fixture::load_default(&tmp);
    let after = edited
        .snapshot_resolution(sole_library(&edited))
        .expect("the edited fixture snapshots");
    assert_eq!(
        after.root_target(),
        first.root_target(),
        "a source-only edit leaves the manifests and the target identity alone"
    );
    assert_ne!(
        after.fingerprint(),
        first.fingerprint(),
        "a source-only edit states another repository state"
    );

    let rendered = format!("{:?}", first.fingerprint());
    assert_eq!(
        rendered, "RustSnapshotFingerprint(redacted)",
        "the identity renders without its digest"
    );
    assert!(
        !rendered.contains('['),
        "no byte sequence may reach a diagnostic: {rendered}"
    );

    let elsewhere = fixture::build_repository(FRESHNESS_PROJECT, false);
    let other = fixture::load_default(&elsewhere);
    let copied = other
        .snapshot_resolution(sole_library(&other))
        .expect("the copied fixture snapshots");
    assert_ne!(
        copied.fingerprint(),
        first.fingerprint(),
        "byte-identical sources beneath another canonical root state another identity"
    );
}

/// One production hashing owner, one proof delegate, one byte consumer.
#[test]
fn snapshot_fingerprint_has_one_production_hash_owner() {
    assert_eq!(
        workspace_source_trees(),
        FIRST_PARTY_SOURCES
            .iter()
            .map(|tree| (*tree).to_owned())
            .collect::<BTreeSet<String>>(),
        "the first-party source model must equal the workspace's own members"
    );

    let sources = first_party_sources();
    assert!(
        !sources.is_empty(),
        "the first-party source scan found nothing"
    );

    assert_sole_hash_sites(sources);
    assert_no_second_hashing_implementation(sources);
    assert_framing_delegation_and_retention(sources);
}

/// Every hashing marker is named by exactly the sources allowed to name it.
fn assert_sole_hash_sites(sources: &[Source]) {
    assert_sole_site(
        sources,
        "RustSnapshotFingerprint::from_claims",
        &[FINGERPRINT_OWNER, PROOF_BUILDER],
    );
    assert_sole_site(
        sources,
        "fn from_claims(claims: &SnapshotClaims<'_>)",
        &[FINGERPRINT_OWNER],
    );
    assert_sole_site(
        sources,
        "fn field(&mut self, bytes: &[u8])",
        &[FRAMING_OWNER],
    );
    assert_sole_site(sources, "fingerprint().bytes()", &[BYTE_CONSUMER]);
    assert_sole_site(
        sources,
        "fn bytes(&self) -> &[u8; 32]",
        &[FINGERPRINT_OWNER],
    );
    assert_sole_site(
        sources,
        "GoSnapshotFingerprint::from_claims",
        &[GO_FINGERPRINT_OWNER, GO_PROOF_BUILDER],
    );
    assert_sole_site(
        sources,
        "fn from_claims(claims: &GoSnapshotClaims<'_>)",
        &[GO_FINGERPRINT_OWNER],
    );
}

/// No source in the hashing scope carries a second hasher.
///
/// The scope is required to select sources first, so an empty filter cannot
/// pass by scanning nothing.
fn assert_no_second_hashing_implementation(sources: &[Source]) {
    for tree in HASHING_SCOPE {
        assert!(
            sources.iter().any(|source| source.path.starts_with(tree)),
            "{tree} selects no scanned source, so the second-hasher filter proves nothing"
        );
    }
    let hashing: Vec<&str> = sources
        .iter()
        .filter(|source| {
            HASHING_SCOPE
                .iter()
                .any(|tree| source.path.starts_with(tree))
                && source.text.contains("Sha256")
        })
        .map(|source| &*source.path)
        .collect();
    assert!(
        hashing.is_empty(),
        "no second snapshot-fingerprint hashing implementation may exist: {hashing:?}"
    );
}

/// The owner hashes through the one framing owner, the proof builder delegates
/// straight into it, and both public owners retain the value.
fn assert_framing_delegation_and_retention(sources: &[Source]) {
    let owner = sources
        .iter()
        .find(|source| &*source.path == FINGERPRINT_OWNER)
        .unwrap_or_else(|| panic!("{FINGERPRINT_OWNER} is a scanned first-party source"));
    assert!(
        read_text(FRAMING_OWNER).contains("self.hasher.update((bytes.len() as u64).to_le_bytes())"),
        "the framing owner states one fixed-width length-delimited digest assembly"
    );
    assert!(
        owner.text.contains("ClaimDigest::new()"),
        "{FINGERPRINT_OWNER} must build its identity through the one framing owner"
    );
    assert!(
        read_text(PROOF_BUILDER).contains("RustSnapshotFingerprint::from_claims(&SnapshotClaims {"),
        "the proof builder must delegate straight into the production constructor"
    );
    for retained in RETAINED_OWNERS {
        assert!(
            read_text(retained).contains("RustSnapshotFingerprint"),
            "{retained} must retain the value"
        );
    }

    let go = sources
        .iter()
        .find(|source| &*source.path == GO_FINGERPRINT_OWNER)
        .unwrap_or_else(|| panic!("{GO_FINGERPRINT_OWNER} is a scanned first-party source"));
    assert!(
        go.text.contains("ClaimDigest::new()"),
        "{GO_FINGERPRINT_OWNER} must build its identity through the one framing owner"
    );
    assert!(
        read_text(GO_PROOF_BUILDER)
            .contains("GoSnapshotFingerprint::from_claims(&GoSnapshotClaims {"),
        "the Go proof builder must delegate straight into the production constructor"
    );
    assert!(
        read_text(GO_COMPLETION_ADAPTER).contains("GoSnapshotFingerprint"),
        "{GO_COMPLETION_ADAPTER} must retain the value"
    );
}

/// Each marker is named by exactly the sources allowed to name it.
fn assert_sole_site(sources: &[Source], marker: &str, expected: &[&str]) {
    let found: Vec<&str> = sources
        .iter()
        .filter(|source| source.text.contains(marker))
        .map(|source| &*source.path)
        .collect();
    assert_eq!(
        found, expected,
        "{marker:?} must be named by exactly {expected:?}"
    );
}

/// Every workspace member's source tree, as the root manifest declares them.
fn workspace_source_trees() -> BTreeSet<String> {
    let manifest: toml::Table =
        toml::from_str(&read_text("Cargo.toml")).expect("the root Cargo.toml parses");
    let members: Vec<String> = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .expect("the root Cargo.toml declares [workspace] members")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("a workspace member is a path string")
                .to_owned()
        })
        .collect();
    assert_eq!(
        members.len(),
        8,
        "the workspace declares eight product members: {members:?}"
    );
    let trees: BTreeSet<String> = members
        .iter()
        .map(|member| format!("{member}/src"))
        .collect();
    for tree in &trees {
        assert!(
            workspace_root().join(tree).is_dir(),
            "{tree} is declared but absent"
        );
    }
    trees
}
