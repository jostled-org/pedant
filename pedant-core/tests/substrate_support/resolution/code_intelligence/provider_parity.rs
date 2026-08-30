//! What a provider changes, and what it must not.
//!
//! The seam is allowed to change who read a source. It is allowed to change
//! nothing else — not the units a snapshot selects, not the digests it holds,
//! not the fingerprint it publishes, not the report a resolver derives from it,
//! and not the refusal a malformed repository earns. Both claims below compare
//! whole serialized answers rather than field samples, because a seam that
//! changed one field of one record would otherwise pass every spot check.

use std::sync::Arc;

use pedant_core::resolution::go::{
    GoProjectResolution, GoResolutionLimits, GoResolutionSnapshot, GoResolver,
};
use pedant_core::resolution::rust::{
    ResolutionLimits, RustResolutionSnapshot, RustResolver, RustTargetResolution,
};

use super::go_fixture::{GO_REPOSITORY, GoFixture, PARTIALLY_MALFORMED_GO_REPOSITORY};
use super::rust_fixture::{PARTIALLY_MALFORMED_REPOSITORY, RustFixture};

/// One retained source, rendered as everything an identity claim compares.
#[derive(Debug, PartialEq, Eq)]
struct SourceClaim {
    path: Box<str>,
    digest: Box<str>,
    text: Box<str>,
}

/// One snapshot, rendered as everything an identity claim compares.
#[derive(Debug, PartialEq, Eq)]
struct SnapshotClaim {
    fingerprint: Box<str>,
    units: Box<[Box<str>]>,
    sources: Box<[SourceClaim]>,
    report: Box<str>,
}

/// 3.T3 (Invariants 3, 21): the provider-aware and convenience entry points
/// return byte-equal units, sources, fingerprints, reports, and refusals.
#[test]
fn provider_aware_snapshots_match_private_provider_results() {
    rust_success_and_refusal_match();
    go_refusal_matches();
}

/// 3.T7 (Invariants 1, 21): reusing one provider across two snapshots changes
/// observations only — every digest, fingerprint, and report byte is the one
/// the convenience entry point publishes.
#[test]
fn provider_reuse_preserves_snapshot_fingerprints_and_resolution_bytes() {
    rust_reuse_preserves_identity();
    go_reuse_preserves_identity();
}

/// The Rust entry points agree on what they publish and on what they refuse.
fn rust_success_and_refusal_match() {
    let fixture = RustFixture::shared(ResolutionLimits::default());
    for target in [fixture.library, fixture.binary()] {
        let convenience = fixture
            .project
            .snapshot_resolution(target)
            .unwrap_or_else(|error| panic!("the convenience entry point should snapshot: {error}"));
        let mut provider = fixture.provider(ResolutionLimits::default());
        let supplied = fixture
            .project
            .snapshot_resolution_with_provider(&mut provider, target)
            .unwrap_or_else(|error| panic!("the provider entry point should snapshot: {error}"));
        assert_eq!(
            rust_claim(&supplied),
            rust_claim(&convenience),
            "the provider entry point publishes the convenience entry point's answer"
        );
    }

    let malformed = RustFixture::of(PARTIALLY_MALFORMED_REPOSITORY, ResolutionLimits::default());
    let expected = malformed
        .project
        .snapshot_resolution(malformed.library)
        .map(|_| Box::from("snapshotted"))
        .unwrap_or_else(|error| render(&error));
    let mut provider = malformed.provider(ResolutionLimits::default());
    let supplied = malformed
        .project
        .snapshot_resolution_with_provider(&mut provider, malformed.library)
        .map(|_| Box::from("snapshotted"))
        .unwrap_or_else(|error| render(&error));
    assert!(
        expected.contains("is not valid Rust"),
        "the malformed fixture should be refused for its parse, not for something else: {expected}"
    );
    assert_eq!(
        supplied, expected,
        "both entry points refuse a malformed closure with the same typed message"
    );
}

/// The Go entry points agree on what they refuse.
///
/// The success half is not stated here, because
/// [`go_reuse_preserves_identity`] already compares a provider-served snapshot
/// with a convenience one over the same repository, byte for byte. The refusal
/// is the half nothing asserted: the Rust seam states both, and a Go seam that
/// flattened a malformed package's typed refusal on one entry point and not the
/// other would have passed every claim in this file.
fn go_refusal_matches() {
    let malformed = GoFixture::of(
        PARTIALLY_MALFORMED_GO_REPOSITORY,
        GoResolutionLimits::default(),
    );
    let expected = malformed
        .project
        .snapshot_resolution()
        .map(|_| Box::from("snapshotted"))
        .unwrap_or_else(|error| render(&error));
    let mut provider = malformed.provider(GoResolutionLimits::default());
    let supplied = malformed
        .project
        .snapshot_resolution_with_provider(&mut provider)
        .map(|_| Box::from("snapshotted"))
        .unwrap_or_else(|error| render(&error));
    assert!(
        expected.contains("IncompleteSource"),
        "the malformed fixture should be refused for the source the grammar could not read, \
         not for something else: {expected}"
    );
    assert_eq!(
        supplied, expected,
        "both Go entry points refuse a malformed package with the same typed message"
    );
}

/// A second snapshot served entirely from a provider's held records publishes
/// exactly what a first, reading snapshot publishes.
fn rust_reuse_preserves_identity() {
    let fixture = RustFixture::shared(ResolutionLimits::default());
    let mut shared = fixture.provider(ResolutionLimits::default());

    let first = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.binary())
        .unwrap_or_else(|error| panic!("the first snapshot should succeed: {error}"));
    assert_eq!(
        &*shared.admitted_paths(),
        [
            Arc::<str>::from("src/lib.rs"),
            Arc::from("src/main.rs"),
            Arc::from("src/shared.rs")
        ],
        "the binary's resolution closure admitted every physical source once"
    );

    let reused = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.library)
        .unwrap_or_else(|error| panic!("the reusing snapshot should succeed: {error}"));
    let fresh = fixture
        .project
        .snapshot_resolution(fixture.library)
        .unwrap_or_else(|error| panic!("the convenience snapshot should succeed: {error}"));

    assert_eq!(
        rust_claim(&reused),
        rust_claim(&fresh),
        "a snapshot served from held records publishes the bytes a reading snapshot does"
    );
    assert_ne!(
        first.fingerprint(),
        reused.fingerprint(),
        "two different targets still publish two identities"
    );
}

/// The Go half of the same claim: a second snapshot over the same project,
/// served from held records, is byte-identical.
fn go_reuse_preserves_identity() {
    let fixture = GoFixture::of(GO_REPOSITORY, GoResolutionLimits::default());
    let mut shared = fixture.provider(GoResolutionLimits::default());

    let first = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared)
        .unwrap_or_else(|error| panic!("the first snapshot should succeed: {error}"));
    assert_eq!(
        &*shared.admitted_paths(),
        [
            Arc::<str>::from("app/helper.go"),
            Arc::from("app/service.go")
        ],
        "the package walk admitted every physical source once"
    );

    let reused = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared)
        .unwrap_or_else(|error| panic!("the reusing snapshot should succeed: {error}"));
    let fresh = fixture
        .project
        .snapshot_resolution()
        .unwrap_or_else(|error| panic!("the convenience snapshot should succeed: {error}"));

    assert_eq!(
        go_claim(&reused),
        go_claim(&first),
        "a second snapshot served from one provider's held records publishes the bytes that \
         provider's first, reading snapshot published"
    );
    assert_eq!(
        go_claim(&reused),
        go_claim(&fresh),
        "a Go snapshot served from held records publishes the bytes a reading snapshot does"
    );
}

/// Everything one Rust snapshot publishes, as comparable text.
///
/// The two differences from its Go twin are the resolver it asks and how a unit
/// is spelled. Everything else is [`snapshot_claim`]'s, because a claim written
/// twice is two places for a whole-answer comparison to quietly stop reading a
/// field.
fn rust_claim(snapshot: &RustResolutionSnapshot) -> SnapshotClaim {
    let resolution: RustTargetResolution = RustResolver::resolve_syntactic(snapshot)
        .unwrap_or_else(|error| panic!("the snapshot should resolve: {error}"));
    snapshot_claim(
        &snapshot.fingerprint(),
        snapshot
            .units()
            .iter()
            .map(|unit| format!("{}@{}", unit.name(), unit.manifest_path()).into_boxed_str())
            .collect(),
        snapshot
            .sources()
            .iter()
            .map(|source| source_claim(source.path(), &source.digest(), source.text()))
            .collect(),
        resolution.report(),
    )
}

/// Everything one Go snapshot publishes, as comparable text.
///
/// Its own resolver and its own unit spelling, and nothing else. See
/// [`rust_claim`].
fn go_claim(snapshot: &GoResolutionSnapshot) -> SnapshotClaim {
    let resolution: GoProjectResolution = GoResolver::resolve_syntactic(snapshot)
        .unwrap_or_else(|error| panic!("the snapshot should resolve: {error}"));
    snapshot_claim(
        &snapshot.fingerprint(),
        snapshot
            .units()
            .iter()
            .map(|unit| format!("{}@{:?}", unit.import_path(), unit.context()).into_boxed_str())
            .collect(),
        snapshot
            .sources()
            .iter()
            .map(|source| source_claim(source.path(), &source.digest(), source.text()))
            .collect(),
        resolution.report(),
    )
}

/// One snapshot's whole published answer, rendered the one way both languages
/// are compared.
fn snapshot_claim<Fingerprint: std::fmt::Debug>(
    fingerprint: &Fingerprint,
    units: Box<[Box<str>]>,
    sources: Box<[SourceClaim]>,
    report: &pedant_types::ResolutionReport,
) -> SnapshotClaim {
    SnapshotClaim {
        fingerprint: render(fingerprint),
        units,
        sources,
        report: serialized(report),
    }
}

/// One retained source's whole published answer, rendered the same way.
fn source_claim<Digest: std::fmt::Debug>(path: &str, digest: &Digest, text: &str) -> SourceClaim {
    SourceClaim {
        path: Box::from(path),
        digest: render(digest),
        text: Box::from(text),
    }
}

/// One published report, as the exact bytes a consumer would receive.
fn serialized(report: &pedant_types::ResolutionReport) -> Box<str> {
    serde_json::to_string(report)
        .unwrap_or_else(|error| panic!("a published report should serialize: {error}"))
        .into_boxed_str()
}

/// Any published value, as comparable text.
fn render<T: std::fmt::Debug>(value: &T) -> Box<str> {
    format!("{value:?}").into_boxed_str()
}
