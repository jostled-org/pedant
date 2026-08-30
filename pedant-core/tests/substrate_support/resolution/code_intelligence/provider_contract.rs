//! The provider-aware snapshot entry points, as a boundary rather than as a
//! behavior.
//!
//! Three claims, and each fails for a different edit. The entry points are
//! generic over the contract, so a provider written outside this crate — with
//! an error type this crate has never seen — drives a real snapshot. They are
//! root-neutral, so every request that crosses the seam is a normalized
//! repository-relative path and never an absolute one. And this crate names no
//! consumer of itself, so the contract it compiles against cannot be the
//! navigation product's.

use pedant_core::resolution::go::{GoFileInventory, GoResolutionLimits, GoSourceFault};
use pedant_core::resolution::rust::{ResolutionLimits, RustFileInventory, RustSourceFault};
use pedant_types::{SourcePath, SourceProvider};

use super::caller::RecordingProvider;
use super::go_fixture::{GO_REPOSITORY, GoFixture};
use super::rust_fixture::{PARTIALLY_MALFORMED_REPOSITORY, RustFixture};
use crate::resolution::manifest_reader::{assert_requires_none, manifest_table};

/// This crate's manifest, which the boundary claim reads.
const MANIFEST: &str = "pedant-core/Cargo.toml";

/// Every workspace member that sits above this crate. None may appear in the
/// manifest above.
const CONSUMERS: &[&str] = &["pedant-snippet", "pedant-mcp", "pedant-lang"];

/// 3.T2 (Invariants 3, 15): the Rust and Go resolution entry points accept the
/// published provider contract, hand it normalized repository-relative paths
/// only, and depend on no consumer of this crate.
#[test]
fn provider_aware_snapshot_entry_points_are_generic_and_root_neutral() {
    a_caller_written_rust_provider_drives_a_snapshot();
    a_caller_written_go_provider_drives_a_snapshot();
    a_caller_written_refusal_converts_into_the_owner_vocabulary();
    this_crate_names_no_consumer();
}

/// A refusal the caller's provider states names the caller's own request and
/// converts into the fault the owning seam publishes.
///
/// This is the half the successful journeys above cannot show: the entry
/// points bound their provider's error by conversion, so an error type the
/// crate has never seen still reaches a typed refusal rather than being
/// flattened into a message.
fn a_caller_written_refusal_converts_into_the_owner_vocabulary() {
    let fixture = RustFixture::of(PARTIALLY_MALFORMED_REPOSITORY, ResolutionLimits::default());
    let mut provider = RecordingProvider::new(fixture.provider(ResolutionLimits::default()));
    let request = SourcePath::new("src/bad.rs").expect("the fixture path is normalized");
    let refused = SourceProvider::<RustFileInventory>::source(&mut provider, request)
        .expect_err("the malformed module states no inventory");
    assert_eq!(
        refused.request().path(),
        "src/bad.rs",
        "the caller's refusal names the caller's own request"
    );
    assert!(
        matches!(
            RustSourceFault::from(refused),
            RustSourceFault::Unparsed { .. }
        ),
        "the caller's fault converts into the Rust owner's typed vocabulary"
    );

    let go = GoFixture::of(GO_REPOSITORY, GoResolutionLimits::default());
    let mut go_provider = RecordingProvider::new(go.provider(GoResolutionLimits::default()));
    let absent = SourcePath::new("app/absent.go").expect("the fixture path is normalized");
    let refused = SourceProvider::<GoFileInventory>::source(&mut go_provider, absent)
        .expect_err("the fixture holds no such source");
    assert_eq!(
        refused.request().path(),
        "app/absent.go",
        "the caller's refusal names the caller's own request"
    );
    assert!(
        matches!(
            GoSourceFault::from(refused),
            GoSourceFault::PathRead { .. } | GoSourceFault::Unreadable(_)
        ),
        "the caller's fault converts into the Go owner's typed vocabulary"
    );
}

/// A provider declared in this test, with its own error type, snapshots a real
/// Cargo target — and every path it was handed is repository-relative.
fn a_caller_written_rust_provider_drives_a_snapshot() {
    let fixture = RustFixture::shared(ResolutionLimits::default());
    let mut provider = RecordingProvider::new(fixture.provider(ResolutionLimits::default()));

    let snapshot = fixture
        .project
        .snapshot_resolution_with_provider(&mut provider, fixture.library)
        .unwrap_or_else(|error| panic!("the caller's provider should serve a snapshot: {error}"));

    let reached: Box<[&str]> = snapshot
        .sources()
        .iter()
        .map(|source| source.path())
        .collect();
    assert_eq!(
        &*reached,
        ["src/lib.rs", "src/shared.rs"],
        "the caller's provider served the library's whole closure"
    );
    assert!(
        !snapshot.sources()[1].ir().structure_sites.is_empty(),
        "a served source carries the inventory its language owner extracted"
    );

    let requested = provider.requested();
    assert_eq!(
        requested.len(),
        2,
        "the loader asked for each reached source once: {requested:?}"
    );
    assert_normalized(&requested);
}

/// The same claim for the Go entry point.
fn a_caller_written_go_provider_drives_a_snapshot() {
    let fixture = GoFixture::of(GO_REPOSITORY, GoResolutionLimits::default());
    let mut provider = RecordingProvider::new(fixture.provider(GoResolutionLimits::default()));

    let snapshot = fixture
        .project
        .snapshot_resolution_with_provider(&mut provider)
        .unwrap_or_else(|error| panic!("the caller's provider should serve a snapshot: {error}"));

    let reached: Box<[&str]> = snapshot
        .sources()
        .iter()
        .map(|source| source.path())
        .collect();
    assert_eq!(
        &*reached,
        ["app/helper.go", "app/service.go"],
        "the caller's provider served every source the package walk admitted"
    );
    assert_eq!(
        snapshot.sources()[1].facts().package_name(),
        Some("app"),
        "a served source carries the fact inventory its language owner extracted"
    );

    let requested = provider.requested();
    assert_eq!(
        requested.len(),
        2,
        "the walk asked for each admitted source once: {requested:?}"
    );
    assert_normalized(&requested);
}

/// No request that crossed the seam named a root.
///
/// The request type refuses an absolute or climbing path at construction, so
/// the point here is that the loaders build their requests from that type at
/// all: a seam that had widened to an absolute path would show it in this list.
fn assert_normalized(requested: &[Box<str>]) {
    for path in requested {
        assert!(
            !path.starts_with('/') && !path.contains("..") && !path.contains('\\'),
            "{path} is not a normalized repository-relative request"
        );
        assert!(
            !path.contains(char::is_whitespace),
            "{path} carries no rendered absolute location"
        );
    }
}

/// The provider seam sits beneath the navigation product, so this crate names
/// none of the members that consume it.
///
/// The reading itself belongs to `manifest_reader`, which owns the one parse of
/// the three dependency tables and the floor that keeps an absence claim from
/// passing over a manifest it found empty. The registry case states the same
/// claim from the other side — that neither other product declares an edge on
/// the navigation crate — and a second copy of the reading is a second place for
/// one of them to stop reading a dependency kind.
///
/// What stays here is the subject: the manifest read must be this crate's own.
fn this_crate_names_no_consumer() {
    assert_requires_none(MANIFEST, CONSUMERS);
    let manifest = manifest_table(MANIFEST);
    assert_eq!(
        manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str),
        Some("pedant-core"),
        "the manifest read is this crate's own"
    );
}
