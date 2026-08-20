//! Tier 2: promotion bound to a verified rust-analyzer snapshot.
//!
//! Every case below loads a real semantic database beside the snapshot it must
//! answer for. The handshake is proved by refusal, the promotion by the records
//! that change — including the dispatch sets it must leave possible, the macro
//! it must not expand, and the UTF-8 byte columns both ends of its join must
//! count in — and the unit qualification by two units that state the same name
//! at the same coordinates.

#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::ResolutionProbe;
#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::rust::RustResolutionError;
#[cfg(feature = "resolution-test-support")]
use pedant_core::resolution::rust::{CargoTargetKind, RustResolver};
use pedant_types::ResolutionTier;

use crate::resolution::fixture;
use crate::resolution::report_views::{
    render_definitions, render_records, render_references, render_targets, render_units,
};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::semantic_asserts::HANDSHAKE_CASES;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::semantic_expectations::CORPUS_SEMANTIC_SETUPS;
use crate::resolution::semantic_expectations::{
    CORPUS_DEFINITIONS, CORPUS_REFERENCES, CORPUS_UNITS, CROSS_UNIT_TARGETS, SEMANTIC_RECORDS,
    SYNTACTIC_RECORDS,
};
use crate::resolution::semantic_fixtures::{CROSS_UNIT_NAMES, SEMANTIC_CORPUS};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::semantic_pairing::library_snapshot;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::semantic_pairing::load_context;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::semantic_pairing::matched_pairing;
use crate::resolution::semantic_pairing::{resolve_semantic, resolve_syntactic};
#[cfg(feature = "resolution-test-support")]
use crate::resolution::syntactic_probe::observed;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::unit_fixtures::SEMANTIC_SHARED_SOURCE;
#[cfg(feature = "resolution-test-support")]
use crate::resolution::views::target_id;

#[test]
fn semantic_resolution_changes_only_candidates_gaps_and_tier() {
    let tmp = fixture::build_repository(SEMANTIC_CORPUS, false);
    let clean_snapshot = crate::resolution::semantic_pairing::library_snapshot(&tmp);
    assert!(
        clean_snapshot.warnings().is_empty(),
        "a library-only module layout emits no semantic-layout warning"
    );
    let syntactic = resolve_syntactic(&tmp);
    let semantic = resolve_semantic(&tmp);
    let (first, second) = (syntactic.report(), semantic.report());

    assert_eq!(
        render_units(first),
        CORPUS_UNITS,
        "Tier 1 states the corpus units"
    );
    assert_eq!(
        render_units(second),
        CORPUS_UNITS,
        "Tier 2 states the same units"
    );
    assert_eq!(
        render_definitions(first),
        CORPUS_DEFINITIONS,
        "Tier 1 states the corpus definitions"
    );
    assert_eq!(
        render_definitions(second),
        CORPUS_DEFINITIONS,
        "Tier 2 states the same definitions"
    );
    assert_eq!(
        render_references(first),
        CORPUS_REFERENCES,
        "Tier 1 states the corpus references"
    );
    assert_eq!(
        render_references(second),
        CORPUS_REFERENCES,
        "Tier 2 states the same references"
    );

    assert_eq!(
        first.tier(),
        ResolutionTier::Syntactic,
        "the parse-only report names its tier"
    );
    assert_eq!(
        second.tier(),
        ResolutionTier::Semantic,
        "the promoted report names its tier"
    );
    assert_eq!(
        render_records(first),
        SYNTACTIC_RECORDS,
        "Tier 1 leaves every parameter receiver's method call dynamic and \
         expands no macro"
    );
    assert_eq!(
        render_records(second),
        SEMANTIC_RECORDS,
        "Tier 2 promotes the one concrete definition, keeps each enumerated \
         dispatch set possible with its gap, leaves the macro unexpanded, and \
         joins a non-ASCII line at the UTF-8 byte column both sides count"
    );
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn semantic_resolution_refuses_shared_physical_source_before_query() {
    let probe = ResolutionProbe::install();
    let tmp = fixture::build_repository(SEMANTIC_SHARED_SOURCE, false);
    let project = fixture::load_default(&tmp);
    let binary = target_id(&project, "app", CargoTargetKind::Binary, "tool");
    let snapshot = project
        .snapshot_resolution(binary)
        .expect("the shared-source binary snapshots completely");
    let context = load_context(&fixture::repository_root(&tmp));

    let error = RustResolver::resolve_semantic(&snapshot, &context)
        .expect_err("Tier 2 cannot distinguish both instances of one physical source");
    let warning = match error {
        RustResolutionError::SemanticSharedSourceMismatch { warning } => warning,
        other => panic!("the shared layout returned the wrong typed mismatch: {other:?}"),
    };
    assert_eq!(warning.path(), "src/common.rs");
    assert_eq!(
        warning
            .unit_keys()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>(),
        ["Cargo.toml#bin#tool", "Cargo.toml#lib#app"]
    );
    assert!(
        probe.semantic_queries().is_empty(),
        "the mismatch precedes queries"
    );
    assert!(
        probe.promotions().is_empty(),
        "the mismatch precedes promotion"
    );
}

#[test]
fn semantic_resolution_returns_unit_qualified_definition_targets() {
    let tmp = fixture::build_repository(CROSS_UNIT_NAMES, false);
    let resolution = resolve_semantic(&tmp);
    assert_eq!(
        render_targets(resolution.report()),
        CROSS_UNIT_TARGETS,
        "every promoted candidate names the unit whose definition it is, so a \
         name or a coordinate shared by two units cannot select the wrong one"
    );
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn semantic_handshake_rejects_every_identity_mismatch_before_query() {
    for case in HANDSHAKE_CASES {
        let probe = ResolutionProbe::install();
        let tmp = fixture::build_repository(case.files, false);
        let pairing = (case.pairing)(&tmp);
        let error = RustResolver::resolve_semantic(&pairing.snapshot, &pairing.context)
            .err()
            .unwrap_or_else(|| panic!("{}: the pairing was accepted", case.label));

        assert!(
            matches!(error, RustResolutionError::SemanticContextMismatch { .. }),
            "{}: unexpected error {error:?}",
            case.label
        );
        let reason = error.to_string();
        assert!(
            reason.contains(case.expected),
            "{}: the refusal should name {:?}, got {reason:?}",
            case.label,
            case.expected
        );
        assert!(
            probe.semantic_queries().is_empty(),
            "{}: the handshake must refuse before any query",
            case.label
        );
        assert!(
            probe.promotions().is_empty(),
            "{}: a refused pairing promotes nothing",
            case.label
        );
    }

    let probe = ResolutionProbe::install();
    let tmp = fixture::build_repository(SEMANTIC_CORPUS, false);
    let pairing = matched_pairing(&tmp);
    RustResolver::resolve_semantic(&pairing.snapshot, &pairing.context)
        .expect("a matched pairing resolves");
    assert!(
        !probe.semantic_queries().is_empty(),
        "the zero-query assertions above are not vacuous: a matched pairing queries"
    );
    assert!(
        !probe.promotions().is_empty(),
        "the zero-promotion assertions above are not vacuous: a matched pairing promotes"
    );
}

#[cfg(feature = "resolution-test-support")]
#[test]
fn semantic_resolution_reuses_verified_workspace_and_cached_file_setup() {
    let probe = ResolutionProbe::install();
    let tmp = fixture::build_repository(SEMANTIC_CORPUS, false);
    let pairing = matched_pairing(&tmp);
    let first = RustResolver::resolve_semantic(&pairing.snapshot, &pairing.context)
        .expect("the first resolution verifies the snapshot");
    let second = RustResolver::resolve_semantic(&pairing.snapshot, &pairing.context)
        .expect("the second resolution verifies the same snapshot");

    assert_eq!(
        render_records(first.report()),
        SEMANTIC_RECORDS,
        "the first resolution promotes what the database proves"
    );
    assert_eq!(
        render_records(second.report()),
        render_records(first.report()),
        "resolving the same verified snapshot twice answers the same"
    );
    assert_eq!(
        probe.semantic_workspace_loads(),
        1,
        "Tier 2 loads no second rust-analyzer workspace"
    );
    assert_eq!(
        observed(&probe.semantic_file_setups()),
        CORPUS_SEMANTIC_SETUPS,
        "each source is set up once and every later query reuses the cache"
    );
}

/// The corpus source after a body-only edit. The manifests, the module layout,
/// and every path are unchanged, so only the retained identity can tell the two
/// repository states apart.
#[cfg(feature = "resolution-test-support")]
const REWRITTEN_ALPHA: &str = "pub struct Widget;\n\nimpl Widget {\n    /* \u{fc} */ pub fn render(&self) {\n        let _ = 1;\n    }\n}\n";

/// The handshake compares the value the snapshot was completed with, so a
/// source-only edit refuses before any query or promotion runs.
///
/// The positive counters come first: a zero-counter assertion that never had a
/// non-zero counterpart proves only that nothing ran.
#[cfg(all(feature = "semantic", feature = "resolution-test-support"))]
#[test]
fn semantic_handshake_reuses_retained_snapshot_fingerprint() {
    let tmp = fixture::build_repository(SEMANTIC_CORPUS, false);
    let context = load_context(&fixture::repository_root(&tmp));

    let matched = ResolutionProbe::install();
    let snapshot = library_snapshot(&tmp);
    let resolution = RustResolver::resolve_semantic(&snapshot, &context)
        .expect("the database describes this exact snapshot");
    assert_eq!(
        snapshot.fingerprint(),
        resolution.snapshot_fingerprint(),
        "the promoted result retains the identity the handshake verified"
    );
    assert!(
        !matched.semantic_queries().is_empty(),
        "a matching identity reaches the database"
    );
    assert!(
        !matched.promotions().is_empty(),
        "a matching identity promotes"
    );
    drop(matched);

    fixture::write_file(tmp.path(), "repo/src/alpha.rs", REWRITTEN_ALPHA.as_bytes());
    let refused = ResolutionProbe::install();
    let edited = library_snapshot(&tmp);
    assert_ne!(
        edited.fingerprint(),
        snapshot.fingerprint(),
        "a source-only edit states another repository state"
    );

    let error = RustResolver::resolve_semantic(&edited, &context)
        .expect_err("the database no longer describes this snapshot");
    assert!(
        matches!(error, RustResolutionError::SemanticContextMismatch { .. }),
        "unexpected error {error:?}"
    );
    assert_eq!(
        refused.semantic_queries().len(),
        0,
        "the refusal precedes every query"
    );
    assert_eq!(
        refused.promotions().len(),
        0,
        "the refusal precedes every promotion"
    );
}
