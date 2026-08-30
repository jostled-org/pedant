//! Contract tests for every `pedant-types` serialized shape.
//!
//! This root owns the wire format: capability findings, profiles, diffs,
//! attestations, and the validated resolution report. It stays the crate's only
//! integration executable — every case module reaches it through a `#[path]`
//! support module, which Cargo links into this same binary instead of a second
//! one.
//!
//! The `#[path]` is required rather than stylistic: default resolution would
//! place the files in `tests/serialization/`, which pedant's
//! `conflicting-module-root` rule rejects beside `serialization.rs`. A sibling
//! directory satisfies both rules.
//!
//! The resolution predicates below stay at this root, unlike every other case:
//! a plan step selects them by bare name and the owner-registration tables list
//! them unqualified, so a module path would rename them.

/// The one valid resolution report every resolution case starts from.
#[path = "serialization_support/resolution_fixture.rs"]
mod resolution_fixture;

/// The one-of-each builder the handle and capacity cases need.
#[path = "serialization_support/resolution_seed.rs"]
mod resolution_seed;

/// What a malformed wire case is, and how one reaches the validator.
#[path = "serialization_support/resolution_case_model.rs"]
mod resolution_case_model;

/// Every malformed wire report and its exact refusal.
#[path = "serialization_support/resolution_cases.rs"]
mod resolution_cases;

/// The published Rust report's exact bytes.
#[path = "serialization_support/resolution_wire_bytes.rs"]
mod resolution_wire_bytes;

/// Every malformed report a writer can state, and the refusal `finish` owes.
#[path = "serialization_support/resolution_builder_cases.rs"]
mod resolution_builder_cases;

/// What each resolution case proves.
#[path = "serialization_support/resolution_asserts.rs"]
mod resolution_asserts;

/// External type-identity, ownership, and transparent-ID wire proofs.
#[path = "serialization_support/resolution_identity.rs"]
mod resolution_identity;

/// Caller-bounded decoding and the report map's serde field contract.
#[path = "serialization_support/resolution_decode_limits.rs"]
mod resolution_decode_limits;

/// A hostile serde size hint cannot influence bounded report allocation.
#[path = "serialization_support/resolution_hostile_hint.rs"]
mod resolution_hostile_hint;

/// The one capability finding the non-resolution cases vary.
#[path = "serialization_support/finding_fixture.rs"]
mod finding_fixture;

/// Every closed enum's text spelling, in both directions.
#[path = "serialization_support/enum_spelling_cases.rs"]
mod enum_spelling_cases;

/// What a capability finding's optional fields do on the wire.
#[path = "serialization_support/finding_cases.rs"]
mod finding_cases;

/// What a profile reports over its findings, and what a diff of two reports.
#[path = "serialization_support/profile_cases.rs"]
mod profile_cases;

/// The shared capability-analysis envelope, its decode boundary, and its merge.
#[path = "serialization_support/capability_analysis_cases.rs"]
mod capability_analysis_cases;

/// The attestation envelope and its completeness record.
#[path = "serialization_support/attestation_cases.rs"]
mod attestation_cases;

/// The legacy `build_script` boolean and the enum that replaced it.
#[path = "serialization_support/legacy_decode_cases.rs"]
mod legacy_decode_cases;

/// The generic source-provider contract, its request path, and its record.
#[path = "serialization_support/source_provider_cases.rs"]
mod source_provider_cases;

// --- Resolution contract: Invariants 1-4 and the Rust language spelling ---

/// Two builders both issue local index zero, so a handle passed to the wrong
/// builder names a valid local record. Every handle-consuming operation must
/// refuse it on brand identity and leave the receiving builder untouched.
#[test]
fn resolution_builder_rejects_every_same_index_foreign_handle_without_mutation() {
    use pedant_types::ResolutionReportLimits;

    let mut local = resolution_seed::seeded_builder(ResolutionReportLimits::default());
    let foreign = resolution_seed::seeded_builder(ResolutionReportLimits::default());

    resolution_asserts::foreign_handles_are_refused(&mut local, &foreign);
    resolution_asserts::seeded_builder_still_finishes(
        local,
        "no rejected operation mutated the builder",
    );
}

#[test]
fn resolution_handle_and_identifier_kinds_remain_nominally_distinct() {
    resolution_identity::assert_distinct_identity_families();
}

#[test]
fn resolution_identifiers_keep_the_transparent_u32_wire_shape() {
    resolution_identity::assert_transparent_identifier_wire_shape();
}

#[test]
fn resolution_report_decode_limits_bound_every_top_level_collection() {
    resolution_decode_limits::assert_each_collection_is_bounded();
}

#[test]
fn resolution_report_decode_limits_preserve_default_and_valid_behavior() {
    resolution_decode_limits::assert_default_and_configured_valid_decoding();
}

#[test]
fn resolution_report_bounded_decode_preserves_map_field_errors() {
    resolution_decode_limits::assert_map_field_errors();
}

#[test]
fn resolution_report_bounded_decode_ignores_hostile_sequence_size_hints() {
    resolution_hostile_hint::assert_hostile_size_hint_is_not_observed();
}

/// The one insertion check answers both the configured capacity and the fixed
/// width of the report's identifiers.
#[test]
fn resolution_builder_enforces_configured_and_id_ceiling_capacities_without_mutation() {
    use pedant_types::ResolutionReportLimits;

    let mut seeded = resolution_seed::seeded_builder(ResolutionReportLimits {
        max_units: 1,
        max_definitions: 1,
        max_references: 1,
    });
    resolution_asserts::configured_capacity_is_enforced(&mut seeded);
    resolution_asserts::seeded_builder_still_finishes(
        seeded,
        "no rejected insertion mutated the builder",
    );
    resolution_asserts::id_ceiling_is_enforced();
}

/// Both construction boundaries — `finish` and custom deserialization — reach
/// the same validator, and each malformed family produces its exact refusal.
///
/// The wire table carries every family; the builder table carries every family
/// a writer can state, and the two are held together by label so neither
/// boundary can grow a rule the other never proves. A rule the validator
/// applies to more than one collection is stated once per call site, so no
/// call site can be deleted while the table stays green.
#[test]
fn resolution_report_validation_rejects_every_malformed_invariant_family() {
    let wire = resolution_cases::malformed_cases();
    let builder = resolution_builder_cases::builder_cases();
    resolution_asserts::every_case_produces_its_refusal(&wire, 32, "malformed family");
    resolution_asserts::every_builder_case_produces_its_refusal(&builder, 13, "malformed family");
    resolution_asserts::boundaries_cover_the_same_families(&wire, &builder);
    resolution_asserts::one_record_per_reference();
    resolution_asserts::valid_report_round_trips();
}

/// Unit containment, cross-unit candidates, and every legal and illegal record
/// shape: the legal ones accepted at both boundaries, the illegal ones refused
/// identically by `finish` and by deserialization.
#[test]
fn resolution_report_enforces_unit_parent_candidate_and_certainty_rules() {
    use pedant_types::ResolutionGap;

    resolution_asserts::unit_containment_and_cross_unit_candidate();
    resolution_asserts::possible_candidates_are_accepted(&[]);
    resolution_asserts::possible_candidates_are_accepted(&[ResolutionGap::ConditionalCompilation]);
    let wire = resolution_cases::certainty_cases();
    let builder = resolution_builder_cases::builder_certainty_cases();
    resolution_asserts::every_case_produces_its_refusal(&wire, 4, "illegal record shape");
    resolution_asserts::every_builder_case_produces_its_refusal(
        &builder,
        4,
        "illegal record shape",
    );
    resolution_asserts::boundaries_cover_the_same_families(&wire, &builder);
}

/// Rust is a shared language with the wire spelling `rust`, and every emitted
/// resolution record carries it.
#[test]
fn rust_language_serializes_as_rust_and_resolution_records_use_it() {
    resolution_asserts::every_record_spells_its_language_rust();
}

/// The shared report vocabulary is one closed set for every language it
/// carries, so the Go definition and reference kinds have exact wire spellings
/// here and the published Rust ones keep theirs in place.
#[test]
fn go_resolution_vocabulary_has_exact_wire_spellings() {
    enum_spelling_cases::assert_resolution_vocabulary_spellings();
}

/// Widening that vocabulary changes no byte of a report a Rust resolver
/// already published.
#[test]
fn legacy_rust_resolution_wire_bytes_stay_exact() {
    resolution_wire_bytes::assert_legacy_rust_report_bytes_stay_exact();
}
