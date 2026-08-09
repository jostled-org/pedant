//! What a profile reports over its findings, and what a diff of two reports.
//!
//! A profile holds findings, not capabilities: the capability list and the diff
//! are derived, and both are what a caller acts on. These cases fix the
//! derivation — deduplicated, in variant order, and the four diff fields.

use pedant_types::{Capability, CapabilityDiff, CapabilityProfile};

use crate::finding_fixture::sample_finding;

/// Two network findings and one file read, so deduplication has work to do.
fn mixed_profile() -> CapabilityProfile {
    CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
            sample_finding(Capability::Network, "c.rs", 3),
        ]
        .into_boxed_slice(),
    }
}

/// A profile holding exactly one finding for `capability`.
fn single_profile(capability: Capability, file: &str, line: usize) -> CapabilityProfile {
    CapabilityProfile {
        findings: vec![sample_finding(capability, file, line)].into_boxed_slice(),
    }
}

#[test]
fn profile_capabilities_deduplicates_and_sorts() {
    let caps = mixed_profile().capabilities();
    assert_eq!(
        caps,
        vec![Capability::Network, Capability::FileRead].into_boxed_slice()
    );
}

#[test]
fn profile_findings_for_filters() {
    let profile = mixed_profile();
    assert_eq!(profile.findings_for(Capability::Network).count(), 2);
    assert_eq!(profile.findings_for(Capability::FileRead).count(), 1);
    assert_eq!(profile.findings_for(Capability::Crypto).count(), 0);
}

#[test]
fn empty_profile_round_trip() {
    let profile = CapabilityProfile::default();
    let json = serde_json::to_string(&profile).unwrap();
    let back: CapabilityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
    assert!(back.capabilities().is_empty());
}

#[test]
fn diff_overlapping_profiles() {
    let old = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::FileRead, "b.rs", 2),
        ]
        .into_boxed_slice(),
    };
    let new = CapabilityProfile {
        findings: vec![
            sample_finding(Capability::Network, "a.rs", 1),
            sample_finding(Capability::Crypto, "c.rs", 3),
        ]
        .into_boxed_slice(),
    };
    let diff = CapabilityDiff::compute(&old, &new);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].capability, Capability::Crypto);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].capability, Capability::FileRead);
    assert_eq!(&*diff.new_capabilities, &[Capability::Crypto]);
    assert_eq!(&*diff.dropped_capabilities, &[Capability::FileRead]);
}

#[test]
fn diff_disjoint_profiles() {
    let old = single_profile(Capability::Network, "a.rs", 1);
    let new = single_profile(Capability::FileWrite, "b.rs", 2);
    let diff = CapabilityDiff::compute(&old, &new);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(&*diff.new_capabilities, &[Capability::FileWrite]);
    assert_eq!(&*diff.dropped_capabilities, &[Capability::Network]);
}

#[test]
fn diff_empty_profiles() {
    let empty = CapabilityProfile::default();
    let diff = CapabilityDiff::compute(&empty, &empty);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.new_capabilities.is_empty());
    assert!(diff.dropped_capabilities.is_empty());
}

#[test]
fn diff_round_trip() {
    let old = single_profile(Capability::Network, "a.rs", 1);
    let new = single_profile(Capability::Crypto, "b.rs", 2);
    let diff = CapabilityDiff::compute(&old, &new);
    let json = serde_json::to_string(&diff).unwrap();
    let back: CapabilityDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, back);
}
