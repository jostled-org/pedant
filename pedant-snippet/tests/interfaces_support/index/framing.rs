//! Where one claim input ends, how many there are, and in which order.
//!
//! The tag byte and the payload are only half of what a digest has to hold. Two
//! fields concatenated without a boundary are one field, two records written in
//! the other order are the same bytes as the first order, and an index claim
//! and a state claim over equal inputs would be readable as each other. None of
//! those is visible from a repository fixture, and every one of them would let
//! two different repositories answer under one identity.

use std::sync::Arc;

use pedant_snippet::{AdmittedPathKind, IssueScope, RevisionClaim, RevisionClaimInput};

use super::claims::{assert_distinct_digests, sealed};

/// The framing that separates one claim input from the next holds.
pub fn claim_framing_survives_every_boundary_and_order() {
    field_boundaries_reach_the_claim();
    order_and_cardinality_reach_the_claim();
    the_two_seals_are_separate_domains();
}

/// Where one field ends and the next begins is part of the claim.
///
/// Without a length prefix a path `"ab"` followed by `"c"` and a path `"a"`
/// followed by `"bc"` are the same bytes, so two repositories holding different
/// files would state one identity. Each pair below holds the concatenation
/// constant and moves only the boundary.
fn field_boundaries_reach_the_claim() {
    let split = |left: &'static str, right: &'static str| {
        sealed(&[
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: left,
            },
            RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: right,
            },
        ])
    };
    assert_ne!(
        split("ab", "c"),
        split("a", "bc"),
        "two admitted paths are two fields, not one concatenation"
    );

    // Those two are separated by the tag byte alone, because no ordinary path
    // carries one. The length is what holds when a payload does: one path that
    // spells two, separator included, is byte-for-byte two paths without it.
    // The separator is swept rather than spelled, so this row does not depend
    // on which tag the encoder assigns to an admitted path.
    let kind = AdmittedPathKind::Source.token();
    let two = split("a", "b");
    for byte in 0_u8..=32 {
        let separator = char::from(byte);
        let swallowed = format!("a{separator}{kind}{separator}b");
        assert_ne!(
            sealed(&[RevisionClaimInput::AdmittedPath {
                kind: AdmittedPathKind::Source,
                path: &swallowed,
            }]),
            two,
            "one path spelling two of them is not two paths, whatever separates them"
        );
    }

    assert_ne!(
        sealed(&[
            RevisionClaimInput::ProjectAuthority("ab"),
            RevisionClaimInput::ProjectUnit("c"),
        ]),
        sealed(&[
            RevisionClaimInput::ProjectAuthority("a"),
            RevisionClaimInput::ProjectUnit("bc"),
        ]),
        "a project key's authority and unit are two fields"
    );

    assert_ne!(
        sealed(&[
            RevisionClaimInput::IssueMessage("ab"),
            RevisionClaimInput::IssueMessage("c"),
        ]),
        sealed(&[
            RevisionClaimInput::IssueMessage("a"),
            RevisionClaimInput::IssueMessage("bc"),
        ]),
        "two issue messages are two fields"
    );
}

/// How many records a claim holds, and in which order, are part of it.
fn order_and_cardinality_reach_the_claim() {
    let record = |path: &'static str| RevisionClaimInput::AdmittedPath {
        kind: AdmittedPathKind::Source,
        path,
    };

    let none = sealed(&[]);
    let one = sealed(&[record("a")]);
    let two = sealed(&[record("a"), record("b")]);
    let repeated = sealed(&[record("a"), record("a")]);
    assert_distinct_digests(
        "record counts",
        &[
            ("zero", none.as_str()),
            ("one", one.as_str()),
            ("two", two.as_str()),
            ("the same record twice", repeated.as_str()),
        ],
    );

    assert_ne!(
        two,
        sealed(&[record("b"), record("a")]),
        "the order inputs are written in reaches the claim, which is why production sorts"
    );
    assert_eq!(
        one,
        sealed(&[record("a")]),
        "and equal inputs in equal order state equal bytes"
    );

    // The same statement one issue further up: a state claim over two issues
    // must depend on their order, because the sorted order production writes
    // them in is the only reason two equal repositories agree.
    let first = IssueScope::File {
        path: Arc::from("a"),
    };
    let second = IssueScope::File {
        path: Arc::from("b"),
    };
    let ordered = |left: &IssueScope, right: &IssueScope| {
        let mut claim = RevisionClaim::new();
        claim.write(RevisionClaimInput::IssueScope(left));
        claim.write(RevisionClaimInput::IssueScope(right));
        claim.seal_state().to_string()
    };
    assert_ne!(
        ordered(&first, &second),
        ordered(&second, &first),
        "two issues in the other order are a different state claim"
    );
}

/// An index claim and a state claim over the same inputs are different bytes.
fn the_two_seals_are_separate_domains() {
    let inputs = [RevisionClaimInput::AdmittedPath {
        kind: AdmittedPathKind::Source,
        path: "a",
    }];
    let mut index = RevisionClaim::new();
    let mut state = RevisionClaim::new();
    for input in inputs {
        index.write(input);
        state.write(input);
    }
    assert_ne!(
        index.seal_index().to_string(),
        state.seal_state().to_string(),
        "an index identity and a state identity cannot be read as each other"
    );
}
