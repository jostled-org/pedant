//! The one resolver ceiling, proved at its first excess for every reference
//! category that carries candidates.
//!
//! Candidate fan-out is the only lowerable resolution ceiling. Coordinates,
//! kinds, and the snapshot identity are validation claims a published wrapper
//! always makes, so lowering them is not a thing a caller can ask for.

use pedant_core::resolution::go::{GoResolutionError, GoResolutionLimits};

use crate::resolution::fixture::FixtureFile;
use crate::resolution::go::fixture::{resolve, resolve_refusal};
use crate::resolution::go::resolution_fixtures::{
    LIMIT_FUNCTION, LIMIT_METHOD, LIMIT_PACKAGE, LIMIT_VALUE,
};

/// One row: the corpus, the ceiling that refuses it, and the ceiling that
/// admits it.
struct Row {
    label: &'static str,
    files: &'static [FixtureFile],
    refused: u32,
    admitted: u32,
}

/// Every reference category that carries candidates.
///
/// A package reference names exactly one package, so its excess is the first
/// candidate; the other three are made two-candidate references by a
/// declaration each platform states.
const ROWS: &[Row] = &[
    Row {
        label: "package",
        files: LIMIT_PACKAGE,
        refused: 0,
        admitted: 1,
    },
    Row {
        label: "function",
        files: LIMIT_FUNCTION,
        refused: 1,
        admitted: 2,
    },
    Row {
        label: "value",
        files: LIMIT_VALUE,
        refused: 1,
        admitted: 2,
    },
    Row {
        label: "concrete method",
        files: LIMIT_METHOD,
        refused: 1,
        admitted: 2,
    },
];

/// 8.T2 (Invariant 5): the candidates-per-reference ceiling refuses at its
/// first excess and publishes no report.
#[test]
fn go_resolution_limits_refuse_every_first_excess() {
    for row in ROWS {
        let error = resolve_refusal(row.files, ceiling(row.refused));
        match error {
            GoResolutionError::CandidateLimitExceeded { limit } => assert_eq!(
                limit, row.refused,
                "the {} row must refuse at its own ceiling",
                row.label
            ),
            other => panic!("the {} row must refuse by ceiling, not {other}", row.label),
        }

        let (tree, snapshot, resolved) = resolve(row.files, ceiling(row.admitted));
        assert!(
            resolved.is_ok(),
            "the {} row must publish a report one candidate above its excess",
            row.label
        );
        drop(resolved);
        drop(snapshot);
        drop(tree);
    }
}

/// The documented defaults with only the candidate ceiling lowered.
fn ceiling(max_candidates_per_reference: u32) -> GoResolutionLimits {
    GoResolutionLimits {
        max_candidates_per_reference,
        ..GoResolutionLimits::default()
    }
}
