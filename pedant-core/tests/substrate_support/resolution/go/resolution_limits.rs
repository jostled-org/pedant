//! The one resolver ceiling, proved at its first excess for every reference
//! category that carries candidates.
//!
//! Candidate fan-out is the only lowerable resolution ceiling. Coordinates,
//! kinds, and the snapshot identity are validation claims a published wrapper
//! always makes, so lowering them is not a thing a caller can ask for.
//!
//! Every category is answered before anything is asserted. A ceiling that
//! stopped refusing admits all four at once, and a fail-fast sequence would
//! report only the first of them.

use pedant_core::resolution::go::{GoResolutionError, GoResolutionLimits};

use crate::resolution::fixture::FixtureFile;
use crate::resolution::go::fixture::resolve;
use crate::resolution::go::resolution_fixtures::{
    LIMIT_FUNCTION, LIMIT_METHOD, LIMIT_PACKAGE, LIMIT_VALUE,
};
use crate::resolution::go::views::borrowed;

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

/// What each category does at its own excess and one candidate above it.
const ANSWERS: &[&str] = &[
    "package|refused at ceiling 0|published",
    "function|refused at ceiling 1|published",
    "value|refused at ceiling 1|published",
    "concrete method|refused at ceiling 1|published",
];

/// 8.T2 (Invariant 5): the candidates-per-reference ceiling refuses at its
/// first excess and publishes no report.
#[test]
fn go_resolution_limits_refuse_every_first_excess() {
    let answered: Box<[Box<str>]> = ROWS.iter().map(answer).collect();
    assert_eq!(
        &*borrowed(&answered),
        ANSWERS,
        "every candidate-bearing category refuses at its own first excess and publishes one above it"
    );
}

/// One row's outcome on both sides of its own ceiling.
fn answer(row: &Row) -> Box<str> {
    format!(
        "{}|{}|{}",
        row.label,
        outcome(row.files, row.refused),
        outcome(row.files, row.admitted)
    )
    .into_boxed_str()
}

/// What one corpus does under one lowered ceiling.
///
/// The refusing ceiling is restated from the error rather than assumed, because
/// a check that refused at some other reference would otherwise read the same as
/// one that refused at this row's own excess.
fn outcome(files: &[FixtureFile], max_candidates_per_reference: u32) -> Box<str> {
    let (tree, snapshot, resolved) = resolve(files, ceiling(max_candidates_per_reference));
    let stated = match resolved {
        Ok(_) => Box::from("published"),
        Err(GoResolutionError::CandidateLimitExceeded { limit }) => {
            format!("refused at ceiling {limit}").into_boxed_str()
        }
        Err(other) => format!("refused by {other}").into_boxed_str(),
    };
    drop(snapshot);
    drop(tree);
    stated
}

/// The documented defaults with only the candidate ceiling lowered.
fn ceiling(max_candidates_per_reference: u32) -> GoResolutionLimits {
    GoResolutionLimits {
        max_candidates_per_reference,
        ..GoResolutionLimits::default()
    }
}
