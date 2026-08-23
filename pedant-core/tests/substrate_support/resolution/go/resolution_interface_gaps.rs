//! What an interface comparison says when it cannot finish, and what it
//! refuses rather than truncating.
//!
//! Four things leave a comparison incomplete: an embedded interface outside the
//! snapshot, a type set written where methods belong, a required method whose
//! parameter names no single type, and a name a concrete type answers twice at
//! one embedding depth. None of them is a mismatch, so the relation survives as
//! possible evidence carrying the gap that says why — and neither is proof, so
//! none of them resolves.
//!
//! The two ceilings are refusals rather than gaps. A candidate list and a
//! comparison count that overrun say nothing about the corpus, so the whole
//! resolution refuses instead of publishing part of it.

use pedant_core::resolution::go::GoResolutionLimits;

use crate::resolution::go::fixture::{ceiling_outcome, resolve_default};
use crate::resolution::go::resolution_interface_fixtures::{
    DISPATCH, INTERFACE_GAPS, LIMIT_INTERFACE,
};
use crate::resolution::go::resolution_views::kind_answers;
use crate::resolution::go::views::borrowed;

/// Every relation the incomplete corpus states, with the gap that keeps each
/// one possible.
///
/// `Left` and `Right` are the control rows: both answer `Pinger` from complete
/// evidence and both resolve, so a resolver that reported everything incomplete
/// fails here rather than passing by never proving anything.
///
/// `Upper` and `Lower` reach the same `Ping` through one embedding each and
/// resolve; `Diamond` reaches it through both of them at one depth and stays
/// possible. Go counts embedding paths rather than the types they arrive at, so
/// a resolver keying its widened level by type alone answers `Diamond` resolved
/// — a proved relation for a selector `go build` rejects. `Upper` and `Lower`
/// are what keeps the fix honest: a resolver calling every repeated type
/// ambiguous loses both of those rows.
///
/// `Carrier` embeds `Pinger` itself, so the only member answering `Ping` is the
/// interface's own method. That relation is real Go, and a comparison admitting
/// only a receiver's methods states nothing at all about `Carrier` — no
/// relation, and no gap saying why none was stated.
const GAPPED: &[&str] = &[
    "Implementation|Console|gaps.go:9|possible|Printer@gaps.go:4|ExternalDefinition",
    "Implementation|Ruler|gaps.go:24|possible|Scaled@gaps.go:19|UnsupportedSyntax",
    "Implementation|File|gaps.go:35|possible|Writer@gaps.go:30|UnsupportedSyntax",
    "Implementation|Left|gaps.go:49|resolved|Pinger@gaps.go:45|",
    "Implementation|Right|gaps.go:55|resolved|Pinger@gaps.go:45|",
    "Implementation|Both|gaps.go:61|possible|Pinger@gaps.go:45|Ambiguous",
    "Implementation|Upper|gaps.go:66|resolved|Pinger@gaps.go:45|",
    "Implementation|Lower|gaps.go:70|resolved|Pinger@gaps.go:45|",
    "Implementation|Diamond|gaps.go:74|possible|Pinger@gaps.go:45|Ambiguous",
    "Implementation|Carrier|gaps.go:79|resolved|Pinger@gaps.go:45|",
];

/// What each ceiling does at its own excess and one above it.
const CEILINGS: &[&str] = &[
    "candidates|refused at ceiling 2|published",
    "comparisons|refused at ceiling 0|published",
];

/// 10.T3 (Invariants 5, 17-18): incomplete interface evidence keeps an exact
/// gap, and an overrun ceiling refuses the whole resolution.
#[test]
fn go_interface_incompleteness_keeps_bounded_gaps() {
    let (tree, snapshot, resolution) = resolve_default(INTERFACE_GAPS);

    let stated = kind_answers(&resolution, "Implementation");
    assert_eq!(
        &*borrowed(&stated),
        GAPPED,
        "incomplete evidence leaves a relation possible with the gap that says why"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);

    let answered: Box<[Box<str>]> = Box::from([candidate_ceiling(), comparison_ceiling()]);
    assert_eq!(
        &*borrowed(&answered),
        CEILINGS,
        "each interface ceiling refuses at its own first excess and publishes one above it"
    );
}

/// What the candidate ceiling does either side of a three-target dispatch.
///
/// The dispatch through `Greeter` names three definitions, and no other
/// reference in that corpus names more than two, so a ceiling of two is
/// refused by that record alone.
fn candidate_ceiling() -> Box<str> {
    let refused = ceiling_outcome(
        DISPATCH,
        GoResolutionLimits {
            max_candidates_per_reference: 2,
            ..GoResolutionLimits::default()
        },
    );
    let published = ceiling_outcome(
        DISPATCH,
        GoResolutionLimits {
            max_candidates_per_reference: 3,
            ..GoResolutionLimits::default()
        },
    );
    format!("candidates|{refused}|{published}").into_boxed_str()
}

/// What the comparison ceiling does either side of one comparison.
fn comparison_ceiling() -> Box<str> {
    let refused = ceiling_outcome(
        LIMIT_INTERFACE,
        GoResolutionLimits {
            max_interface_comparisons: 0,
            ..GoResolutionLimits::default()
        },
    );
    let published = ceiling_outcome(
        LIMIT_INTERFACE,
        GoResolutionLimits {
            max_interface_comparisons: 1,
            ..GoResolutionLimits::default()
        },
    );
    format!("comparisons|{refused}|{published}").into_boxed_str()
}
