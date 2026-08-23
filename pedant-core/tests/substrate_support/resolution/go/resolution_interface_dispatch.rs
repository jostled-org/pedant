//! Interface dispatch: every target a call through an interface could reach,
//! and none of them resolved.
//!
//! The value behind an interface is chosen at run time. A corpus holding one
//! implementor says which method that value would answer with *if* it held one
//! of these types, and a corpus is never the whole program: another package, a
//! later commit, or a test double can add an implementor without touching this
//! call. So the answer is possible whatever the count, and a resolver that
//! resolved the one-implementor case would state a target the program need not
//! reach.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_interface_fixtures::DISPATCH;
use crate::resolution::go::resolution_views::kind_answers;
use crate::resolution::go::views::borrowed;

/// Every call the corpus states, with the targets each could reach.
///
/// Three arities, one rule. `Greet` has two implementors, `Only` has one, and
/// `Hush` has none, and all three stay possible: the count changes the
/// candidate list, never the certainty.
///
/// Each list opens with the interface's own method, which is the definition the
/// call names statically, and continues with the concrete method every
/// implementor answers under that name.
const DISPATCHES: &[&str] = &[
    "Call|Greet|dispatch.go:33|possible|Greet@dispatch.go:3,Greet@dispatch.go:16,Greet@dispatch.go:22|DynamicDispatch,Ambiguous",
    "Call|Hush|dispatch.go:37|possible|Hush@dispatch.go:7|DynamicDispatch",
    "Call|Only|dispatch.go:41|possible|Only@dispatch.go:11,Only@dispatch.go:28|DynamicDispatch,Ambiguous",
];

/// Every relation the same corpus proves, which is what makes the dispatch
/// rows readable: the implementors named there are the ones whose methods the
/// calls above reach.
const RELATIONS: &[&str] = &[
    "Implementation|One|dispatch.go:14|resolved|Greeter@dispatch.go:2|",
    "Implementation|Two|dispatch.go:20|resolved|Greeter@dispatch.go:2|",
    "Implementation|Alone|dispatch.go:26|resolved|Solo@dispatch.go:10|",
];

/// 10.T2 (Invariant 17): every interface dispatch target is possible, at zero,
/// one, and several implementors alike.
#[test]
fn go_interface_dispatch_is_always_possible() {
    let (tree, snapshot, resolution) = resolve_default(DISPATCH);

    let dispatched = kind_answers(&resolution, "Call");
    let implemented = kind_answers(&resolution, "Implementation");
    assert_eq!(
        &*borrowed(&dispatched),
        DISPATCHES,
        "a call through an interface names every target it could reach, and resolves none of them"
    );
    assert_eq!(
        &*borrowed(&implemented),
        RELATIONS,
        "the implementors whose methods those calls reach are the ones the corpus proves"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
