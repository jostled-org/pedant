//! Structural implementation: which concrete types answer which interfaces,
//! and what a corpus must prove before it says so.
//!
//! Go states no intent, so the relation is the method set: every method the
//! interface requires, answered by a method of the same name whose canonical
//! signature is the same type by type. A comparison reading names alone, or
//! reading a type's name without its package, states relations Go does not
//! hold, and the near misses in the fixture are written to catch exactly that.
//!
//! The form is part of the claim. A method receiving its type by pointer is not
//! in the value form's method set, so a type answering with one implements as
//! `*T` rather than as `T`, and the site says which.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_interface_fixtures::INTERFACES;
use crate::resolution::go::resolution_views::kind_answers;
use crate::resolution::go::views::borrowed;

/// Every structural relation the corpus states, in report order.
///
/// `Person` and `Embedder` state the same four relations, which is the whole
/// promotion claim: `Embedder` declares no method of its own and answers every
/// interface through the type it embeds.
///
/// `*Counter` is the pointer row. Its `Speak` receives a pointer, so a value of
/// `Counter` carries no `Speak` at all and the relation belongs to the pointer
/// form alone.
///
/// `Mismatch` and `Local` state nothing, and their absence is the falsification:
/// `Mismatch` answers `Speak` with a `string` where `Speaker` requires an `int`,
/// and `Local` answers `Tag` over its own package's `Token` where `Tagger`
/// requires `shape.Token`. A comparison reading method names, or reading type
/// names without their packages, states two relations here that Go does not.
///
/// `Tuned` is declared under a build predicate this tier does not evaluate, so
/// its relation is possible where every other row is proved.
const RELATIONS: &[&str] = &[
    "Implementation|Person|impl.go:6|resolved|Speaker@shape/shape.go:4|",
    "Implementation|Person|impl.go:6|resolved|Named@shape/shape.go:8|",
    "Implementation|Person|impl.go:6|resolved|Loud@shape/shape.go:12|",
    "Implementation|Person|impl.go:6|resolved|Tagger@shape/shape.go:17|",
    "Implementation|*Counter|impl.go:24|resolved|Speaker@shape/shape.go:4|",
    "Implementation|Embedder|impl.go:30|resolved|Speaker@shape/shape.go:4|",
    "Implementation|Embedder|impl.go:30|resolved|Named@shape/shape.go:8|",
    "Implementation|Embedder|impl.go:30|resolved|Loud@shape/shape.go:12|",
    "Implementation|Embedder|impl.go:30|resolved|Tagger@shape/shape.go:17|",
    "Implementation|Mute|impl.go:34|resolved|Named@shape/shape.go:8|",
    "Implementation|Tuned|plat_linux.go:2|possible|Named@shape/shape.go:8|ConditionalCompilation",
];

/// 10.T1 (Invariant 18): a proven method set states one resolved implementation
/// relation, and an unproven one states none.
#[test]
fn go_structural_implementations_require_complete_method_sets() {
    let (tree, snapshot, resolution) = resolve_default(INTERFACES);

    let stated = kind_answers(&resolution, "Implementation");
    assert_eq!(
        &*borrowed(&stated),
        RELATIONS,
        "every proved relation is stated once at its concrete type's name, and no near miss is"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
