//! Concrete method sets: which receiver evidence a snapshot can complete, and
//! what it says when it cannot.
//!
//! A receiver whose named type is written, named by a composite literal, taken
//! by address, produced by a conversion, or returned by a callable the snapshot
//! holds is statically known. A receiver reached through an expression the
//! model states no type for is not, and says so rather than guessing.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::METHOD_SETS;
use crate::resolution::go::resolution_views::{unit_definitions, unit_references};
use crate::resolution::go::views::borrowed;

/// The package unit stating every receiver form.
const APP: &str = "x#production";

/// Every definition the package states, which is what a method's parent claim
/// is read against: a concrete method is a child of its receiver's named type.
const APP_DEFINITIONS: &[&str] = &[
    "x#production|Package|app|plat_linux.go:0|",
    "x#production|Method|Platform|plat_linux.go:2|Node",
    "x#production|Method|Platform|plat_windows.go:2|Node",
    "x#production|Function|Platform|platform.go:2|app",
    "x#production|Function|Literal|receivers.go:2|app",
    "x#production|Function|Address|receivers.go:7|app",
    "x#production|Function|Result|receivers.go:12|app",
    "x#production|Function|Converted|receivers.go:17|app",
    "x#production|Function|Declared|receivers.go:22|app",
    "x#production|Function|Indexed|receivers.go:27|app",
    "x#production|Struct|Base|types.go:2|app",
    "x#production|Method|Ping|types.go:4|Base",
    "x#production|Struct|Node|types.go:8|app",
    "x#production|Field|Base|types.go:9|Node",
    "x#production|Field|Name|types.go:10|Node",
    "x#production|Method|Rename|types.go:13|Node",
    "x#production|Method|Label|types.go:17|Node",
    "x#production|Function|NewNode|types.go:21|app",
];

/// Every method call the package states, and the receiver evidence each one
/// carries.
const METHOD_CALLS: &[&str] = &[
    "x#production|Call|NewNode|platform.go:3|resolved|x#production::NewNode|",
    "x#production|Call|Platform|platform.go:4|possible|x#production::Platform,x#production::Platform|ConditionalCompilation,Ambiguous",
    "x#production|Call|Label|receivers.go:4|resolved|x#production::Label|",
    "x#production|Call|Ping|receivers.go:9|resolved|x#production::Ping|",
    "x#production|Call|NewNode|receivers.go:13|resolved|x#production::NewNode|",
    "x#production|Call|Label|receivers.go:14|resolved|x#production::Label|",
    "x#production|Call|Label|receivers.go:19|resolved|x#production::Label|",
    "x#production|Call|Label|receivers.go:24|resolved|x#production::Label|",
    "x#production|Call|Label|receivers.go:28|-||DynamicDispatch",
];

/// 5.T5 (Invariant 16): a unique method on a statically known concrete
/// receiver resolves, an admitted promoted method resolves with it, and
/// incomplete or ambiguous receiver evidence stays explicit.
#[test]
fn go_concrete_method_sets_resolve_unique_and_promoted_receivers() {
    let (tree, snapshot, resolution) = resolve_default(METHOD_SETS);

    assert_eq!(
        &*borrowed(&unit_definitions(&resolution, APP)),
        APP_DEFINITIONS,
        "every concrete method is a child of its receiver's named type"
    );

    let stated = unit_references(&resolution, APP);
    let calls: Box<[&str]> = stated
        .iter()
        .filter(|line| line.contains("|Call|"))
        .map(|line| &**line)
        .collect();
    assert_eq!(
        &*calls, METHOD_CALLS,
        "each receiver form states exactly the evidence its source gives it"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
