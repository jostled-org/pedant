//! Concrete method sets: which receiver evidence a snapshot can complete, and
//! what it says when it cannot.
//!
//! A receiver whose named type is written, named by a composite literal, taken
//! by address, produced by a conversion, or returned by a callable the snapshot
//! holds is statically known. A receiver reached through an expression the
//! model states no type for is not, and says so rather than guessing.
//!
//! What the known receiver then answers is decided by embedding depth. Go
//! widens the search one level at a time and stops at the first level that
//! answers, so a direct member beats a promoted one and a shallow promotion
//! beats a deep one. Two answers at one level are two candidates, because an
//! ambiguous selector is a Go program error rather than a choice.

use crate::resolution::go::fixture::resolve_default;
use crate::resolution::go::resolution_fixtures::METHOD_SETS;
use crate::resolution::go::resolution_views::{member_answers, unit_definitions, unit_references};
use crate::resolution::go::snapshot_views::{
    source_declared_types, source_initializers, source_results,
};
use crate::resolution::go::views::borrowed;

/// The package unit stating every receiver form.
const APP: &str = "x#production";

/// The second package, which declares the type one receiver is written from and
/// the method that receiver reaches.
const STORE: &str = "x/store#production";

/// The initializer every bound name retains, which is the receiver evidence the
/// answers below are read from.
///
/// A composite literal, its address, and a call are the three forms a short
/// variable declaration proves a type through; a receiver, a parameter, and a
/// `var` state their type directly and retain no initializer at all.
const RETAINED_INITIALIZERS: &[&str] = &[
    "foreign.go|n|none",
    "foreign.go|n|call|-|Fetch|false",
    "plat_linux.go|n|none",
    "plat_windows.go|n|none",
    "platform.go|n|call|-|NewNode|false",
    "receivers.go|n|literal|-|Node|false",
    "receivers.go|n|literal-address|-|Node|true",
    "receivers.go|n|call|-|NewNode|false",
    "receivers.go|raw|none",
    "receivers.go|n|call|-|Node|false",
    "receivers.go|n|none",
    "receivers.go|all|none",
    "receivers.go|n|literal|-|Node|false",
    "receivers.go|n|call|-|NewNode|false",
    "receivers.go|n|call|-|NewNode|false",
    "receivers.go|n|literal|-|Node|false",
    "receivers.go|n|literal|-|Node|false",
    "receivers.go|n|none",
    "store/store.go|n|none",
    "store/store.go|s|none",
    "types.go|r|none",
    "types.go|r|none",
    "types.go|b|none",
    "types.go|b|none",
    "types.go|n|none",
    "types.go|next|none",
    "types.go|n|none",
    "zembed.go|s|none",
    "zembed.go|n|none",
];

/// The type every bound name writes, which is the receiver evidence a `var`, a
/// parameter, and a receiver carry instead of an initializer.
///
/// `foreign.go` is the row the qualifier claim stands on: `var n store.Node`
/// binds a name whose type belongs to another package, and the package it names
/// is retained beside the name rather than folded into it. A retention that kept
/// only `Node` would read identically to the six bare `Node` rows beneath it,
/// and the method call over it would then resolve inside `app`.
const DECLARED_TYPES: &[&str] = &[
    "foreign.go|n|store|Node|false",
    "foreign.go|n|-|-|false",
    "plat_linux.go|n|-|Node|true",
    "plat_windows.go|n|-|Node|true",
    "platform.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|raw|-|Node|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|Node|false",
    "receivers.go|all|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|-|false",
    "receivers.go|n|-|Node|false",
    "store/store.go|n|-|Node|false",
    "store/store.go|s|-|Shared|false",
    "types.go|r|-|Root|false",
    "types.go|r|-|Root|false",
    "types.go|b|-|Base|false",
    "types.go|b|-|Base|false",
    "types.go|n|-|Node|true",
    "types.go|next|-|string|false",
    "types.go|n|-|Node|false",
    "zembed.go|s|-|Shared|false",
    "zembed.go|n|-|ForeignBase|false",
];

/// The single result every declaration states, which is what makes a receiver
/// read from a call statically known.
///
/// `NewNode` and `Fetch` are the only declarations here that return a named
/// type. `NewNode` returns `app`'s own in pointer form; `Fetch` returns another
/// package's, and the package it names is retained beside the type rather than
/// folded into it. Every other callable returns a `string` no method is called
/// on, and the types and fields beside them declare no result at all.
///
/// A retention that dropped the declared result would leave `n := NewNode()`
/// with no receiver type, and one that dropped the qualifier would leave
/// `n := Fetch()` looking like it returned `app`'s `Node`, so this table is read
/// beside the method answers rather than trusted through them.
const DECLARED_RESULTS: &[&str] = &[
    "foreign.go|Foreign|-|string|false",
    "foreign.go|Fetch|store|Node|false",
    "foreign.go|Crossed|-|string|false",
    "plat_linux.go|Platform|-|string|false",
    "plat_windows.go|Platform|-|string|false",
    "platform.go|Platform|-|string|false",
    "receivers.go|Literal|-|string|false",
    "receivers.go|Address|-|string|false",
    "receivers.go|Result|-|string|false",
    "receivers.go|Converted|-|string|false",
    "receivers.go|Declared|-|string|false",
    "receivers.go|Indexed|-|string|false",
    "receivers.go|Renamed|-|string|false",
    "receivers.go|Pointed|-|string|false",
    "receivers.go|Dereferenced|-|string|false",
    "receivers.go|Addressed|-|string|false",
    "receivers.go|Promoted|-|string|false",
    "receivers.go|MissingMember|-|string|false",
    "store/store.go|Node|-|-|false",
    "store/store.go|Label|-|string|false",
    "store/store.go|Shared|-|-|false",
    "store/store.go|Promote|-|string|false",
    "types.go|Root|-|-|false",
    "types.go|Trace|-|string|false",
    "types.go|Ping|-|string|false",
    "types.go|Base|-|-|false",
    "types.go|Root|-|-|false",
    "types.go|Ping|-|string|false",
    "types.go|Label|-|string|false",
    "types.go|Node|-|-|false",
    "types.go|Base|-|-|false",
    "types.go|Name|-|-|false",
    "types.go|Rename|-|-|false",
    "types.go|Label|-|string|false",
    "types.go|NewNode|-|Node|true",
    "zembed.go|Shared|-|-|false",
    "zembed.go|Promote|-|string|false",
    "zembed.go|ForeignBase|-|-|false",
    "zembed.go|Shared|-|-|false",
    "zembed.go|Embedded|-|string|false",
];

/// Every definition the package states, which is what a method's parent claim
/// is read against: a concrete method is a child of its receiver's named type.
const APP_DEFINITIONS: &[&str] = &[
    "x#production|Package|app|foreign.go:0|",
    "x#production|Function|Foreign|foreign.go:4|app",
    "x#production|Function|Fetch|foreign.go:9|app",
    "x#production|Function|Crossed|foreign.go:13|app",
    "x#production|Method|Platform|plat_linux.go:2|Node",
    "x#production|Method|Platform|plat_windows.go:2|Node",
    "x#production|Function|Platform|platform.go:2|app",
    "x#production|Function|Literal|receivers.go:2|app",
    "x#production|Function|Address|receivers.go:7|app",
    "x#production|Function|Result|receivers.go:12|app",
    "x#production|Function|Converted|receivers.go:17|app",
    "x#production|Function|Declared|receivers.go:22|app",
    "x#production|Function|Indexed|receivers.go:27|app",
    "x#production|Function|Renamed|receivers.go:31|app",
    "x#production|Function|Pointed|receivers.go:37|app",
    "x#production|Function|Dereferenced|receivers.go:43|app",
    "x#production|Function|Addressed|receivers.go:48|app",
    "x#production|Function|Promoted|receivers.go:53|app",
    "x#production|Function|MissingMember|receivers.go:58|app",
    "x#production|Struct|Root|types.go:2|app",
    "x#production|Method|Trace|types.go:4|Root",
    "x#production|Method|Ping|types.go:8|Root",
    "x#production|Struct|Base|types.go:12|app",
    "x#production|Field|Root|types.go:13|Base",
    "x#production|Method|Ping|types.go:16|Base",
    "x#production|Method|Label|types.go:20|Base",
    "x#production|Struct|Node|types.go:24|app",
    "x#production|Field|Base|types.go:25|Node",
    "x#production|Field|Name|types.go:26|Node",
    "x#production|Method|Rename|types.go:29|Node",
    "x#production|Method|Label|types.go:33|Node",
    "x#production|Function|NewNode|types.go:37|app",
    "x#production|Struct|Shared|zembed.go:4|app",
    "x#production|Method|Promote|zembed.go:6|Shared",
    "x#production|Struct|ForeignBase|zembed.go:10|app",
    "x#production|Field|Shared|zembed.go:11|ForeignBase",
    "x#production|Function|Embedded|zembed.go:14|app",
];

/// Every reference the package states, compared whole.
///
/// The method calls are the claim, and the type and field occurrences beside
/// them are what keeps the claim honest: a receiver's type is read from the same
/// corpus the type rows name, so a gained, lost, or re-certified type reference
/// is a change to the evidence the method answers stand on.
///
/// Four rows carry the pointer-or-value rule. `Renamed` calls `Rename` — a
/// pointer-form method — on a value-typed receiver, `Pointed` calls it through a
/// pointer, `Result` reaches value-form `Label` through a pointer, and `Address`
/// reaches promoted value-form `Ping` through one. A resolver that matched a
/// receiver's pointer form against its method's would answer `MissingDefinition`
/// for the crossing rows.
///
/// `Dereferenced` and `Addressed` write the receiver the parentheses Go requires
/// around a dereference or an address before a selector, so the receiver text
/// itself carries `*` and `&` rather than only the binding beneath it.
///
/// `Foreign` carries the cross-package rule. Its receiver is declared
/// `store.Node`, and both packages declare a `Node` holding a `Label`, so the
/// package the receiver's type names decides which `Label` the call reaches. The
/// row names `x/store#production::Label`; a resolver that read the type name
/// without its qualifier would name `x#production::Label` here and stay green
/// everywhere else.
///
/// `Crossed` carries the same rule over a *result*. `Fetch` returns
/// `store.Node`, and a declared result names its package through the imports of
/// the file that declared it rather than the file asking, so this tier states no
/// receiver type and `foreign.go:15` keeps the dynamic-dispatch gap. That gap is
/// the honest answer, and it is the row that moves: a resolver reading the
/// result's name without its qualifier finds `app`'s own `Node` and publishes a
/// resolved edge into the wrong package.
const APP_REFERENCES: &[&str] = &[
    "x#production|Import|x/store|foreign.go:2|resolved|x/store#production::store|",
    "x#production|Type|string|foreign.go:4|-||ExternalDefinition",
    "x#production|Type|Node|foreign.go:5|resolved|x/store#production::Node|",
    "x#production|Call|Label|foreign.go:6|resolved|x/store#production::Label|",
    "x#production|Type|Node|foreign.go:9|resolved|x/store#production::Node|",
    "x#production|Type|Node|foreign.go:10|resolved|x/store#production::Node|",
    "x#production|Type|string|foreign.go:13|-||ExternalDefinition",
    "x#production|Call|Fetch|foreign.go:14|resolved|x#production::Fetch|",
    "x#production|Call|Label|foreign.go:15|-||DynamicDispatch",
    "x#production|Type|Node|plat_linux.go:2|possible|x#production::Node|ConditionalCompilation",
    "x#production|Type|string|plat_linux.go:2|-||ExternalDefinition,ConditionalCompilation",
    "x#production|Type|Node|plat_windows.go:2|possible|x#production::Node|ConditionalCompilation",
    "x#production|Type|string|plat_windows.go:2|-||ExternalDefinition,ConditionalCompilation",
    "x#production|Type|string|platform.go:2|-||ExternalDefinition",
    "x#production|Call|NewNode|platform.go:3|resolved|x#production::NewNode|",
    "x#production|Call|Platform|platform.go:4|possible|x#production::Platform,x#production::Platform|ConditionalCompilation,Ambiguous",
    "x#production|Type|string|receivers.go:2|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:3|resolved|x#production::Node|",
    "x#production|Call|Label|receivers.go:4|resolved|x#production::Label|",
    "x#production|Type|string|receivers.go:7|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:8|resolved|x#production::Node|",
    "x#production|Call|Ping|receivers.go:9|resolved|x#production::Ping|",
    "x#production|Type|string|receivers.go:12|-||ExternalDefinition",
    "x#production|Call|NewNode|receivers.go:13|resolved|x#production::NewNode|",
    "x#production|Call|Label|receivers.go:14|resolved|x#production::Label|",
    "x#production|Type|Node|receivers.go:17|resolved|x#production::Node|",
    "x#production|Type|string|receivers.go:17|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:18|resolved|x#production::Node|",
    "x#production|Call|Label|receivers.go:19|resolved|x#production::Label|",
    "x#production|Type|string|receivers.go:22|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:23|resolved|x#production::Node|",
    "x#production|Call|Label|receivers.go:24|resolved|x#production::Label|",
    "x#production|Type|Node|receivers.go:27|resolved|x#production::Node|",
    "x#production|Type|string|receivers.go:27|-||ExternalDefinition",
    "x#production|Call|Label|receivers.go:28|-||DynamicDispatch",
    "x#production|Type|string|receivers.go:31|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:32|resolved|x#production::Node|",
    "x#production|Call|Rename|receivers.go:33|resolved|x#production::Rename|",
    "x#production|Call|Label|receivers.go:34|resolved|x#production::Label|",
    "x#production|Type|string|receivers.go:37|-||ExternalDefinition",
    "x#production|Call|NewNode|receivers.go:38|resolved|x#production::NewNode|",
    "x#production|Call|Rename|receivers.go:39|resolved|x#production::Rename|",
    "x#production|Call|Label|receivers.go:40|resolved|x#production::Label|",
    "x#production|Type|string|receivers.go:43|-||ExternalDefinition",
    "x#production|Call|NewNode|receivers.go:44|resolved|x#production::NewNode|",
    "x#production|Call|Label|receivers.go:45|resolved|x#production::Label|",
    "x#production|Type|string|receivers.go:48|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:49|resolved|x#production::Node|",
    "x#production|Call|Ping|receivers.go:50|resolved|x#production::Ping|",
    "x#production|Type|string|receivers.go:53|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:54|resolved|x#production::Node|",
    "x#production|Call|Trace|receivers.go:55|resolved|x#production::Trace|",
    "x#production|Type|string|receivers.go:58|-||ExternalDefinition",
    "x#production|Type|Node|receivers.go:59|resolved|x#production::Node|",
    "x#production|Call|Absent|receivers.go:60|-||MissingDefinition",
    "x#production|Type|Root|types.go:4|resolved|x#production::Root|",
    "x#production|Type|string|types.go:4|-||ExternalDefinition",
    "x#production|Type|Root|types.go:8|resolved|x#production::Root|",
    "x#production|Type|string|types.go:8|-||ExternalDefinition",
    "x#production|Type|Root|types.go:13|resolved|x#production::Root|",
    "x#production|Type|Base|types.go:16|resolved|x#production::Base|",
    "x#production|Type|string|types.go:16|-||ExternalDefinition",
    "x#production|Type|Base|types.go:20|resolved|x#production::Base|",
    "x#production|Type|string|types.go:20|-||ExternalDefinition",
    "x#production|Type|Base|types.go:25|resolved|x#production::Base|",
    "x#production|Type|string|types.go:26|-||ExternalDefinition",
    "x#production|Type|Node|types.go:29|resolved|x#production::Node|",
    "x#production|Type|string|types.go:29|-||ExternalDefinition",
    "x#production|Value|Name|types.go:30|resolved|x#production::Name|",
    "x#production|Type|Node|types.go:33|resolved|x#production::Node|",
    "x#production|Type|string|types.go:33|-||ExternalDefinition",
    "x#production|Value|Name|types.go:34|resolved|x#production::Name|",
    "x#production|Type|Node|types.go:37|resolved|x#production::Node|",
    "x#production|Type|Node|types.go:38|resolved|x#production::Node|",
    "x#production|Import|x/store|zembed.go:2|resolved|x/store#production::store|",
    "x#production|Type|Shared|zembed.go:6|resolved|x#production::Shared|",
    "x#production|Type|string|zembed.go:6|-||ExternalDefinition",
    "x#production|Type|Shared|zembed.go:11|resolved|x/store#production::Shared|",
    "x#production|Type|string|zembed.go:14|-||ExternalDefinition",
    "x#production|Type|ForeignBase|zembed.go:15|resolved|x#production::ForeignBase|",
    "x#production|Call|Promote|zembed.go:16|resolved|x/store#production::Promote|",
];

/// Every definition the second package states, which is what the crossing call
/// resolves into.
const STORE_DEFINITIONS: &[&str] = &[
    "x/store#production|Package|store|store/store.go:0|",
    "x/store#production|Struct|Node|store/store.go:2|store",
    "x/store#production|Method|Label|store/store.go:4|Node",
    "x/store#production|Struct|Shared|store/store.go:8|store",
    "x/store#production|Method|Promote|store/store.go:10|Shared",
];

/// Every reference the second package states, compared whole.
///
/// The package declares its `Label` and calls none, so a resolved `Label` this
/// unit does not state is one the crossing row in `app` reached rather than one
/// `store` reached for itself.
const STORE_REFERENCES: &[&str] = &[
    "x/store#production|Type|Node|store/store.go:4|resolved|x/store#production::Node|",
    "x/store#production|Type|string|store/store.go:4|-||ExternalDefinition",
    "x/store#production|Type|Shared|store/store.go:10|resolved|x/store#production::Shared|",
    "x/store#production|Type|string|store/store.go:10|-||ExternalDefinition",
];

/// The three names the embedding chain answers at more than one depth.
const PROMOTED_NAMES: &[&str] = &["Label", "Ping", "Promote", "Trace"];

/// Which declaration each of those names reached, by the site it is written at.
///
/// Every other table labels a candidate `<unit>::<name>`, which is the same text
/// for `Node`'s `Label` and `Base`'s. Depth is the whole claim here, so these
/// rows name the line instead. `Node` declares `Label` at `types.go:33` and
/// `Base` promotes one from `types.go:20`, so depth 0 wins; `Base` declares
/// `Ping` at `types.go:16` and `Root` promotes one from `types.go:8`, so depth 1
/// wins over depth 2; `Trace` is declared only on `Root`, so reaching it at all
/// is reaching depth 2.
///
/// A resolver that gathered every depth into one candidate set would answer two
/// sites for `Label` and two for `Ping`, and one that widened past the first
/// answering level would answer `types.go:20` and `types.go:8`. Both stay green
/// in every other table.
const PROMOTION_DEPTHS: &[&str] = &[
    "Call|Label|foreign.go:6|store/store.go:4",
    "Call|Label|foreign.go:15|",
    "Call|Label|receivers.go:4|types.go:33",
    "Call|Ping|receivers.go:9|types.go:16",
    "Call|Label|receivers.go:14|types.go:33",
    "Call|Label|receivers.go:19|types.go:33",
    "Call|Label|receivers.go:24|types.go:33",
    "Call|Label|receivers.go:28|",
    "Call|Label|receivers.go:34|types.go:33",
    "Call|Label|receivers.go:40|types.go:33",
    "Call|Label|receivers.go:45|types.go:33",
    "Call|Ping|receivers.go:50|types.go:16",
    "Call|Trace|receivers.go:55|types.go:4",
    "Call|Promote|zembed.go:16|store/store.go:10",
];

/// 7.T1 (Invariant 16): a unique method on a statically known concrete
/// receiver resolves according to its pointer or value method set, a promoted
/// method resolves at the shallowest depth that answers it, a receiver whose
/// declared type names another package resolves in that package, and incomplete
/// or ambiguous receiver evidence stays explicit.
#[test]
fn go_concrete_method_sets_resolve_unique_and_promoted_receivers() {
    let (tree, snapshot, resolution) = resolve_default(METHOD_SETS);

    assert_eq!(
        &*borrowed(&source_declared_types(&snapshot)),
        DECLARED_TYPES,
        "the snapshot retains the type each binding writes, with the package that type names"
    );
    assert_eq!(
        &*borrowed(&source_initializers(&snapshot)),
        RETAINED_INITIALIZERS,
        "the snapshot retains the initializer each receiver's type is inferred from"
    );
    assert_eq!(
        &*borrowed(&source_results(&snapshot)),
        DECLARED_RESULTS,
        "the snapshot retains the result each callable declares, in the form its source writes"
    );
    assert_eq!(
        &*borrowed(&unit_definitions(&resolution, APP)),
        APP_DEFINITIONS,
        "every concrete method is a child of its receiver's named type"
    );
    assert_eq!(
        &*borrowed(&unit_references(&resolution, APP)),
        APP_REFERENCES,
        "each receiver form states exactly the evidence its source gives it"
    );
    assert_eq!(
        &*borrowed(&member_answers(&resolution, APP, PROMOTED_NAMES)),
        PROMOTION_DEPTHS,
        "a promoted member resolves at the shallowest embedding depth that answers it"
    );
    assert_eq!(
        &*borrowed(&unit_definitions(&resolution, STORE)),
        STORE_DEFINITIONS,
        "the second package declares the type and the method the crossing receiver reaches"
    );
    assert_eq!(
        &*borrowed(&unit_references(&resolution, STORE)),
        STORE_REFERENCES,
        "the second package states only its own occurrences"
    );

    drop(resolution);
    drop(snapshot);
    drop(tree);
}
