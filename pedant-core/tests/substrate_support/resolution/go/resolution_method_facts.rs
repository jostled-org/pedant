//! What the snapshot retained for every name the method-set case reads.
//!
//! A method answer is only as good as the receiver evidence beneath it, so the
//! evidence is stated in its own tables rather than trusted through the answers.
//! Each row is the written form of one binding or declaration: the initializer
//! a short variable declaration proves its type through, the type a `var`, a
//! parameter, or a receiver writes directly, and the single result a callable
//! declares. The case in `resolution_methods` reads these first, then reads the
//! definitions and references resolution built from them.

/// The initializer every bound name retains, which is the receiver evidence the
/// answers below are read from.
///
/// A composite literal, its address, and a call are the three forms a short
/// variable declaration proves a type through; a receiver, a parameter, and a
/// `var` state their type directly and retain no initializer at all.
pub(crate) const RETAINED_INITIALIZERS: &[&str] = &[
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
    "zembed.go|b|none",
    "zgaps.go|s|none",
    "zgaps.go|p|none",
    "zgaps.go|u|none",
    "zshadow.go|d|none",
];

/// The type every bound name writes, which is the receiver evidence a `var`, a
/// parameter, and a receiver carry instead of an initializer.
///
/// `foreign.go` is the row the qualifier claim stands on: `var n store.Node`
/// binds a name whose type belongs to another package, and the package it names
/// is retained beside the name rather than folded into it. A retention that kept
/// only `Node` would read identically to the six bare `Node` rows beneath it,
/// and the method call over it would then resolve inside `app`.
pub(crate) const DECLARED_TYPES: &[&str] = &[
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
    "zembed.go|b|-|Boxed|false",
    "zgaps.go|s|-|Stringer|false",
    "zgaps.go|p|-|Printed|false",
    "zgaps.go|u|-|Unbound|false",
    "zshadow.go|d|-|Doubled|false",
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
pub(crate) const DECLARED_RESULTS: &[&str] = &[
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
    "zembed.go|Boxed|-|-|false",
    "zembed.go|Base|-|-|false",
    "zembed.go|Boxing|-|string|false",
    "zgaps.go|Stringer|-|-|false",
    "zgaps.go|String|-|string|false",
    "zgaps.go|Printed|-|-|false",
    "zgaps.go|Stringer|-|-|false",
    "zgaps.go|Unbound|-|-|false",
    "zgaps.go|Shared|-|-|false",
    "zgaps.go|Outside|-|string|false",
    "zgaps.go|Unimported|-|string|false",
    "zshadow.go|Doubled|-|-|false",
    "zshadow.go|Shared|-|-|false",
    "zshadow.go|Twinned|-|string|false",
];
