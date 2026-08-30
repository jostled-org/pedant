//! What Tier 2 owes over
//! [`SEMANTIC_CORPUS`](super::semantic_fixtures::SEMANTIC_CORPUS).
//!
//! The unit, definition, and reference inventories are stated once, because
//! both tiers owe the same ones: Tier 2 may change candidates, gaps, and the
//! report tier and nothing else.

/// Every unit the corpus states: the root library and its path dependency.
pub const CORPUS_UNITS: &[&str] = &[
    "Cargo.toml#lib#app|app",
    "crates/helper/Cargo.toml#lib#helper|helper",
];

/// Every definition the corpus states, in report order.
pub const CORPUS_DEFINITIONS: &[&str] = &[
    "app|Struct|Widget|src/alpha.rs:0:11-0:17|alpha",
    "app|Method|render|src/alpha.rs:3:20-3:26|alpha",
    "app|Module|alpha|src/lib.rs:0:8-0:13|-",
    "app|Module|shapes|src/lib.rs:1:8-1:14|-",
    "app|Function|run|src/lib.rs:5:7-5:10|-",
    "app|Function|paint|src/lib.rs:11:7-11:12|-",
    "app|Trait|Draw|src/shapes.rs:0:10-0:14|shapes",
    "app|Method|draw|src/shapes.rs:1:7-1:11|Draw",
    "app|Trait|Ring|src/shapes.rs:4:10-4:14|shapes",
    "app|Method|ring|src/shapes.rs:5:7-5:11|Ring",
    "app|Struct|Circle|src/shapes.rs:8:11-8:17|shapes",
    "app|Method|draw|src/shapes.rs:11:7-11:11|shapes",
    "app|Struct|Square|src/shapes.rs:14:11-14:17|shapes",
    "app|Method|draw|src/shapes.rs:17:7-17:11|shapes",
    "app|Struct|Bell|src/shapes.rs:20:11-20:15|shapes",
    "app|Method|ring|src/shapes.rs:23:7-23:11|shapes",
    "helper|Function|assist|crates/helper/src/lib.rs:0:7-0:13|-",
];

/// Every reference the corpus states, in report order.
pub const CORPUS_REFERENCES: &[&str] = &[
    "app|Type|Widget|src/alpha.rs:2:5-2:11",
    "app|Type|Self|src/alpha.rs:3:28-3:32",
    "app|Module|alpha|src/lib.rs:0:4-0:13",
    "app|Module|shapes|src/lib.rs:1:4-1:14",
    "app|Import|crate::alpha::Widget|src/lib.rs:3:0-3:25",
    "app|Type|Widget|src/lib.rs:5:20-5:26",
    "app|Call|render|src/lib.rs:6:20-6:26",
    "app|Call|helper::assist|src/lib.rs:7:4-7:18",
    "app|Call|println|src/lib.rs:8:4-8:11",
    "app|Call|draw|src/lib.rs:12:10-12:14",
    "app|Call|ring|src/lib.rs:13:9-13:13",
    "app|Type|Self|src/shapes.rs:1:13-1:17",
    "app|Type|Self|src/shapes.rs:5:13-5:17",
    "app|Implementation|Draw|src/shapes.rs:10:5-10:9",
    "app|Type|Circle|src/shapes.rs:10:14-10:20",
    "app|Type|Self|src/shapes.rs:11:13-11:17",
    "app|Implementation|Draw|src/shapes.rs:16:5-16:9",
    "app|Type|Square|src/shapes.rs:16:14-16:20",
    "app|Type|Self|src/shapes.rs:17:13-17:17",
    "app|Implementation|Ring|src/shapes.rs:22:5-22:9",
    "app|Type|Bell|src/shapes.rs:22:14-22:18",
    "app|Type|Self|src/shapes.rs:23:13-23:17",
];

/// What Tier 1 answers: every path resolves, the macro is never expanded, and
/// each method call on a parameter receiver has no established type, so it is a
/// dynamic-dispatch gap.
pub const SYNTACTIC_RECORDS: &[&str] = &[
    "Widget@src/alpha.rs:2:5-2:11|Resolved:Widget|",
    "Self@src/alpha.rs:3:28-3:32|Resolved:Widget|",
    "alpha@src/lib.rs:0:4-0:13|Resolved:alpha|",
    "shapes@src/lib.rs:1:4-1:14|Resolved:shapes|",
    "crate::alpha::Widget@src/lib.rs:3:0-3:25|Resolved:Widget|",
    "Widget@src/lib.rs:5:20-5:26|Resolved:Widget|",
    "render@src/lib.rs:6:20-6:26||DynamicDispatch",
    "helper::assist@src/lib.rs:7:4-7:18|Resolved:assist|",
    "println@src/lib.rs:8:4-8:11||MacroExpansion",
    "draw@src/lib.rs:12:10-12:14||DynamicDispatch",
    "ring@src/lib.rs:13:9-13:13||DynamicDispatch",
    "Self@src/shapes.rs:1:13-1:17||ExternalDefinition",
    "Self@src/shapes.rs:5:13-5:17||ExternalDefinition",
    "Draw@src/shapes.rs:10:5-10:9|Resolved:Draw|",
    "Circle@src/shapes.rs:10:14-10:20|Resolved:Circle|",
    "Self@src/shapes.rs:11:13-11:17|Resolved:Circle|",
    "Draw@src/shapes.rs:16:5-16:9|Resolved:Draw|",
    "Square@src/shapes.rs:16:14-16:20|Resolved:Square|",
    "Self@src/shapes.rs:17:13-17:17|Resolved:Square|",
    "Ring@src/shapes.rs:22:5-22:9|Resolved:Ring|",
    "Bell@src/shapes.rs:22:14-22:18|Resolved:Bell|",
    "Self@src/shapes.rs:23:13-23:17|Resolved:Bell|",
];

/// What Tier 2 answers over the same corpus.
///
/// The inherent method call becomes the one concrete definition the database
/// names, at a column both sides must count in UTF-8 bytes. Each trait call
/// stays `Possible` and keeps its dispatch gap, because an implementation set —
/// of two members or of one — is enumerated, not proved. The macro invocation
/// is untouched: this tier expands nothing.
pub const SEMANTIC_RECORDS: &[&str] = &[
    "Widget@src/alpha.rs:2:5-2:11|Resolved:Widget|",
    "Self@src/alpha.rs:3:28-3:32|Resolved:Widget|",
    "alpha@src/lib.rs:0:4-0:13|Resolved:alpha|",
    "shapes@src/lib.rs:1:4-1:14|Resolved:shapes|",
    "crate::alpha::Widget@src/lib.rs:3:0-3:25|Resolved:Widget|",
    "Widget@src/lib.rs:5:20-5:26|Resolved:Widget|",
    "render@src/lib.rs:6:20-6:26|Resolved:render|",
    "helper::assist@src/lib.rs:7:4-7:18|Resolved:assist|",
    "println@src/lib.rs:8:4-8:11||MacroExpansion",
    "draw@src/lib.rs:12:10-12:14|Possible:draw,Possible:draw|DynamicDispatch,Ambiguous",
    "ring@src/lib.rs:13:9-13:13|Possible:ring|DynamicDispatch",
    "Self@src/shapes.rs:1:13-1:17||ExternalDefinition",
    "Self@src/shapes.rs:5:13-5:17||ExternalDefinition",
    "Draw@src/shapes.rs:10:5-10:9|Resolved:Draw|",
    "Circle@src/shapes.rs:10:14-10:20|Resolved:Circle|",
    "Self@src/shapes.rs:11:13-11:17|Resolved:Circle|",
    "Draw@src/shapes.rs:16:5-16:9|Resolved:Draw|",
    "Square@src/shapes.rs:16:14-16:20|Resolved:Square|",
    "Self@src/shapes.rs:17:13-17:17|Resolved:Square|",
    "Ring@src/shapes.rs:22:5-22:9|Resolved:Ring|",
    "Bell@src/shapes.rs:22:14-22:18|Resolved:Bell|",
    "Self@src/shapes.rs:23:13-23:17|Resolved:Bell|",
];

/// What Tier 2 answers over
/// [`CROSS_UNIT_NAMES`](super::semantic_fixtures::CROSS_UNIT_NAMES), naming the
/// unit of every candidate definition.
///
/// Both units declare `assist` at the same coordinates of their own library, so
/// only the unit tells the two targets apart.
pub const CROSS_UNIT_TARGETS: &[&str] = &[
    "app|helper::Tool@src/lib.rs:2:19-2:31|\
     Resolved:helper/Tool@crates/helper/src/lib.rs:2:11-2:15|",
    "app|helper::assist@src/lib.rs:3:4-3:18|\
     Resolved:helper/assist@crates/helper/src/lib.rs:0:7-0:13|",
    "app|use_it@src/lib.rs:4:10-4:16|\
     Resolved:helper/use_it@crates/helper/src/lib.rs:5:11-5:17|",
    "helper|Tool@crates/helper/src/lib.rs:4:5-4:9|\
     Resolved:helper/Tool@crates/helper/src/lib.rs:2:11-2:15|",
    "helper|Self@crates/helper/src/lib.rs:5:19-5:23|\
     Resolved:helper/Tool@crates/helper/src/lib.rs:2:11-2:15|",
];

/// Every source the corpus sets up in the semantic database, in the order the
/// units and their sorted closures name them. One entry per source: a second
/// resolution reuses the cached analysis rather than setting a file up again.
#[cfg(feature = "resolution-test-support")]
pub const CORPUS_SEMANTIC_SETUPS: &[&str] = &[
    "src/alpha.rs",
    "src/lib.rs",
    "src/shapes.rs",
    "crates/helper/src/lib.rs",
];
