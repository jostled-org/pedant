//! The exact report contents each Tier 1 case owns.
//!
//! Every line below is read off the fixture source beside it and the stated
//! rules, so the table is an independent model and not a baseline the run
//! moved. Five rules produce all of it:
//!
//! 1. **Span.** A site spans the declared name, zero-based line and zero-based
//!    UTF-8 byte column, end exclusive. A `mod` item instead spans `mod` through
//!    its name; a `use` item spans `use` through its semicolon.
//! 2. **Parent.** A definition names its lexical owner when the source states
//!    one — a trait states one, an `impl` block does not — and otherwise the
//!    `mod` item that selected its source.
//! 3. **Order.** Units sort by key. Definitions and references sort by unit,
//!    then span, then kind, then name or text. Records follow reference order.
//! 4. **Certainty.** A candidate is `Resolved` only when nothing along the
//!    chain from its reference to its definition carries a condition; a
//!    condition anywhere makes it `Possible` and adds `ConditionalCompilation`.
//! 5. **Sites.** A one-segment path in value position states no reference site:
//!    without types this tier cannot tell a unit-struct value from a local
//!    binding, so `Widget`, `Root`, `Item`, `Gated`, `Holder`, and `Renamed`
//!    written as expressions appear in no table below. Such a path is read for
//!    receiver inference. Every other path states one site: a callee, a
//!    qualified path, a type mention, a struct literal, an import leaf, and an
//!    external `mod` item.
//!
//! Each table's own comment names the fixture lines it was read from, so a
//! wrong line is checkable against the fixture rather than against a run.

/// One conditional reference, the owner its condition comes from, and the exact
/// record it must carry.
pub struct ConditionCase {
    pub owner: &'static str,
    pub text: &'static str,
    pub line: u32,
    pub expected: &'static str,
}

/// The two units [`RESOLUTION_CORPUS`](super::syntactic_fixtures::RESOLUTION_CORPUS)
/// selects, keyed by manifest, target kind, and target name.
pub const CORPUS_UNITS: &[&str] = &[
    "Cargo.toml#lib#app|app",
    "crates/helper/Cargo.toml#lib#helper|helper",
];

/// Each report unit bound back to the snapshot unit it describes.
pub const CORPUS_BINDINGS: &[&str] = &["app|RustSnapshotUnitId(0)", "helper|RustSnapshotUnitId(1)"];

/// Every definition the corpus states, in report order: `src/alpha.rs` lines 0,
/// 3, 7, 10, 12, and 17, then `src/lib.rs` lines 0, 5, 8, 13, 14, 18, and 21,
/// then the dependency library's line 0.
///
/// `alpha.rs` is selected by `mod alpha;`, so each of its six definitions names
/// that item as its parent. `area` at line 14 sits in `trait Shape` and names
/// it; `build` and `area` at line 18 sit in `impl` blocks, which state no owner,
/// and the crate root is selected by no `mod` item, so both are parentless.
pub const CORPUS_DEFINITIONS: &[&str] = &[
    "app|Struct|Widget|src/alpha.rs:0:11-0:17|alpha",
    "app|Function|new|src/alpha.rs:3:11-3:14|alpha",
    "app|Method|render|src/alpha.rs:7:11-7:17|alpha",
    "app|Function|plain|src/alpha.rs:10:7-10:12|alpha",
    "app|Struct|Panel|src/alpha.rs:12:11-12:16|alpha",
    "app|Method|draw|src/alpha.rs:17:11-17:15|alpha",
    "app|Module|alpha|src/lib.rs:0:4-0:13|-",
    "app|Struct|Root|src/lib.rs:5:11-5:15|-",
    "app|Function|build|src/lib.rs:8:11-8:16|-",
    "app|Trait|Shape|src/lib.rs:13:10-13:15|-",
    "app|Method|area|src/lib.rs:14:7-14:11|Shape",
    "app|Method|area|src/lib.rs:18:7-18:11|-",
    "app|Function|run|src/lib.rs:21:7-21:10|-",
    "helper|Function|assist|crates/helper/src/lib.rs:0:7-0:13|-",
];

/// Every record the corpus states. Each supported target kind is resolved: the
/// module declaration, both imports, the alias, the struct literal and type
/// mentions, the associated function, the inherent method, the trait, the
/// implementation, and the path-dependency call.
///
/// `&self` receivers are type mentions of `Self`, which is why `src/alpha.rs:7`,
/// `src/alpha.rs:17`, and `src/lib.rs:18` carry one. All three receiver
/// mechanisms resolve a method call: the annotation at line 22 carries
/// `render` at line 23, the struct literal at line 27 carries `draw` at line
/// 28, and the constructor at line 29 carries `render` at line 30. The only gap
/// is `Self` in the trait at `src/lib.rs:14`: nothing in this fixture states
/// what implements `Shape` there, so its target lies outside the snapshot.
pub const CORPUS_RECORDS: &[&str] = &[
    "Widget@src/alpha.rs:2:5-2:11|Resolved:Widget|",
    "Widget@src/alpha.rs:3:20-3:26|Resolved:Widget|",
    "Self@src/alpha.rs:7:19-7:23|Resolved:Widget|",
    "Widget@src/alpha.rs:13:15-13:21|Resolved:Widget|",
    "Panel@src/alpha.rs:16:5-16:10|Resolved:Panel|",
    "Self@src/alpha.rs:17:17-17:21|Resolved:Panel|",
    "alpha@src/lib.rs:0:4-0:13|Resolved:alpha|",
    "crate::alpha::Widget@src/lib.rs:2:0-2:25|Resolved:Widget|",
    "helper::assist@src/lib.rs:3:0-3:26|Resolved:assist|",
    "Root@src/lib.rs:7:5-7:9|Resolved:Root|",
    "Root@src/lib.rs:8:22-8:26|Resolved:Root|",
    "Self@src/lib.rs:14:13-14:17||ExternalDefinition",
    "Shape@src/lib.rs:17:5-17:10|Resolved:Shape|",
    "Root@src/lib.rs:17:15-17:19|Resolved:Root|",
    "Self@src/lib.rs:18:13-18:17|Resolved:Root|",
    "Widget@src/lib.rs:22:16-22:22|Resolved:Widget|",
    "Widget::new@src/lib.rs:22:25-22:36|Resolved:new|",
    "render@src/lib.rs:23:11-23:17|Resolved:render|",
    "alpha::plain@src/lib.rs:24:4-24:16|Resolved:plain|",
    "aid@src/lib.rs:25:4-25:7|Resolved:assist|",
    "Root::build@src/lib.rs:26:4-26:15|Resolved:build|",
    "alpha::Panel@src/lib.rs:27:16-27:28|Resolved:Panel|",
    "draw@src/lib.rs:28:10-28:14|Resolved:draw|",
    "Widget::new@src/lib.rs:29:15-29:26|Resolved:new|",
    "render@src/lib.rs:30:9-30:15|Resolved:render|",
];

/// Every definition [`SHARED_SOURCE`](super::syntactic_fixtures::SHARED_SOURCE)
/// states, in report order.
///
/// One parsed `shared/common.rs` yields three definitions twice, once per unit,
/// and each copy names that unit's own `mod common;` item as its parent. Both
/// `Item` and `make` sit in `impl` blocks, which state no owner, so the `mod`
/// item selects them; `app` sorts `shared/common.rs` before `src/lib.rs` and
/// `helper` sorts `crates/helper/src/lib.rs` before it.
pub const SHARED_DEFINITIONS: &[&str] = &[
    "app|Struct|Item|shared/common.rs:0:11-0:15|common",
    "app|Function|make|shared/common.rs:3:11-3:15|common",
    "app|Function|shared|shared/common.rs:8:7-8:13|common",
    "app|Module|common|src/lib.rs:1:4-1:14|-",
    "app|Function|root_call|src/lib.rs:3:7-3:16|-",
    "helper|Module|common|crates/helper/src/lib.rs:1:4-1:14|-",
    "helper|Function|helper_call|crates/helper/src/lib.rs:3:7-3:18|-",
    "helper|Struct|Item|shared/common.rs:0:11-0:15|common",
    "helper|Function|make|shared/common.rs:3:11-3:15|common",
    "helper|Function|shared|shared/common.rs:8:7-8:13|common",
];

/// Every record [`SHARED_SOURCE`](super::syntactic_fixtures::SHARED_SOURCE)
/// states, naming the unit each candidate definition belongs to.
///
/// This is the table that separates the two identities. A resolver that kept
/// one identity per path would answer both units with the same definition, and
/// a resolver whose associated-item lookup ignored units would answer
/// `common::Item::make` with both. Every candidate here names the unit its own
/// reference was written in.
pub const SHARED_TARGETS: &[&str] = &[
    "app|Item@shared/common.rs:2:5-2:9|Resolved:app/Item@shared/common.rs:0:11-0:15|",
    "app|Item@shared/common.rs:3:21-3:25|Resolved:app/Item@shared/common.rs:0:11-0:15|",
    "app|common@src/lib.rs:1:4-1:14|Resolved:app/common@src/lib.rs:1:4-1:14|",
    "app|common::shared@src/lib.rs:4:4-4:18|Resolved:app/shared@shared/common.rs:8:7-8:13|",
    "app|common::Item::make@src/lib.rs:5:4-5:22|Resolved:app/make@shared/common.rs:3:11-3:15|",
    "helper|common@crates/helper/src/lib.rs:1:4-1:14|\
     Resolved:helper/common@crates/helper/src/lib.rs:1:4-1:14|",
    "helper|common::shared@crates/helper/src/lib.rs:4:4-4:18|\
     Resolved:helper/shared@shared/common.rs:8:7-8:13|",
    "helper|common::Item::make@crates/helper/src/lib.rs:5:4-5:22|\
     Resolved:helper/make@shared/common.rs:3:11-3:15|",
    "helper|Item@shared/common.rs:2:5-2:9|Resolved:helper/Item@shared/common.rs:0:11-0:15|",
    "helper|Item@shared/common.rs:3:21-3:25|Resolved:helper/Item@shared/common.rs:0:11-0:15|",
];

/// The binary target's local and same-package-library calls. The two `make`
/// definitions occupy the same physical path and coordinates, so the candidate
/// unit is the only distinction between them.
pub const SAME_PACKAGE_LOCAL_METHOD: &str = "tool|make@src/main.rs:6:10-6:14||DynamicDispatch";
pub const SAME_PACKAGE_LIBRARY_FUNCTION: &str = "tool|app::common::shared@src/main.rs:7:4-7:23|\
     Resolved:app/shared@src/common.rs:6:7-6:13|";
pub const SAME_PACKAGE_LIBRARY_METHOD: &str = "tool|make@src/main.rs:8:12-8:16||DynamicDispatch";

/// Every reference [`IMPORT_SHAPES`](super::syntactic_fixtures::IMPORT_SHAPES)
/// states. Grouped leaves keep their own paths and share the one `use` span, a
/// rename keeps the path it renames, a glob keeps the module it opens, and the
/// two identical call paths at lines 17 and 18 stay two sites.
///
/// The group at line 3 contributes two entries under one span, so they sort by
/// text: `Gadget` before `Widget`.
pub const IMPORT_REFERENCES: &[&str] = &[
    "app|Module|alpha|src/lib.rs:0:4-0:13",
    "app|Module|beta|src/lib.rs:1:4-1:12",
    "app|Import|crate::alpha::Gadget|src/lib.rs:3:0-3:35",
    "app|Import|crate::alpha::Widget|src/lib.rs:3:0-3:35",
    "app|Import|crate::alpha::Widget|src/lib.rs:4:0-4:36",
    "app|Import|crate::beta|src/lib.rs:5:0-5:19",
    "app|Type|Renamed|src/lib.rs:8:17-8:24",
    "app|Call|shared|src/lib.rs:10:4-10:10",
    "app|Import|crate::alpha::Widget|src/lib.rs:14:4-14:29",
    "app|Call|crate::alpha::plain|src/lib.rs:17:8-17:27",
    "app|Call|crate::alpha::plain|src/lib.rs:18:8-18:27",
];

/// The lexical module scopes the import fixture's crate root declares: the
/// source itself, then the one its inline `mod inner` opens.
pub const IMPORT_SCOPES: &[&str] = &["0||None", "1|inner|Some(0)"];

/// Every record the import fixture states: an alias binds its target, a glob
/// brings its module's names in, and the module-scoped import is visible only
/// where it is written.
pub const IMPORT_RECORDS: &[&str] = &[
    "alpha@src/lib.rs:0:4-0:13|Resolved:alpha|",
    "beta@src/lib.rs:1:4-1:12|Resolved:beta|",
    "crate::alpha::Gadget@src/lib.rs:3:0-3:35|Resolved:Gadget|",
    "crate::alpha::Widget@src/lib.rs:3:0-3:35|Resolved:Widget|",
    "crate::alpha::Widget@src/lib.rs:4:0-4:36|Resolved:Widget|",
    "crate::beta@src/lib.rs:5:0-5:19|Resolved:beta|",
    "Renamed@src/lib.rs:8:17-8:24|Resolved:Widget|",
    "shared@src/lib.rs:10:4-10:10|Resolved:shared|",
    "crate::alpha::Widget@src/lib.rs:14:4-14:29|Resolved:Widget|",
    "crate::alpha::plain@src/lib.rs:17:8-17:27|Resolved:plain|",
    "crate::alpha::plain@src/lib.rs:18:8-18:27|Resolved:plain|",
];

/// One case per owner a condition can be inherited from.
///
/// Each case isolates its owner: where the owner is a definition or a Cargo
/// edge, the reference is written unconditionally, and where the owner is the
/// reference's own lexical position, the definition it names is unconditional.
/// So a `Possible` verdict here can come from one place only.
pub const CONDITION_CASES: &[ConditionCase] = &[
    ConditionCase {
        owner: "an optional Cargo dependency edge",
        text: "gated::help",
        line: 47,
        expected: "gated::help@src/lib.rs:47:4-47:15|Possible:help|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional external module declaration",
        text: "gatedmod",
        line: 3,
        expected: "gatedmod@src/lib.rs:3:4-3:16|Possible:gatedmod|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a definition inside a conditional inline module",
        text: "nested::deep",
        line: 59,
        expected: "nested::deep@src/lib.rs:59:8-59:20|Possible:deep|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional lexical owner",
        text: "Holder::always",
        line: 35,
        expected: "Holder::always@src/lib.rs:35:4-35:18|Possible:always|ConditionalCompilation",
    },
    ConditionCase {
        owner: "conditional items under complementary predicates",
        text: "plain::marker",
        line: 46,
        expected: "plain::marker@src/lib.rs:46:4-46:17|Possible:marker,Possible:marker|ConditionalCompilation,Ambiguous",
    },
    ConditionCase {
        owner: "a conditional trait definition",
        text: "Gate",
        line: 20,
        expected: "Gate@src/lib.rs:20:5-20:9|Possible:Gate|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional implementation block",
        text: "Holder",
        line: 29,
        expected: "Holder@src/lib.rs:29:5-29:11|Possible:Holder|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional import",
        text: "crate::plain::Marker",
        line: 6,
        expected: "crate::plain::Marker@src/lib.rs:6:0-6:25|Possible:Marker|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional definition named unconditionally",
        text: "Gated",
        line: 39,
        expected: "Gated@src/lib.rs:39:14-39:19|Possible:Gated|ConditionalCompilation",
    },
    ConditionCase {
        owner: "a conditional reference to an unconditional definition",
        text: "Holder",
        line: 45,
        expected: "Holder@src/lib.rs:45:14-45:20|Possible:Holder|ConditionalCompilation",
    },
];

/// The unconditional control beside [`CONDITION_CASES`]: an always-active
/// module declaration stays resolved, so the possible verdicts above are not
/// simply what this fixture always produces.
pub const CONDITION_CONTROL: &str = "plain@src/lib.rs:0:4-0:13|Resolved:plain|";

/// Every record the CRLF, non-ASCII fixture states.
///
/// Byte columns, not character columns: `grüßen` holds two two-byte code
/// points, so the call path that starts at byte 4 of line 4 ends at byte 19 and
/// not at byte 17.
pub const CRLF_RECORDS: &[&str] = &[
    "alpha@src/lib.rs:1:4-1:13|Resolved:alpha|",
    "alpha::grüßen@src/lib.rs:4:4-4:19|Resolved:grüßen|",
];
