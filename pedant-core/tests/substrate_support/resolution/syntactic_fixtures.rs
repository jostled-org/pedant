//! Temporary Cargo repositories the Tier 1 cases resolve.

use crate::resolution::fixture::FixtureFile;

/// A root library, a module beside it, and an always-active path dependency:
/// one repository holding every reference kind Tier 1 must resolve.
///
/// Each of the three receiver mechanisms the tier supports establishes one
/// method call: the annotation on `widget`, the struct literal that builds
/// `panel`, and the constructor call that builds `made`.
pub const RESOLUTION_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod alpha;

use crate::alpha::Widget;
use helper::assist as aid;

pub struct Root;

impl Root {
    pub fn build() -> Root {
        Root
    }
}

pub trait Shape {
    fn area(&self);
}

impl Shape for Root {
    fn area(&self) {}
}

pub fn run() {
    let widget: Widget = Widget::new();
    widget.render();
    alpha::plain();
    aid();
    Root::build();
    let panel = alpha::Panel { inner: widget };
    panel.draw();
    let made = Widget::new();
    made.render();
}
"#,
    ),
    (
        "repo/src/alpha.rs",
        r#"pub struct Widget;

impl Widget {
    pub fn new() -> Widget {
        Widget
    }

    pub fn render(&self) {}
}

pub fn plain() {}

pub struct Panel {
    pub inner: Widget,
}

impl Panel {
    pub fn draw(&self) {}
}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/helper/src/lib.rs", "pub fn assist() {}\n"),
];

/// One physical source reached by two units. The root library and its path
/// dependency each declare `shared/common.rs` through `#[path]`, so the source
/// belongs to both closures.
///
/// The store keys sources by normalized path, so this file is read, hashed, and
/// parsed once. Every unit still owns its own instance of it: each unit's calls
/// must select that unit's definitions, including the associated function,
/// whose owner name is stated twice in the corpus and once per unit.
pub const SHARED_SOURCE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"#[path = "../shared/common.rs"]
pub mod common;

pub fn root_call() {
    common::shared();
    common::Item::make();
}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/helper/src/lib.rs",
        r#"#[path = "../../../shared/common.rs"]
pub mod common;

pub fn helper_call() {
    common::shared();
    common::Item::make();
}
"#,
    ),
    (
        "repo/shared/common.rs",
        r#"pub struct Item;

impl Item {
    pub fn make() -> Item {
        Item
    }
}

pub fn shared() {}
"#,
    ),
];

/// Imports in every shape the inventory must retain, plus one path text that
/// occurs twice so the two occurrences stay two reference sites.
pub const IMPORT_SHAPES: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod alpha;
pub mod beta;

use crate::alpha::{Gadget, Widget};
use crate::alpha::Widget as Renamed;
use crate::beta::*;

pub fn use_bindings() {
    let renamed: Renamed = Renamed;
    let _ = renamed;
    shared();
}

pub mod inner {
    use crate::alpha::Widget;

    pub fn hold() {
        crate::alpha::plain();
        crate::alpha::plain();
    }
}
"#,
    ),
    (
        "repo/src/alpha.rs",
        "pub struct Widget;\n\npub struct Gadget;\n\npub fn plain() {}\n",
    ),
    ("repo/src/beta.rs", "pub fn shared() {}\n"),
];

/// Every owner a condition can be inherited from: a Cargo edge, an external
/// module, an inline module, a lexical owner, an item, an implementation, an
/// import, and a reference. Two `marker` definitions under complementary
/// predicates prove alternatives are never collapsed.
pub const CONDITION_OWNERS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
gated = { path = "crates/gated", optional = true }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod plain;

#[cfg(feature = "extra")]
pub mod gatedmod;

#[cfg(unix)]
use crate::plain::Marker;

#[cfg(feature = "extra")]
pub struct Gated;

pub struct Holder;

pub struct Gadget;

#[cfg(unix)]
pub trait Gate {
    fn opened();
}

impl Gate for Gadget {
    fn opened() {}
}

impl Holder {
    pub fn always() {}
}

#[cfg(unix)]
impl Holder {
    pub fn only_unix() {}
}

#[cfg(target_family = "wasm")]
pub fn owner_scoped() {
    Holder::always();
}

pub fn uses_gated() {
    let held: Gated = Gated;
    let _ = held;
}

pub fn caller() {
    #[cfg(windows)]
    let held: Holder = Holder;
    plain::marker();
    gated::help();
    Holder::only_unix();
}

pub mod outer {
    #[cfg(target_os = "linux")]
    pub mod nested {
        pub fn deep() {}
    }

    #[cfg(target_os = "linux")]
    pub fn reach() {
        nested::deep();
    }
}
"#,
    ),
    (
        "repo/src/plain.rs",
        r#"pub struct Marker;

#[cfg(unix)]
pub fn marker() {}

#[cfg(not(unix))]
pub fn marker() {}
"#,
    ),
    ("repo/src/gatedmod.rs", "pub fn gated_only() {}\n"),
    (
        "repo/crates/gated/Cargo.toml",
        "[package]\nname = \"gated\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/gated/src/lib.rs", "pub fn help() {}\n"),
];

/// A source whose lines end with CRLF and whose text is not ASCII, so every
/// emitted coordinate must land on a UTF-8 boundary of the exact bytes.
pub const NON_ASCII_CRLF: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        "// héllo wörld\r\npub mod alpha;\r\n\r\npub fn caller() {\r\n    alpha::grüßen();\r\n}\r\n",
    ),
    (
        "repo/src/alpha.rs",
        "// wörter\npub fn grüßen() {\n    let _ = \"añejo\";\n}\n",
    ),
];

/// The same repository under another package name, so its unit keys cannot
/// bind a report produced from [`NON_ASCII_CRLF`].
pub const RENAMED_PACKAGE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        "// héllo wörld\r\npub mod alpha;\r\n\r\npub fn caller() {\r\n    alpha::grüßen();\r\n}\r\n",
    ),
    (
        "repo/src/alpha.rs",
        "// wörter\npub fn grüßen() {\n    let _ = \"añejo\";\n}\n",
    ),
];

/// The same package name and layout with one source removed, so a report from
/// [`NON_ASCII_CRLF`] names a file this snapshot does not hold.
pub const MISSING_SOURCE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        "// héllo wörld\r\npub fn caller() {}\r\n",
    ),
];
