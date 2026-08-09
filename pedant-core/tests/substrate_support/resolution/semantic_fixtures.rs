//! Temporary Cargo repositories the Tier 2 cases load a real semantic database
//! for.
//!
//! Every source here is plain Rust with LF line endings and no conditionally
//! declared module, because rust-analyzer resolves its own module tree: a
//! repository whose syntactic universe and semantic universe disagree is a
//! handshake case, not a resolution case. [`CONDITIONAL_MODULE`] is exactly
//! that disagreement, stated once.

use crate::resolution::fixture::FixtureFile;

/// A root library, the modules beside it, and an always-active path dependency.
///
/// Every claim Tier 2 owes over one repository is stated here, so one corpus
/// carries them all:
///
/// - `run` takes its receiver as a parameter, so Tier 1 establishes no receiver
///   type for `widget.render()` and records a dynamic-dispatch gap. Tier 2
///   resolves that one concrete definition through the database.
/// - `shape.draw()` reaches a trait declaration two types implement, and
///   `bell.ring()` one that a single type implements. Both stay possible with
///   the dispatch gap retained, because an enumerated set is not a proof.
/// - `println!` is a macro invocation neither tier expands.
/// - The promoted method call and its definition both sit behind a comment
///   holding a two-byte character, so a column counted in characters rather
///   than UTF-8 bytes moves one end of the join and not the other.
///
/// Nothing else about the two tiers may differ.
pub const SEMANTIC_CORPUS: &[FixtureFile] = &[
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
pub mod shapes;

use crate::alpha::Widget;

pub fn run(widget: &Widget) {
    /* ü */ widget.render();
    helper::assist();
    println!("done");
}

pub fn paint(shape: &dyn shapes::Draw, bell: &dyn shapes::Ring) {
    shape.draw();
    bell.ring();
}
"#,
    ),
    (
        "repo/src/alpha.rs",
        r#"pub struct Widget;

impl Widget {
    /* ü */ pub fn render(&self) {}
}
"#,
    ),
    (
        "repo/src/shapes.rs",
        r#"pub trait Draw {
    fn draw(&self);
}

pub trait Ring {
    fn ring(&self);
}

pub struct Circle;

impl Draw for Circle {
    fn draw(&self) {}
}

pub struct Square;

impl Draw for Square {
    fn draw(&self) {}
}

pub struct Bell;

impl Ring for Bell {
    fn ring(&self) {}
}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/helper/src/lib.rs", "pub fn assist() {}\n"),
];

/// The same repository with the dependency removed from the root manifest.
///
/// Written over [`SEMANTIC_CORPUS`] after its snapshot is taken, so the
/// database the context then loads holds one unit where the snapshot claims
/// two.
#[cfg(feature = "resolution-test-support")]
pub const MANIFEST_WITHOUT_DEPENDENCY: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#;

/// The same repository with the dependency made optional.
///
/// Written before both loads, so the snapshot claims a conditional unit that
/// the database — which activates no feature — does not hold.
#[cfg(feature = "resolution-test-support")]
pub const MANIFEST_WITH_OPTIONAL_DEPENDENCY: &str = r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper", optional = true }
"#;

/// Other bytes for a snapshotted source, written between the two loads.
#[cfg(feature = "resolution-test-support")]
pub const CHANGED_ALPHA: &str = r#"pub struct Widget;

impl Widget {
    pub fn render(&self) {
        let _ = 1;
    }
}
"#;

/// Two units that state the same definition name at the same coordinates in
/// their own sources, plus a cross-unit call and a cross-unit method call.
///
/// `assist` is declared at line 0 of both libraries, so a target chosen by name
/// — or by coordinate alone — cannot tell the two apart. `value.use_it()` takes
/// its receiver as a parameter, so only the database can say which unit's
/// definition it reaches.
pub const CROSS_UNIT_NAMES: &[FixtureFile] = &[
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
        r#"pub fn assist() {}

pub fn run(value: &helper::Tool) {
    helper::assist();
    value.use_it();
}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/helper/src/lib.rs",
        r#"pub fn assist() {}

pub struct Tool;

impl Tool {
    pub fn use_it(&self) {}
}
"#,
    ),
];

/// A repository whose root library declares a module behind a feature.
///
/// The syntactic closure keeps `src/gated.rs`, because Tier 1 evaluates no
/// predicate. rust-analyzer activates no feature and therefore holds one
/// source for the crate. The two path sets disagree.
#[cfg(feature = "resolution-test-support")]
pub const CONDITIONAL_MODULE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[features]
extra = []
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"#[cfg(feature = "extra")]
pub mod gated;

pub fn run() {}
"#,
    ),
    ("repo/src/gated.rs", "pub fn only_with_extra() {}\n"),
];

/// A repository whose path dependency is excluded from the workspace.
///
/// Cargo resolves only the library target of a non-member package, so the
/// database holds no crate for the dependency's binary. Requesting that binary
/// is a target the semantic database cannot answer for.
#[cfg(feature = "resolution-test-support")]
pub const EXCLUDED_BINARY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }

[workspace]
exclude = ["crates/helper"]
"#,
    ),
    ("repo/src/lib.rs", "pub fn run() {}\n"),
    (
        "repo/crates/helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/helper/src/lib.rs", "pub fn assist() {}\n"),
    (
        "repo/crates/helper/src/main.rs",
        "fn main() {\n    helper::assist();\n}\n",
    ),
];
