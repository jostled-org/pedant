//! The temporary Cargo repositories every graph case projects.
//!
//! Each corpus is a real repository the production loader, snapshot, and
//! syntactic resolver read; no case mocks a project, a snapshot, or a report.

/// One fixture file: repository-relative path and exact contents.
pub type FixtureFile = (&'static str, &'static str);

/// One library root reaching every Rust symbol kind, every reference kind,
/// nested inline and external modules, and normal, development, and
/// conditional path dependencies.
pub const GRAPH_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
helper = { path = "crates/helper" }

[dev-dependencies]
harness = { path = "crates/harness" }

[target.'cfg(unix)'.dependencies]
gated = { path = "crates/gated" }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod alpha;

use helper::assist;

pub const LIMIT: u32 = 4;

pub static NAME: &str = "app";

pub struct Root;

pub enum Mode {
    On,
}

pub union Bits {
    raw: u32,
}

pub trait Shape {
    fn area(&self);
}

pub type Alias = Root;

impl Shape for Root {
    fn area(&self) {}
}

impl Root {
    pub fn make() -> Root {
        Root
    }

    pub fn tick(&self) {}
}

pub mod inner {
    pub fn nested() {}
}

pub fn run() {
    let root = Root::make();
    root.tick();
    alpha::plain();
    assist();
    inner::nested();
}
"#,
    ),
    (
        "repo/src/alpha.rs",
        r#"pub fn plain() {}
"#,
    ),
    (
        "repo/crates/helper/Cargo.toml",
        r#"[package]
name = "helper"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/crates/helper/src/lib.rs",
        r#"pub fn assist() {}
"#,
    ),
    (
        "repo/crates/harness/Cargo.toml",
        r#"[package]
name = "harness"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/crates/harness/src/lib.rs",
        r#"pub fn check() {}
"#,
    ),
    (
        "repo/crates/gated/Cargo.toml",
        r#"[package]
name = "gated"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/crates/gated/src/lib.rs",
        r#"pub fn gate() {}
"#,
    ),
];

/// One binary root and its package library, both declaring the same external
/// module, so one normalized source is instantiated by two units.
pub const SHARED_SOURCE_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "tool"
path = "src/main.rs"
"#,
    ),
    (
        "repo/src/main.rs",
        r#"mod common;

fn main() {
    common::shared();
}
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod common;

pub fn library() {
    common::shared();
}
"#,
    ),
    (
        "repo/src/common.rs",
        r#"pub fn shared() {}
"#,
    ),
];

/// One binary root whose entry point is the package library's own source, so
/// both units instantiate exactly the same single normalized path.
pub const IDENTICAL_SOURCE_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "tool"
path = "src/lib.rs"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn only() {}
"#,
    ),
];

/// One build-script root, the only root kind whose namespace exposes a build
/// dependency.
pub const BUILD_SCRIPT_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[build-dependencies]
builder = { path = "crates/builder" }
"#,
    ),
    (
        "repo/build.rs",
        r#"fn main() {
    builder::prepare();
}
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn library() {}
"#,
    ),
    (
        "repo/crates/builder/Cargo.toml",
        r#"[package]
name = "builder"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/crates/builder/src/lib.rs",
        r#"pub fn prepare() {}
"#,
    ),
];

/// One package declaring an example, an integration test, and a benchmark
/// beside its library, so the three container levels no other corpus reaches
/// each have a projected root.
pub const TARGET_KIND_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[[example]]
name = "demo"
path = "examples/demo.rs"

[[test]]
name = "case"
path = "tests/case.rs"

[[bench]]
name = "measure"
path = "benches/measure.rs"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn library() {}
"#,
    ),
    (
        "repo/examples/demo.rs",
        r#"fn main() {}
"#,
    ),
    (
        "repo/tests/case.rs",
        r#"fn main() {}
"#,
    ),
    (
        "repo/benches/measure.rs",
        r#"fn main() {}
"#,
    ),
];

/// The smallest repository that still produces a container, a file, two
/// definitions, one reference, and one resolved candidate edge.
pub const MINIMAL_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn run() { work(); }
pub fn work() {}
"#,
    ),
];

/// A second single-package repository whose root target is named differently,
/// so a pairing with the first fails on root-target identity alone.
pub const OTHER_ROOT_CORPUS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "other"
version = "0.1.0"
edition = "2021"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub fn run() { work(); }
pub fn work() {}
"#,
    ),
];
