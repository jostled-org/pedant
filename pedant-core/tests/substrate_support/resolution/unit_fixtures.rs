//! Repositories and expected values for target-scoped dependency unit
//! selection.
//!
//! The models live beside the cases that read them so no expectation is
//! derived from a run. The single-target repositories live in
//! `closure_fixtures.rs`.

use crate::resolution::fixture::FixtureFile;

/// A root package with one dependency of every kind, a rename, a conditional
/// edge, a transitive normal edge, and sources that belong to none of them.
pub const DEPENDENCY_UNITS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
libx = { path = "crates/libx" }
renamed = { package = "libx", path = "crates/libx" }

[dev-dependencies]
devy = { path = "crates/devy" }

[build-dependencies]
buildz = { path = "crates/buildz" }

[target."cfg(unix)".dependencies]
condw = { path = "crates/condw" }
"#,
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
    ("repo/src/main.rs", "fn main() {}\n"),
    ("repo/src/unrelated.rs", "pub fn unrelated() {}\n"),
    ("repo/tests/it.rs", "#[test]\nfn it() {}\n"),
    ("repo/examples/demo.rs", "fn main() {}\n"),
    ("repo/benches/perf.rs", "fn main() {}\n"),
    ("repo/build.rs", "fn main() {}\n"),
    (
        "repo/crates/libx/Cargo.toml",
        r#"[package]
name = "libx"
version = "0.1.0"
edition = "2021"

[dependencies]
deep = { path = "../deep" }

[dev-dependencies]
devy = { path = "../devy" }
"#,
    ),
    ("repo/crates/libx/src/lib.rs", "pub mod part;\n"),
    ("repo/crates/libx/src/part.rs", "pub fn part() {}\n"),
    ("repo/crates/libx/src/bin/extra.rs", "fn main() {}\n"),
    (
        "repo/crates/deep/Cargo.toml",
        "[package]\nname = \"deep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/deep/src/lib.rs", "pub fn deep() {}\n"),
    ("repo/crates/deep/build.rs", "fn main() {}\n"),
    (
        "repo/crates/devy/Cargo.toml",
        "[package]\nname = \"devy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/devy/src/lib.rs", "pub fn devy() {}\n"),
    (
        "repo/crates/buildz/Cargo.toml",
        "[package]\nname = \"buildz\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/buildz/src/lib.rs", "pub fn buildz() {}\n"),
    (
        "repo/crates/condw/Cargo.toml",
        "[package]\nname = \"condw\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/condw/src/lib.rs", "pub fn condw() {}\n"),
];

/// `package|target|activation` for every unit a library root selects.
pub const EXPECTED_LIBRARY_UNITS: &[&str] = &[
    "app|app|always",
    "condw|condw|cfg(unix)",
    "deep|deep|always",
    "devy|devy|cfg(test)",
    "libx|libx|always",
];

/// `source unit|alias|target unit|kind|activation` for every selected edge.
pub const EXPECTED_LIBRARY_EDGES: &[&str] = &[
    "app|condw|condw|Normal|cfg(unix)",
    "app|libx|libx|Normal|always",
    "app|renamed|libx|Normal|always",
    "app|devy|devy|Development|cfg(test)",
    "libx|deep|deep|Normal|always",
];

/// Every source the library root's unit graph reaches, path-deduplicated.
pub const EXPECTED_LIBRARY_UNIT_SOURCES: &[&str] = &[
    "crates/condw/src/lib.rs",
    "crates/deep/src/lib.rs",
    "crates/devy/src/lib.rs",
    "crates/libx/src/lib.rs",
    "crates/libx/src/part.rs",
    "src/lib.rs",
];

/// `package|source,source` for every unit the library root selects, which
/// binds each closure to the unit that owns it rather than to the shared store.
pub const EXPECTED_LIBRARY_UNIT_MEMBERSHIP: &[&str] = &[
    "app|src/lib.rs",
    "condw|crates/condw/src/lib.rs",
    "deep|crates/deep/src/lib.rs",
    "devy|crates/devy/src/lib.rs",
    "libx|crates/libx/src/lib.rs,crates/libx/src/part.rs",
];

/// The module instances the one multi-source dependency unit holds.
pub const EXPECTED_LIBX_MODULES: &[&str] = &[
    "RustModuleId(0)|crate|crates/libx/src/lib.rs|0|false|None",
    "RustModuleId(1)|part|crates/libx/src/part.rs|1|false|Some(RustModuleId(0))",
];

/// Sources inside the repository that no selected unit may reach.
pub const EXCLUDED_FROM_UNIT_SOURCES: &[&str] = &[
    "build.rs",
    "crates/buildz/src/lib.rs",
    "crates/deep/build.rs",
    "crates/libx/src/bin/extra.rs",
    "benches/perf.rs",
    "examples/demo.rs",
    "src/main.rs",
    "src/unrelated.rs",
    "tests/it.rs",
];

/// Every unit a test root selects: normal plus development edges, taken as
/// declared rather than under a test condition.
pub const EXPECTED_TEST_UNITS: &[&str] = &[
    "app|app|always",
    "app|it|always",
    "condw|condw|cfg(unix)",
    "deep|deep|always",
    "devy|devy|always",
    "libx|libx|always",
];

/// Every unit an example root selects: its package library plus normal and
/// development dependencies.
pub const EXPECTED_EXAMPLE_UNITS: &[&str] = &[
    "app|app|always",
    "app|demo|always",
    "condw|condw|cfg(unix)",
    "deep|deep|always",
    "devy|devy|always",
    "libx|libx|always",
];

/// Every unit a benchmark root selects: its package library plus normal and
/// development dependencies.
pub const EXPECTED_BENCHMARK_UNITS: &[&str] = &[
    "app|app|always",
    "app|perf|always",
    "condw|condw|cfg(unix)",
    "deep|deep|always",
    "devy|devy|always",
    "libx|libx|always",
];

/// Every unit a build-script root selects.
pub const EXPECTED_BUILD_UNITS: &[&str] =
    &["app|build-script-build|always", "buildz|buildz|always"];

/// One package whose library and binary targets each instantiate the same
/// physical source, while the binary also names the library through Cargo's
/// implicit same-package edge.
///
/// The binary snapshot must contain both units. That makes `src/common.rs`
/// occupy the same path and coordinates twice, while the receiver types below
/// require one call to select the binary instance and one to select the library
/// instance.
pub const SAME_PACKAGE_TARGETS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"

[[bin]]
name = "tool"
path = "src/main.rs"
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod common;

pub fn run(item: &common::Item) {
    common::shared();
    item.make();
}
"#,
    ),
    (
        "repo/src/main.rs",
        r#"mod common;

fn main() {}

fn drive(local: &common::Item, library: &app::common::Item) {
    common::shared();
    local.make();
    app::common::shared();
    library.make();
}
"#,
    ),
    (
        "repo/src/common.rs",
        r#"pub struct Item;

impl Item {
    pub fn make(&self) {}
}

pub fn shared() {}
"#,
    ),
];

/// A library and binary that both instantiate one physical module containing
/// a receiver call Tier 1 must leave dynamic.
///
/// rust-analyzer analyzes `src/common.rs` as one file, so it cannot return a
/// distinct semantic answer for both Cargo unit identities in the binary
/// resolution snapshot.
pub const SEMANTIC_SHARED_SOURCE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"

[[bin]]
name = "tool"
path = "src/main.rs"
"#,
    ),
    ("repo/src/lib.rs", "pub mod common;\n"),
    ("repo/src/main.rs", "mod common;\n\nfn main() {}\n"),
    (
        "repo/src/common.rs",
        r#"pub struct Item;

impl Item {
    pub fn make(&self) {}
}

pub fn invoke(item: &Item) {
    item.make();
}
"#,
    ),
];

/// A root whose dependency paths compose every activation form: a
/// target-qualified development edge that conjoins two predicates, a package
/// reached through two different predicates, and a package reached both
/// conditionally and unconditionally.
pub const ACTIVATION_COMPOSITION: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
both = { path = "crates/both" }

[target."cfg(unix)".dependencies]
unixa = { path = "crates/unixa" }

[target."cfg(windows)".dependencies]
wina = { path = "crates/wina" }

[target."cfg(unix)".dev-dependencies]
condev = { path = "crates/condev" }
"#,
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
    (
        "repo/crates/unixa/Cargo.toml",
        r#"[package]
name = "unixa"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = { path = "../shared" }
both = { path = "../both" }
"#,
    ),
    ("repo/crates/unixa/src/lib.rs", "pub fn unixa() {}\n"),
    (
        "repo/crates/wina/Cargo.toml",
        r#"[package]
name = "wina"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = { path = "../shared" }
"#,
    ),
    ("repo/crates/wina/src/lib.rs", "pub fn wina() {}\n"),
    (
        "repo/crates/shared/Cargo.toml",
        "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/shared/src/lib.rs", "pub fn shared() {}\n"),
    (
        "repo/crates/both/Cargo.toml",
        "[package]\nname = \"both\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/both/src/lib.rs", "pub fn both() {}\n"),
    (
        "repo/crates/condev/Cargo.toml",
        "[package]\nname = \"condev\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/condev/src/lib.rs", "pub fn condev() {}\n"),
];

/// The effective activation each composed unit carries. `condev` conjoins the
/// target predicate with test compilation, `shared` disjoins the two predicates
/// that reach it, and `both` widens to `always` because one path is
/// unconditional.
pub const EXPECTED_ACTIVATION_UNITS: &[&str] = &[
    "app|app|always",
    "both|both|always",
    "condev|condev|all(cfg(test), cfg(unix))",
    "shared|shared|any(cfg(unix), cfg(windows))",
    "unixa|unixa|cfg(unix)",
    "wina|wina|cfg(windows)",
];

/// Each edge carries the predicate its own declaration exposes, which is not
/// the composed predicate of the path that reached it.
pub const EXPECTED_ACTIVATION_EDGES: &[&str] = &[
    "app|both|both|Normal|always",
    "app|unixa|unixa|Normal|cfg(unix)",
    "app|wina|wina|Normal|cfg(windows)",
    "app|condev|condev|Development|all(cfg(test), cfg(unix))",
    "unixa|both|both|Normal|always",
    "unixa|shared|shared|Normal|always",
    "wina|shared|shared|Normal|always",
];

pub const MISSING_LIBRARY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
onlybin = { path = "crates/onlybin" }
"#,
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
    (
        "repo/crates/onlybin/Cargo.toml",
        "[package]\nname = \"onlybin\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/onlybin/src/main.rs", "fn main() {}\n"),
];

pub const DEPENDENCY_CYCLE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
first = { path = "crates/first" }
"#,
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
    (
        "repo/crates/first/Cargo.toml",
        r#"[package]
name = "first"
version = "0.1.0"
edition = "2021"

[dependencies]
second = { path = "../second" }
"#,
    ),
    ("repo/crates/first/src/lib.rs", "pub fn first() {}\n"),
    (
        "repo/crates/second/Cargo.toml",
        r#"[package]
name = "second"
version = "0.1.0"
edition = "2021"

[dependencies]
first = { path = "../first" }
"#,
    ),
    ("repo/crates/second/src/lib.rs", "pub fn second() {}\n"),
];
