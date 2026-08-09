//! Repositories and expected values for one target's module closure.
//!
//! The models live beside the cases that read them so no expectation is
//! derived from a run. The multi-unit repositories live in `unit_fixtures.rs`.

use pedant_core::resolution::rust::SourceClosureFailureKind;

use crate::resolution::fixture::FixtureFile;

/// Bare callable trait objects are valid only before Rust 2021. Each accepted
/// fixture leaves a capability-bearing import after all three callable forms,
/// so the snapshot can prove both the repair and the original source span.
pub const LEGACY_CALLABLE_SOURCE: &str = r#"type Action = Fn(&u8) + Send + Sync;
type MutableAction = FnMut(&u8);
type OnceAction = FnOnce(&u8);
use std::net::TcpStream;

pub fn connect() {
    let _socket = TcpStream::connect("127.0.0.1:9");
}
"#;

pub const LEGACY_CALLABLES_OMITTED_EDITION: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    ),
    ("repo/src/lib.rs", LEGACY_CALLABLE_SOURCE),
];

pub const LEGACY_CALLABLES_EXPLICIT_2015: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
    ),
    ("repo/src/lib.rs", LEGACY_CALLABLE_SOURCE),
];

pub const LEGACY_CALLABLES_INHERITED_2018: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[workspace]\nmembers = [\"app\"]\n\n[workspace.package]\nedition = \"2018\"\n",
    ),
    (
        "repo/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
    ),
    ("repo/app/src/lib.rs", LEGACY_CALLABLE_SOURCE),
];

pub const LEGACY_CALLABLES_2021: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", LEGACY_CALLABLE_SOURCE),
];

pub const LEGACY_CALLABLE_NEAR_MATCH: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    ),
    ("repo/src/lib.rs", "type Action = FnLike(&u8);\n"),
];

pub const LEGACY_CALLABLE_THEN_MALFORMED: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    ),
    (
        "repo/src/lib.rs",
        "type Action = Fn(&u8);\nfn malformed( {\n",
    ),
];

/// Two selected units point at one physical source under different editions.
/// The legacy unit is ordered first, proving a compatibility-repaired cached
/// tree cannot make the later Rust 2021 unit appear valid.
pub const SHARED_CALLABLE_ACROSS_EDITIONS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[workspace]\nmembers = [\"app\", \"modern\"]\n",
    ),
    (
        "repo/app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\
         [lib]\npath = \"../shared.rs\"\n\
         [dependencies]\nmodern = { path = \"../modern\" }\n",
    ),
    (
        "repo/modern/Cargo.toml",
        "[package]\nname = \"modern\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [lib]\npath = \"../shared.rs\"\n",
    ),
    ("repo/shared.rs", "type Action = Fn(&u8);\n"),
];

/// A single-package repository whose library reaches every supported module
/// form and leaves an unrelated sibling, a second target, and a dependency
/// package outside its closure.
pub const MODULE_CLOSURE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
alpha = { path = "crates/alpha" }
"#,
    ),
    (
        "repo/src/lib.rs",
        r#"pub mod standard;
pub mod nested;

#[path = "custom/relocated.rs"]
pub mod relocated;

pub mod inline_owner {
    pub mod deep;
}
"#,
    ),
    (
        "repo/src/standard.rs",
        r#"#[path = "sibling.rs"]
pub mod sibling;

pub fn standard() {}
"#,
    ),
    // `standard.rs` is neither a crate root nor a `mod.rs`, so its two lookup
    // bases differ: `mod name;` reads `src/standard/`, while a top-level
    // `#[path]` reads the directory `standard.rs` itself lives in. The decoy
    // below occupies the wrong answer.
    ("repo/src/sibling.rs", "pub fn sibling() {}\n"),
    ("repo/src/standard/sibling.rs", "pub fn decoy() {}\n"),
    (
        "repo/src/nested/mod.rs",
        r#"pub mod leaf;

#[cfg_attr(unix, path = "posix.rs")]
#[cfg_attr(windows, path = "win.rs")]
pub mod platform;
"#,
    ),
    ("repo/src/nested/leaf.rs", "pub fn leaf() {}\n"),
    // Mutually exclusive `cfg_attr` overrides. Nothing evaluates a predicate,
    // so both alternatives belong to the closure.
    ("repo/src/nested/posix.rs", "pub fn posix() {}\n"),
    ("repo/src/nested/win.rs", "pub fn win() {}\n"),
    ("repo/src/custom/relocated.rs", "pub fn relocated() {}\n"),
    ("repo/src/inline_owner/deep.rs", "pub fn deep() {}\n"),
    ("repo/src/unrelated.rs", "pub fn unrelated() {}\n"),
    ("repo/src/main.rs", "fn main() {}\n"),
    (
        "repo/crates/alpha/Cargo.toml",
        "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/alpha/src/lib.rs", "pub fn alpha() {}\n"),
];

/// One package whose library and binary both reach `src/shared.rs`, beside a
/// build script with its own module and a source no primary target reaches.
pub const PRIMARY_TARGET_OVERLAP: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    ),
    ("repo/src/lib.rs", "mod shared;\npub fn api() {}\n"),
    (
        "repo/src/main.rs",
        "mod shared;\nfn main() { shared::shared(); }\n",
    ),
    ("repo/src/shared.rs", "pub fn shared() {}\n"),
    ("repo/build.rs", "mod helper;\nfn main() {}\n"),
    ("repo/helper.rs", "pub fn helper() {}\n"),
    ("repo/src/unreached.rs", "this is not Rust\n"),
];

/// Every source the library target reaches, in the snapshot's sorted order.
pub const EXPECTED_LIBRARY_CLOSURE: &[&str] = &[
    "src/custom/relocated.rs",
    "src/inline_owner/deep.rs",
    "src/lib.rs",
    "src/nested/leaf.rs",
    "src/nested/mod.rs",
    "src/nested/posix.rs",
    "src/nested/win.rs",
    "src/sibling.rs",
    "src/standard.rs",
];

/// Sources that exist in the repository but belong to another target, another
/// package, or no module graph at all. `src/standard/sibling.rs` is the decoy
/// a `#[path]` resolved against the wrong base would have selected.
pub const EXCLUDED_FROM_LIBRARY_CLOSURE: &[&str] = &[
    "src/main.rs",
    "src/unrelated.rs",
    "src/standard/sibling.rs",
    "crates/alpha/src/lib.rs",
];

/// `id|name|source|depth|inline|parent` for every module instance the library
/// closure creates: standard, nested `mod.rs`, `#[path]` from a crate root,
/// an inline owner that keeps its parent's source, the external child that
/// inline owner opens, one instance per mutually exclusive `cfg_attr` path,
/// and a `#[path]` from a file that is not a crate root.
pub const EXPECTED_LIBRARY_MODULES: &[&str] = &[
    "RustModuleId(0)|crate|src/lib.rs|0|false|None",
    "RustModuleId(1)|standard|src/standard.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(2)|nested|src/nested/mod.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(3)|relocated|src/custom/relocated.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(4)|inline_owner|src/lib.rs|1|true|Some(RustModuleId(0))",
    "RustModuleId(5)|deep|src/inline_owner/deep.rs|2|false|Some(RustModuleId(4))",
    "RustModuleId(6)|leaf|src/nested/leaf.rs|2|false|Some(RustModuleId(2))",
    "RustModuleId(7)|platform|src/nested/posix.rs|2|false|Some(RustModuleId(2))",
    "RustModuleId(8)|platform|src/nested/win.rs|2|false|Some(RustModuleId(2))",
    "RustModuleId(9)|sibling|src/sibling.rs|2|false|Some(RustModuleId(1))",
];

/// A library whose module graph repeats sources on purpose.
///
/// `nest` includes its own `mod.rs`, which keeps the same lookup directory and
/// so declares the same child again: without module-instance ancestry that
/// chain never ends. `again` includes the crate root. `first` and `second`
/// occupy one shared source that owns a child of its own, which is legal and
/// must still be instantiated under both positions.
pub const MODULE_REPETITION: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        r#"#[path = "lib.rs"]
pub mod again;

#[path = "shared.rs"]
pub mod first;

#[path = "shared.rs"]
pub mod second;

pub mod nest;
"#,
    ),
    ("repo/src/shared.rs", "pub mod tail;\n"),
    ("repo/src/shared/tail.rs", "pub fn tail() {}\n"),
    (
        "repo/src/nest/mod.rs",
        "#[path = \"mod.rs\"]\npub mod recurse;\n",
    ),
];

/// Every source the repetition closure reaches, sorted and deduplicated.
pub const EXPECTED_REPETITION_SOURCES: &[&str] = &[
    "src/lib.rs",
    "src/nest/mod.rs",
    "src/shared.rs",
    "src/shared/tail.rs",
];

/// Every module instance the repetition closure creates. `again` and `recurse`
/// each occupy a source their own ancestry already holds and expand no
/// further; `first` and `second` are two instances of one source, and each
/// opens its own `tail`.
pub const EXPECTED_REPETITION_MODULES: &[&str] = &[
    "RustModuleId(0)|crate|src/lib.rs|0|false|None",
    "RustModuleId(1)|again|src/lib.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(2)|first|src/shared.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(3)|second|src/shared.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(4)|nest|src/nest/mod.rs|1|false|Some(RustModuleId(0))",
    "RustModuleId(5)|recurse|src/nest/mod.rs|2|false|Some(RustModuleId(4))",
    "RustModuleId(6)|tail|src/shared/tail.rs|2|false|Some(RustModuleId(3))",
    "RustModuleId(7)|tail|src/shared/tail.rs|2|false|Some(RustModuleId(2))",
];

/// The only source a root-confinement case may read: its own entry point. The
/// sentinel each escape points at lives outside the repository root. Only the
/// probe configuration can observe the reads this names.
#[cfg(feature = "resolution-test-support")]
pub const ENTRY_ONLY_READS: &[&str] = &["src/lib.rs"];

/// The smallest loadable package: one manifest and one library entry point.
#[cfg(feature = "resolution-test-support")]
pub const MINIMAL_PACKAGE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub fn app() {}\n"),
];

pub const MISSING_MODULE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod absent;\n"),
];

pub const AMBIGUOUS_MODULE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod dup;\n"),
    ("repo/src/dup.rs", "pub fn flat() {}\n"),
    ("repo/src/dup/mod.rs", "pub fn nested() {}\n"),
];

/// A `#[path]` that points at a sentinel outside the repository root. Root
/// confinement owns this case, so it proves the sentinel is never read rather
/// than only that the closure refuses it.
pub const PATH_ESCAPE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/src/lib.rs",
        "#[path = \"../../outside/secret.rs\"]\npub mod escape;\n",
    ),
    ("outside/secret.rs", "pub fn secret() {}\n"),
];

pub const PARSE_FAILURE: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/src/lib.rs", "pub mod broken;\n"),
    ("repo/src/broken.rs", "fn ( {\n"),
];

pub const MISSING_ENTRY: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
    ),
    ("repo/src/other.rs", "pub fn other() {}\n"),
];

/// One closure rejection: the fixture to materialize and the failure the
/// snapshot owes.
pub struct ClosureCase {
    pub label: &'static str,
    pub files: &'static [FixtureFile],
    pub expected: SourceClosureFailureKind,
}

pub const CLOSURE_CASES: &[ClosureCase] = &[
    ClosureCase {
        label: "a declaration with no matching file",
        files: MISSING_MODULE,
        expected: SourceClosureFailureKind::MissingModule,
    },
    ClosureCase {
        label: "both name.rs and name/mod.rs",
        files: AMBIGUOUS_MODULE,
        expected: SourceClosureFailureKind::AmbiguousModule,
    },
    ClosureCase {
        label: "a module source that does not parse",
        files: PARSE_FAILURE,
        expected: SourceClosureFailureKind::SourceParse,
    },
    ClosureCase {
        label: "a declared entry point that does not exist",
        files: MISSING_ENTRY,
        expected: SourceClosureFailureKind::EntryRead,
    },
];
