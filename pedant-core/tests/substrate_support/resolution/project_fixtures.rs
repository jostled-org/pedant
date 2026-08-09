//! Cargo repositories and expected project views for the project-authority
//! cases, including the member patterns migrated from the removed
//! `tests/workspace_members.rs` root.

use pedant_core::resolution::rust::RustProjectError;

use crate::resolution::fixture::FixtureFile;

/// A workspace that is also a package, with every supported target kind, every
/// dependency kind, an inherited version, an excluded directory, an in-root
/// non-member path dependency, and an out-of-root path dependency.
pub const COMPLETE_PROJECT: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[workspace]
members = ["crates/*"]
exclude = ["crates/excluded"]

[workspace.package]
version = "1.2.3"
rust-version = "1.80"

[workspace.dependencies]
shared = { path = "vendor/shared" }

[package]
name = "root-app"
version = "0.4.0"
edition = "2021"

[dependencies]
alpha = { path = "crates/alpha" }
outside = { path = "../outside" }
serde = "1"
renamed = { package = "alpha", path = "crates/alpha" }

[dev-dependencies]
beta = { path = "crates/beta", optional = true }

[build-dependencies]
shared = { workspace = true }

[target."cfg(unix)".dependencies]
beta = { path = "crates/beta" }
"#,
    ),
    ("repo/src/lib.rs", "pub mod api;\n"),
    ("repo/src/main.rs", "fn main() {}\n"),
    ("repo/src/bin/tool.rs", "fn main() {}\n"),
    ("repo/src/bin/nested/main.rs", "fn main() {}\n"),
    ("repo/examples/demo.rs", "fn main() {}\n"),
    ("repo/tests/it.rs", "#[test]\nfn it() {}\n"),
    ("repo/benches/bench.rs", "fn main() {}\n"),
    ("repo/build.rs", "fn main() {}\n"),
    (
        "repo/crates/alpha/Cargo.toml",
        r#"[package]
name = "alpha"
version.workspace = true
rust-version.workspace = true
edition = "2021"
"#,
    ),
    ("repo/crates/alpha/src/lib.rs", "pub fn alpha() {}\n"),
    (
        "repo/crates/beta/Cargo.toml",
        r#"[package]
name = "beta"
version = "0.2.0"
edition = "2021"
"#,
    ),
    ("repo/crates/beta/src/lib.rs", "pub fn beta() {}\n"),
    (
        "repo/crates/excluded/Cargo.toml",
        r#"[package]
name = "excluded"
version = "0.9.0"
edition = "2021"
"#,
    ),
    ("repo/crates/excluded/src/lib.rs", "pub fn excluded() {}\n"),
    (
        "repo/vendor/shared/Cargo.toml",
        r#"[package]
name = "shared"
version = "3.0.0"
edition = "2021"
"#,
    ),
    ("repo/vendor/shared/src/lib.rs", "pub fn shared() {}\n"),
    (
        "outside/Cargo.toml",
        r#"[package]
name = "outside"
version = "4.0.0"
edition = "2021"
"#,
    ),
    ("outside/src/lib.rs", "pub fn outside() {}\n"),
];

/// `name|version|rust-version|manifest|member` for every package, in the
/// project's manifest-path order.
pub const EXPECTED_PACKAGES: &[&str] = &[
    "root-app|0.4.0|-|Cargo.toml|member",
    "alpha|1.2.3|1.80|crates/alpha/Cargo.toml|member",
    "beta|0.2.0|-|crates/beta/Cargo.toml|member",
    "shared|3.0.0|-|vendor/shared/Cargo.toml|dependency",
];

/// `package|kind|name|entry` for every target, ordered by package, target kind,
/// then target name.
pub const EXPECTED_TARGETS: &[&str] = &[
    "root-app|Library|root_app|src/lib.rs",
    "root-app|Binary|nested|src/bin/nested/main.rs",
    "root-app|Binary|root-app|src/main.rs",
    "root-app|Binary|tool|src/bin/tool.rs",
    "root-app|Example|demo|examples/demo.rs",
    "root-app|Test|it|tests/it.rs",
    "root-app|Benchmark|bench|benches/bench.rs",
    "root-app|BuildScript|build-script-build|build.rs",
    "alpha|Library|alpha|crates/alpha/src/lib.rs",
    "beta|Library|beta|crates/beta/src/lib.rs",
    "shared|Library|shared|vendor/shared/src/lib.rs",
];

/// `package|kind|local name|activation|library entry` for every dependency,
/// ordered by package, dependency kind, then local name. `-` marks a
/// dependency with no in-repository library target.
pub const EXPECTED_DEPENDENCIES: &[&str] = &[
    "root-app|Normal|alpha|always|crates/alpha/src/lib.rs",
    "root-app|Normal|beta|cfg(unix)|crates/beta/src/lib.rs",
    "root-app|Normal|outside|always|-",
    "root-app|Normal|renamed|always|crates/alpha/src/lib.rs",
    "root-app|Normal|serde|always|-",
    "root-app|Development|beta|feature = \"beta\"|crates/beta/src/lib.rs",
    "root-app|Build|shared|always|vendor/shared/src/lib.rs",
];

/// One rejection case: the files to write and the error the loader owes.
pub struct RejectionCase {
    pub label: &'static str,
    pub files: &'static [FixtureFile],
    pub expected: fn(&RustProjectError) -> bool,
}

const MISSING_VERSION: &[FixtureFile] = &[(
    "repo/Cargo.toml",
    "[package]\nname = \"no-version\"\nedition = \"2021\"\n",
)];

const MISSING_INHERITED_VERSION: &[FixtureFile] = &[
    ("repo/Cargo.toml", "[workspace]\nmembers = [\"member\"]\n"),
    (
        "repo/member/Cargo.toml",
        "[package]\nname = \"inheriting\"\nversion.workspace = true\nedition = \"2021\"\n",
    ),
];

const INVALID_VERSION: &[FixtureFile] = &[(
    "repo/Cargo.toml",
    "[package]\nname = \"bad-version\"\nversion = \"not-a-version\"\nedition = \"2021\"\n",
)];

const MISSING_INHERITED_EDITION: &[FixtureFile] = &[
    ("repo/Cargo.toml", "[workspace]\nmembers = [\"member\"]\n"),
    (
        "repo/member/Cargo.toml",
        "[package]\nname = \"inheriting\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
    ),
];

const INVALID_EDITION: &[FixtureFile] = &[(
    "repo/Cargo.toml",
    "[package]\nname = \"bad-edition\"\nversion = \"0.1.0\"\nedition = \"2030\"\n",
)];

const MALFORMED_MANIFEST: &[FixtureFile] = &[("repo/Cargo.toml", "[package\nname = \"broken\"\n")];

pub const REJECTION_CASES: &[RejectionCase] = &[
    RejectionCase {
        label: "package without a version",
        files: MISSING_VERSION,
        expected: |error| matches!(error, RustProjectError::MissingPackageVersion { .. }),
    },
    RejectionCase {
        label: "inheritance without a workspace version",
        files: MISSING_INHERITED_VERSION,
        expected: |error| {
            matches!(
                error,
                RustProjectError::MissingWorkspacePackageVersion { .. }
            )
        },
    },
    RejectionCase {
        label: "version that is not semver",
        files: INVALID_VERSION,
        expected: |error| matches!(error, RustProjectError::InvalidPackageVersion { .. }),
    },
    RejectionCase {
        label: "inheritance without a workspace edition",
        files: MISSING_INHERITED_EDITION,
        expected: |error| {
            matches!(
                error,
                RustProjectError::MissingWorkspacePackageEdition { .. }
            )
        },
    },
    RejectionCase {
        label: "edition that Cargo does not recognize",
        files: INVALID_EDITION,
        expected: |error| matches!(error, RustProjectError::InvalidPackageEdition { .. }),
    },
    RejectionCase {
        label: "manifest that is not toml",
        files: MALFORMED_MANIFEST,
        expected: |error| matches!(error, RustProjectError::ManifestParse { .. }),
    },
];

/// Member-pattern fixtures migrated from the removed `workspace_members.rs`
/// root: single-segment globs, nested globs, exclusion, a literal member, and
/// a member directory with no manifest.
pub const MEMBER_PATTERNS: &[FixtureFile] = &[
    (
        "repo/Cargo.toml",
        r#"[workspace]
members = [
    "crates/*-util",
    "crates/*/plugin-*",
    "direct",
    "crates/no-manifest",
    "absent",
]
exclude = ["crates/fs-util"]
"#,
    ),
    (
        "repo/crates/http-util/Cargo.toml",
        "[package]\nname = \"http-util\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/fs-util/Cargo.toml",
        "[package]\nname = \"fs-util\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/http-core/Cargo.toml",
        "[package]\nname = \"http-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/alpha/plugin-http/Cargo.toml",
        "[package]\nname = \"alpha-plugin-http\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/beta/plugin-fs/Cargo.toml",
        "[package]\nname = \"beta-plugin-fs\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/crates/beta/tooling/Cargo.toml",
        "[package]\nname = \"beta-tooling\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    (
        "repo/direct/Cargo.toml",
        "[package]\nname = \"direct\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
    ("repo/crates/no-manifest/src/lib.rs", "pub fn absent() {}\n"),
];
